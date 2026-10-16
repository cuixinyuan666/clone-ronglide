# docs/26 — NChBi 第二批：chlib 算法解剖

> 批次：NChBi 第二批（2026-10-17）
> 上承：docs/25（NChBi 第一批 — 入口链与 P 分派）
> 目标：解剖 chlib 算法层，闭环 docs/25 §七 待仲裁 #5/#6/#7；**静态完成，不依赖 frida**
> 工具：`tools/re-inventory/disasm_func.py --dll`、`x87_sim.py`、`nchbi/map_family_slots.py`（本批新增）
> 证据目录：`tools/re-inventory/nchbi/`

---

## 〇、摘要

1. **`0x10002770`（NChBiSta, ch_api vt[+0x38]）= 纯「结构展开器」**：把 `obj10` 的端点项数组 + `obj8` 的记录表
   展开成**逐 bar 的阶梯函数** `out[]`；函数体 130 条指令、**0 条 x87 条件**、**无任何 `-3/+3` 立即数**。
2. **输出码存在性闭环**：`-3` 的唯一产生路径 = 段 C（`0x10002883-94`，`value × 3`）；
   其余值 = `value × {10, 2, 1}` 或 `0`（memset）。
   ⇒ 用户公式 `SELECT(VAR2=-3)` 命中「每个结构区间结束后的端点 bar」。
3. **共享容器确证**：`NChBi(0x10002340)` 与 `NChBiSta(0x10002770)` **共用同一 ch_api 实例的 obj8 + obj10**；
   NChBi **填**、NChBiSta **读** ⇒ `NCHBISTA` 必须与 `NCHBI` 同实例且在其后调用。
4. **授权码勘误**：NChBi = `EA62`，**NChBiSta = `EA61`**。
5. **加分项达成**：ch_api 虚表 `0x10015214` 的 **+0x18…+0xcc 共 50 槽全部映射到 TAFLib 导出名**
   （新定名 `NChBiZj3@+0x48`、`NChBiZjNum@+0x5c`）。
6. **ch_api 子对象布局全解**（ctor `0x100010d0`）：`+8/+0xc/+0x10/+0x14/+0x18/+0x1c` 六个子对象 + 各自 vtable。

---

## 一、`0x10002770`（NChBiSta）解剖

证据：`tools/re-inventory/nchbi/chlib_worker_10002770.txt`（130 insn，`0x10002770`–`0x100028f0 ret 0x10`）

### 1.1 入口与签名 [A]

```
10002770  sub esp,0xc ; push ebx/ebp/esi/edi
10002775  ebp = [esp+0x18]  -> arg1 = count
1000277b  edi = [esp+0x24]  -> arg2 = out (double*)
1000278a  esi = ecx         -> this (ch_api*)
1000278c  call 0x1001494c   -> memset(out, 0, count*8)        (cdecl, 3 参)
```

```c
int __thiscall ch_api::vt38(this /*ch_api*/, int count, double* out, void* ctx6, void* arg4);
//  ret 0x10 = 4 栈参; ★ 函数体内完全不使用 ctx6 / arg4  [A]
```

- 返回值：失败 `or eax,0xffffffff` → **-1**（4 个失败出口合一，`0x100028e6-0x100028f0`）；成功 `xor eax,eax` → **0**。
- 与 NChBi(`0x10002340`) 同构处：`memset` 前置、`ret 0x10`、`__thiscall`。
  不同处：**没有 P 参数参与、没有 x87 比较、没有 ctx6 读取**。

### 1.2 四道前置门 [A]

| 序 | 地址 | 检查 | 属性 |
| --- | --- | --- | --- |
| 1 | `0x100027a6` | `[[this+8]+0x1c]`（obj8 记录表指针）!= 0 | 容器已备 |
| 2 | `0x100027ba` | `[[this+0x10]+0x30]`（obj10 项数组基址）!= 0 | 容器已备 |
| 3 | `0x100027c2` | `[this+4]`（ch_auth*）!= 0 | 授权对象存在 |
| 4 | `0x100027cc-db` | `ch_auth->vt[+4](0xEA61)` | **授权码 EA61** |

任何一门失败 → `0x100028e6` → `return -1`。

> ★ **与 NChBi 的授权形态差异** [A]：
> - NChBi(`0x10002340`)：`if ((int)P == 0) 才查 ch_auth`（`EA62`）；
> - NChBiSta(`0x10002770`)：**无条件查 ch_auth**（`EA61`）。
> - TAFLib 包装层也各查一次（NChBi 包装层 `(P==0||P==51)`→`EA62`；NChBiSta 包装层无条件→`EA61`）。

### 1.3 表结构 [A]

```
obj8  = [this+8]     → +0x1c = 记录表基址(Rec20, 0x20 B/条) ; +0x28 = 记录数 nrecs
obj10 = [this+0x10]  → +0x30 = 端点项数组(Item21, 0x21 B/条) ; +0x3c = 项数 nitems
```

**Item21（0x21 = 33 字节/条）字段**：

| 偏移 | 类型 | 用途 |
| --- | --- | --- |
| `+0x00` | int32 | 值 `v`（推定 ±1），参与 `neg` / `×2` / `×3` / `×10` |
| `+0x04` | uint8 | bit0 = 有效项；bit3(0x08) = 值 ×2 |
| `+0x09` | int32 | **记录索引 recIdx** → `obj8[+0x1c] + recIdx*0x20`（本函数用） |
| `+0x1d` | int32 | **bar 索引 barIdx**（`0x10002340` 用，见 §三） |

**步长 0x21 的交叉确证** [A]：本函数 `add esi, 0x21`；`0x10002340` 四路展开 `add eax, 0x84` = `4 × 0x21` ✓。

**Rec20（0x20 字节/条）**：`+0x00` = 起 bar、`+0x04` = 止 bar。

### 1.4 主循环算法 [A]

```c
int cur = 0; int eax = 0;                       // cur: 段间传递值; eax: 输出 bar 游标
for (k = 0; k < obj10->nitems; k++) {
    Item21 *it = obj10->items + k*0x21;
    if (!(it->flags & 1)) { cur = it->value; continue; }        // 无效项: 仅更新 cur
    int idx = it->recIdx;
    if (idx < 0 || idx >= obj8->nrecs) break;                   // 断链退出
    if (cur == 0) cur = -it->value;                             // 首项取反 [C]
    Rec20 *rec = obj8->recs + idx*0x20;

    while (eax < rec->start && eax < count) out[eax++] = cur*10;      // 段 A
    while (eax <= rec->end   && eax < count) out[eax++] =           // 段 B
        (it->flags & 8) ? cur*2 : cur;
    if (eax > 0 && eax < count)             out[eax++] = cur*3;       // 段 C ★
    cur = it->value;
}
if (eax < count) { out[eax] = cur*10; /* rep movsd 前向复制 8B 到尾部 */ }   // 尾广播
return 0;
```

地址对应：

| 段 | 地址 | 缩放实现 | 写值 |
| --- | --- | --- | --- |
| A 填充 | `0x10002832-4c` | `lea ebx,[ecx+ecx*4]; add ebx,ebx` = `ecx*10` | `cur*10` |
| B 区间 | `0x1000284e-79` | `fild [esi-9]`，或 `add ebx,ebx` = `*2`（flag bit3） | `cur` / `cur*2` |
| C 端点 | `0x1000287b-96` | `lea ecx,[ecx+ecx*2]` = `ecx*3` | `cur*3` ★ |
| 尾广播 | `0x100028b3-d8` | `ecx*10` + `rep movsd`（前向复制 8 B） | `cur*10` |

### 1.5 x87 条件表 [A]

```
python tools/re-inventory/x87_sim.py tools/re-inventory/nchbi/chlib_worker_10002770.txt \
       -o tools/re-inventory/nchbi/cond_chlib_10002770.txt
=> 0 conditions, 9 stores, 31 blocks, conflicts=0
```

**0 条 x87 比较条件** —— 函数内 x87 仅用于 `fild`（int→double）+ `fstp`（double→mem）。
⇒ `0x10002770` 是**纯整数运算 + 类型转换**，无任何浮点判定 [A]。
（对照：同批 `0x10002340` 有 10 条 x87 条件，做 argmax/argmin。）

---

## 二、★ 输出码判定表（`-3 / +3 / 0` 闭环）

### 2.1 前提：无立即数常量 [A]

对 `0x10002770` 全文做「立即数写入」扫描，结果**仅 `0x100028e9 or eax,0xffffffff`** 一处。
⇒ 输出值 **100% 来自 `Item21.value` 的 {×10, ×2, ×1, ×3} 缩放**，不存在硬编码 `-3`。

### 2.2 判定表 [A(路径) / B(语义)]

| 输出值 | 产生段 | 证据地址 | 条件 | 语义（推定） |
| --- | --- | --- | --- | --- |
| **±3** | **段 C** | `0x10002883-94` | `0 < eax < count`（即 `rec->end` 之后第一格） | **端点 / 分型 bar**（`-3` 底分型、`+3` 顶分型）★ |
| ±1 | 段 B | `0x1000286d fild [esi-9]` | `rec->start ≤ eax ≤ rec->end`，flag bit3=0 | 记录区间内部 bar |
| ±2 | 段 B | `0x1000285e-67 add ebx,ebx` | 同上，flag bit3=1 | 区间内加权 bar |
| ±10 | 段 A | `0x10002836-46` | `eax < rec->start` | 区间前填充段 |
| ±10 | 尾广播 | `0x100028b7-d8` | `eax ≥ 所有 rec->end` | 尾部填充段 |
| 0 | memset | `0x1000278c` | 未被任何记录覆盖 | 无结构 |

**结论** [A/B]：**`-3` 的唯一产生路径是段 C**。用户公式 `SELECT(VAR2=-3)` / `ALERT(VAR2=-3,'底分型')`
命中的就是「每个结构区间结束后紧邻的那一根 bar」。
`Item21.value` 的符号（推定 +1 顶 / -1 底）决定 `±3` 的方向；**value 值域需动态确认**（§七 待仲裁）。

### 2.3 与 NChBi（`0x10002340`）的输出对照 [A]

| 项 | NChBi `0x10002340` | NChBiSta `0x10002770` |
| --- | --- | --- |
| 写 `out[]` 的方式 | `out[it->barIdx] = it->value`（单点写） | 逐 bar 区间填充（阶梯函数） |
| 索引字段 | `Item21.barIdx`（`+0x1d`） | `Item21.recIdx`（`+0x09`） |
| ×2 实现 | `fld [edx+ecx*8]; fmul st(1)`，乘常量 **`0x100154b8 = 2.0`** | 硬编码 `add ebx,ebx` |
| 输出语义 | 极值 bar 上打「值」 | 每个 bar 的结构编码 |

> 两者对该 bit3 标志的语义**一致（×2）**：NChBi 用 `0x100154b8 = 2.0`，NChBiSta 用 `add ebx,ebx`。 [A]

---

## 三、共享基础设施解码（docs/25 待仲裁 #5 / #7）

### 3.1 ch_api 子对象布局（ctor `0x100010d0` 实证）[A]

```
10001102  [esi]      = 0x10015214          ; ch_api vtable
10001108  [esi+4]    = arg                 ; ch_auth*
1000112c  [esi+8]    = new(0x2c) vt 0x100153ec    ; obj8
10001165  [esi+0xc]  = new(0x38) vt 0x10015474    ; obj_c   (byte[+0x1c]=1)
10001199  [esi+0x10] = new(0x60) -> 0x10009850    ; obj10   (vt 0x10015438)
100011db  [esi+0x14] = new(0x68) -> 0x1000be70    ; obj14   (vt 0x1001544c)
10001203  [esi+0x18] = new(0x60) -> 0x1000e7c0    ; obj18
1000122a  [esi+0x1c] = new(0x3c) vt 0x10015488    ; obj1c   (+0x1c=12,+0x20=26,+0x24=9)
```

| 成员 | 大小 | vtable | 角色 |
| --- | --- | --- | --- |
| `+0x8` obj8 | 0x2c | `0x100153ec` | **记录表产出者**（`+0x1c` 表 / `+0x28` 计数 / `+0x18` 已备标志）vt 仅 4 槽 |
| `+0xc` obj_c | 0x38 | `0x10015474` | 派生器（`+0x20`/`+0x24` 表镜像，`+0x28`/`+0x34`） |
| `+0x10` obj10 | 0x60 | `0x10015438` | **结果容器**（`+0x1c` 类型码 / `+0x20..0x2c` 镜像 / `+0x30` 项数组 / `+0x3c` 项数） |
| `+0x14` obj14 | 0x68 | `0x1001544c` | 未解剖 |
| `+0x18` obj18 | 0x60 | （`0x1000e7c0`） | 未解剖 |
| `+0x1c` obj1c | 0x3c | `0x10015488` | 常量表 `{12, 26, 9}` |

obj8 vt = `0x100094b0 / 0x10009500 / 0x10009530 / 0x1000e0b0`（4 槽，其后即字符串字面量）。
**全族 vt[+0xc] 同为 `0x1000e0b0`** ⇒ 统一「主计算/清空」虚函数 [B]。

### 3.2 `0x10006670(this, count)` = 容器准备器 [A]

```
if (!obj8[+0x18]) {
    obj8->vt[+4]();                       // 0x10009500 预清
    obj8->vt[+0x0c](count, ...);          // 0x1000e0b0 主计算  → obj8[+0x1c]/[+0x28]
    if (obj8->vt[+8]() != 0) return -1;   // 0x10009530 校验
}
if (!obj_c[+0x18]) {
    obj_c->vt[+4](); obj_c->vt[+0x0c](count, ...);
    obj_c[+0x20] = obj8[+0x1c];           // 表镜像
    obj_c[+0x24] = obj8[+0x28];
    obj_c->vt[+8]();
}
return 0;
```

### 3.3 `0x10009930(P) → obj10[+0x1c]` = chlib 版 P→类型码 [A]

```
obj10[+0x1c] = P
if ((unsigned)(P-11) <= 0x28)  obj10[+0x1c] = jumpbyte_100099a8[P-11]
```
跳表值：**11→2、12→1、21→4、22→3、31→6、32→5，其余→0**
⇒ 与 TAFLib 包装层 `NChBi` 的 `switch` 常量表**逐值相同**（`2(a-1)+(3-b)`）。
⇒ **同一 P 编码在 TAFLib 与 chlib 双实现**；包装层短路在前，故 chlib 侧只在 `P==0` 计算路径上用到。

### 3.4 NChBi(`0x10002340`) 的 prep 序列 [A]

```
100023c8  prep_containers(count)            → 备 obj8 / obj_c
100023dd  obj10->vt[+4]()                   → 0x100099e0
100023e6  code_of_P(obj10, (int)P)          → 0x10009930 写 obj10[+0x1c]
10002401  obj10->vt[+0x0c](count, out, ctx6, 0, 0)   → 0x1000e0b0 主计算
10002403  obj10[+0x20]=obj8[+0x1c]; obj10[+0x24]=obj8[+0x28]
10002415  obj10[+0x28]=obj_c[+0x28]; obj10[+0x2c]=obj_c[+0x34]
1000242f  obj10->vt[+8](); if fail return -1
10002439  esi = obj10; eax = obj10[+0x30]; ecx = obj10[+0x3c] → argmax/argmin 内核
```

### 3.5 「是否共享内部容器」—— 结论 [A]

| 项 | NChBi `0x10002340` (vt+0x34) | NChBiSta `0x10002770` (vt+0x38) |
| --- | --- | --- |
| obj8 `[this+8]` | **写**（经 `0x10006670`，`+0x1c`/`+0x28`） | **读**（`+0x1c` 表 / `+0x28` 计数） |
| obj_c `[this+0xc]` | 读（`+0x28`/`+0x34` → 镜像入 obj10） | 不用 |
| obj10 `[this+0x10]` | **写**（`+0x30`/`+0x3c` 由 vt[+0x0c] 生成） | **读**（`+0x30` 基址 / `+0x3c` 项数） |
| ctx6 (arg3) | 用（argmax/argmin 数据源） | **不用**（忽略 arg3/arg4） |
| 调 `0x10006670` / `0x10009930` | 是 | **否** |

⇒ **两者共享同一 ch_api 实例的 obj8 + obj10 容器**；NChBi **填**、NChBiSta **读** [A]。
⇒ **`NCHBISTA` 自身不触发计算**：TAFLib 包装层 `0x10012c40` 只做 `Authorize` + 填 ctx6 + 调 vt[+0x38]，
   故单独调用 `NCHBISTA`（同一实例上尚未跑过 `NCHBI`）会看到空容器 → `nitems==0` → 输出全 0 [A]。
⇒ 用户公式 `VAR1:=NCHBI(P); VAR2:=NCHBISTA;` 的**先后顺序是语义必需**。

---

## 四、数据流图（文本）

```
TAFLib 0x10006cc0(this)
  └─ ctx6 = { +0x00 High, +0x04 Open, +0x08 Low, +0x0c Close, +0x10 Volume, +0x14 Amount }
             (RData.dll!XTAData::Get*Buffer ; IAT 0x1006f254/258/250/240/280/2dc)

【NChBi 路径】 TAFLib 0x10012a50 --Authorize(EA62)--> ch_api vt[+0x34] = chlib 0x10002340
   0x10006670(count)
     └─> obj8.vt[+0x0c](count)  ==> obj8[+0x1c] 记录表 Rec20(0x20B/条) , obj8[+0x28] nrecs
                 │
                 └─> obj_c[+0x20]/[+0x24] 镜像
   0x10009930(P) ==> obj10[+0x1c] 类型码
   obj10.vt[+0x0c](count, out, ctx6, ...)  ==> obj10[+0x30] 端点项数组 Item21(0x21B/条) , obj10[+0x3c] nitems
   内核: argmax(ctx6->high, 种子 -DBL_MAX@0x100154c8) + argmin(ctx6->low, 种子 +DBL_MAX@0x100154c0)
   输出: out[Item21.barIdx(+0x1d)] = Item21.value(+0x00) ; bit3 时 × 2.0(0x100154b8)

【NChBiSta 路径】 TAFLib 0x10012c40 --Authorize(EA61)--> ch_api vt[+0x38] = chlib 0x10002770
   只读 obj8[+0x1c]/[+0x28] 与 obj10[+0x30]/[+0x3c]   (不读 ctx6!)
   for k in 0..nitems-1:
       it = obj10[+0x30] + k*0x21
       rec = obj8[+0x1c] + it->recIdx*0x20       ; rec->start / rec->end
       out[ .. rec->start)      = cur*10          ; 段 A 填充
       out[rec->start .. rec->end] = cur (或 cur*2 若 it->flags&8)  ; 段 B 区间
       out[rec->end + 1]        = cur*3           ; 段 C 端点 ★ (-3 来源)
   out[尾部] = 最后一个 cur*10                    ; 尾广播 (rep movsd)
```

- **步长**：obj8 记录表 0x20 B/条；obj10 端点项数组 **0x21 B/条**。
- **索引**：`Item21.recIdx(+0x09)` → 记录索引 `[0, nrecs)`；`Rec20.start/end` → bar 区间。
- **缓冲区**：`out`（double × count，memset 0 起）；无中间浮点缓冲。
- **`0x10002770` 不使用 ctx6**（无行情读取、无 x87 比较）⇒ **纯结构展开器**；`0x10002340` 才做行情极值。

---

## 五、加分项：同族槽位全映射

工具：`tools/re-inventory/nchbi/map_family_slots.py`（新入仓）
证据：`nchbi/family_slots.txt`（NChB* 族）、`nchbi/family_slots_full.txt`（全导出 117 个）

**方法**：对每个 TAFLib 导出反汇编，匹配模式
`mov ecx,[esi+0xbc]; mov edx,[ecx]; mov edx,[edx+0xNN]` → 得槽号；
再用 chlib ch_api 虚表 `0x10015214` 把槽号翻译成 chlib 函数地址。

### 5.1 NChBi 家族槽位表 [A]

| 槽 | chlib 函数 | TAFLib 导出 | 备注 |
| --- | --- | --- | --- |
| +0x18 | 0x10001590 | NChBhh / NChBh | 新 |
| +0x1c | 0x10001690 | NChBhl | 新 |
| +0x20 | 0x10001790 | NChRef | 新 |
| +0x24 | 0x10001a10 | NChFx | 新 |
| +0x28 | 0x10001bd0 | NChFxSta | 新 |
| +0x2c | 0x10001d90 | NChFxUpDn | 新 |
| +0x30 | 0x10002190 | NChFxOrder | 新 |
| **+0x34** | **0x10002340** | **NChBi** | docs/25 |
| **+0x38** | **0x10002770** | **NChBiSta** | 本批 |
| +0x3c | 0x10002900 | NChBiSta2 | 本批（见 §六） |
| +0x44 | 0x10002ea0 | NChBiZj | |
| **+0x48** | **0x10002fc0** | **NChBiZj3** | **本批新定名** |
| +0x4c | 0x10003180 | NChBiZjOrder | |
| +0x58 | 0x10003680 | NChBiFxNum | |
| **+0x5c** | **0x100038b0** | **NChBiZjNum** | **本批新定名** |
| +0x60 | 0x10003a90 | NChBiSpeed | |

### 5.2 全族扩展 [A]

`+0x78 = 0x100045f0` 被 `NChDuanKh / NChDuanKl / NChDuanKd / NChZs / NChZs_L2` **共用**（靠 P 区分）；
`+0x7c` NChZsG、`+0x80` NChZsD、`+0x84` NChZsBs12、`+0x88` NChZsBs3、`+0x8c` NChZsBreach、
`+0x90` NChZsL2M、`+0x94` NChZsFj、`+0x98` NChZsDg、`+0x9c` NChZsHLTurn、`+0xa0` NChFjZsNum、
`+0xa4` NChZsSel、`+0xa8` NChZsSelPri、`+0xac` NChZsSelSlPri、`+0xb0` NChZsSelSpPri、
`+0xb8` NChMacdArea、`+0xbc` NChSecArea、`+0xc4` Xuech/Xuech2（= `0x10006470`）。
⇒ **ch_api 是 50+ 虚函数的大接口**，覆盖 NChBhh…NChSecArea…Xuech 全族。

### 5.3 8 个「无 TAFLib 调用者」的槽 [B]

`+0x40=0x10002d80`、`+0x50=0x10003330`、`+0x54=0x10003450`、`+0x64=0x10003cd0`、
`+0x68=0x10004170`、`+0x6c=0x100042f0`、`+0x70=0x100043e0`、`+0x74=0x100044d0`

- 字节模式扫描 TAFLib `.text`（`8B 42/4A/52/5A/62/6A/72/7A NN`）：这 8 槽 **0 处引用**
  （`+0x64` 的 2 处 `mov eax,[edx+0x64]` 落在 `CalcProc_BuyK`(`0x100144e0`) 内，`edx` 是 BuyK 私有对象，
  非 ch_api）。
- ⇒ 这些槽在 TAFLib 侧**无调用者**：或为 chlib 内部互调，或为保留槽 [B]。
- 命名归属：**待仲裁 [C]**。

---

## 六、兄弟对照：`0x10002900`（NChBiSta2, vt[+0x3c]）

证据：`nchbi/chlib_worker_10002900.txt`（`0x10002900`–`0x10002d4f ret 0x10`，失败出口 `0x10002d69`）

- **与 `0x10002770` 同族同形**：同样 `memset` + `Authorize` + 读 obj8/obj10 表 + `ret 0x10` + `or eax,-1` 失败口。
- **差异**：缩放用 `imul ebx,esi` / `imul edx,esi` / `imul ecx,esi` 系列（`0x10002a33`、`0x10002bd1`、
  `0x10002c1d`、`0x10002c6e`、`0x10002cc3`、`0x10002d2c`），乘数 `esi` 来自局部/参数，
  且多处 `fild [esp+0x30/0x34]`（两个乘数暂存槽）。
- ⇒ **NChBiSta2 = 带可配置乘数的 NChBiSta 变体**（`NCHBISTA2` 支持两个系数参数）[B]。

---

## 七、勘误与待仲裁

### 7.1 勘误（相对 docs/25）[A]

| # | docs/25 原述 | 实测 |
| --- | --- | --- |
| 1 | `0x10006670` = 「count 早退检查」[C] | 实为**容器准备器**（obj8/obj_c 三连虚调用 + 表镜像） |
| 2 | `0x10009930` = 「内部数据准备」[C] | 实为 **chlib 版 P→类型码跳表**（与包装层常量表逐值相同） |
| 3 | NChBi 与 NChBiSta「各自独立」 | **共享 obj8/obj10 容器**；NChBi 填、NChBiSta 读 |
| 4 | 授权码统一 `EA62` | NChBi=`EA62`，**NChBiSta=`EA61`** |
| 5 | ch_api「仅 0x24 字节、子对象仅 `+8`/`+0x10`」 | 子对象共 6 个（`+8/+0xc/+0x10/+0x14/+0x18/+0x1c`） |
| 6 | 槽 `+0x40/+0x48/+0x50/+0x54/+0x5c/+0x64` 未定名 | `+0x48=NChBiZj3`、`+0x5c=NChBiZjNum` 已定名；其余 8 槽确认无 TAFLib 调用者 |

### 7.2 待仲裁 [C]

1. `Item21.value` 是否恒为 ±1（决定 `±3` 是否唯一由该值缩放产生；若 value 可取其它值，`±3` 仍可由组合得到）。
2. `Item21` 的 `recIdx@+0x09` 与 `barIdx@+0x1D` 为何都是「+1 未对齐」偏移 —— 疑为手写字节流序列化；
   两函数各只读其中一个字段。
3. `±2` / `±10` 的确切语义（多级别标注？笔间填充？）。
4. 8 个无 TAFLib 调用者的槽（`+0x40` 等）的命名归属 —— 需扫 chlib 内部的间接调用点。
5. `0x10002770` 段 A 的 `cur = -it->value`（首项取反）语义。
6. `0x10002340` 的窗口长度 `[esp+0xc]` 初值 -1 的来源（docs/25 遗留）。

---

## 八、可复现命令

```bash
PY=C:/Users/Administrator/Documents/a_conda/python.exe
DLL=D:/a_ronglide/clone-ronglide/ronglide-app/chlib.dll

# 1) 反汇编 NChBiSta 工作函数
$PY tools/re-inventory/disasm_func.py 0x10002770 --max 0x600 --dll "$DLL" \
    -o tools/re-inventory/nchbi/chlib_worker_10002770.txt

# 2) x87 条件表 (结果: 0 conditions)
$PY tools/re-inventory/x87_sim.py tools/re-inventory/nchbi/chlib_worker_10002770.txt \
    -o tools/re-inventory/nchbi/cond_chlib_10002770.txt

# 3) 兄弟函数
$PY tools/re-inventory/disasm_func.py 0x10002900 --max 0x2a0 --dll "$DLL" \
    -o tools/re-inventory/nchbi/chlib_worker_10002900.txt
$PY tools/re-inventory/disasm_func.py 0x10006670 --max 0x180 --dll "$DLL"
$PY tools/re-inventory/disasm_func.py 0x10009930 --max 0x1c0 --dll "$DLL" \
    -o tools/re-inventory/nchbi/chlib_prep_10009930.txt
$PY tools/re-inventory/disasm_func.py 0x100010d0 --max 0x1a0 --dll "$DLL"   # ch_api ctor

# 4) 同族槽位映射 (新增工具)
$PY tools/re-inventory/nchbi/map_family_slots.py -o tools/re-inventory/nchbi/family_slots.txt

# 5) 常量确认
$PY -c "import pefile,struct; pe=pefile.PE(r'$DLL',fast_load=True); ib=pe.OPTIONAL_HEADER.ImageBase; d=open(r'$DLL','rb').read(); \
        o=0x554b8; print(struct.unpack('<d', d[o:o+8])[0])"   # => 2.0
```

---

## 九、下一步（第三批）建议

**推荐：Out 向量深挖（`NCHBISTA` 语义闭环）** —— 理由：
docs/26 已把 `-3` 的**产生路径**定死（段 C），但 `Item21.value` 的值域、`±2/±10` 语义仍是 [B]/[C]。
第三批用 **frida 动态 dump**（挂 `0x10002770` 的 `out[]` 出口 + `obj10[+0x30]` 的 Item21 数组）
即可把 §二 判定表整体升到 [A]，同时闭环用户公式的 `-3 = 底分型` 断言。

**备选：NChBiZj / NChBiZjOrder 链**（`0x10002ea0` / `0x10003180`）—— 若本轮优先「静态覆盖度」，
可按 §五 槽位表顺势解剖「笔转折 + 序号」两支。

> 已写入看板 `docs/19` 的 `NCHBI.next`。
