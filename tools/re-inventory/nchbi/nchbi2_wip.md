# NChBi 第二批 WIP — chlib 算法解剖

证据：`chlib_worker_10002770.txt`(130 insn, `0x10002770`–`0x100028f0 ret 0x10`)。

---

## 1. `0x10002770`(vt[+0x38]=NChBiSta) 入口与签名 [A]

```
0x10002770  sub esp,0xc
0x10002773  push ebx / ebp / esi / edi
ebp = [esp+0x18]  -> arg1 = count        (__thiscall: ecx=this)
edi = [esp+0x24]  -> arg2 = out (double*)
lea eax,[ebp*8]; push eax; push 0; push edi; call 0x1001494c
        => memset(out, 0, count*8)      // 与 0x10002340 同构
```
签名（`ret 0x10` = 4 栈参）：
```c
int __thiscall ch_api::vt38(this /*ch_api*/, int count, double* out, ?arg3, ?arg4);
```
- 返回值：失败路径 `or eax,0xffffffff` → **return -1**；成功 → `xor eax,eax` → **return 0**。
- **无输入 P 参数参与**（与 NChBi 0x10002340 不同；NChBiSta 不用 P）。

## 2. 前置门（4 道，全为「非空 + 授权」）[A]

| 序 | 地址 | 检查 | 失败 |
| --- | --- | --- | --- |
| 1 | 100027a6 | `[[this+8]+0x1c]` != 0 | → 100028e6 return -1 |
| 2 | 100027ba | `[[this+0x10]+0x30]` != 0 | → 100028e6 return -1 |
| 3 | 100027c2 | `[this+4]` (ch_auth*) != 0 | → 100028e6 return -1 |
| 4 | 100027cc-d9 | `ch_auth->vt[+4](0xEA61)` | al==0 → 100028e6 return -1 |

**授权码 = 0xEA61**（NChBi 为 0xEA62；NChBiSta 用 **EA61**）[A]。
⇒ 与 NChBi 0x10002340 的「P==0 才查授权」不同，**NChBiSta 无条件查授权** [A]。

## 3. 两个内部子对象与表结构 [A]

```
obj8  = [this+8]     ; +0x1c = L1c (0x20 字节记录表基址)   +0x28 = L28 (记录数)
obj10 = [this+0x10]  ; +0x30 = base(端点项数组, 步长0x21)   +0x3c = L3c (项数)
```
局部槽（`add esp,0xc` 后 esp=E-0x10，E=sub 后基）：
- `[esp+0x14]` = L1c（记录表，0x20B/条）→ 仅作 `idx*0x20` 基址
- `[esp+0x10]` = L28（记录数）→ `edx` 上界
- `[esp+0x24]` = L3c（项数）→ 外层循环上界
- `[esp+0x20]` = 外层循环计数
- `[esp+0x18]` = 浮点装载暂存（`fild [esp+0x18]`）

**端点项数组**（base=ebx，步长 **0x21 = 33 字节**）字段：
| 偏移 | 类型 | 用途 |
| --- | --- | --- |
| +0x00 | int32 | 符号/值 `v`（`ecx`），参与 `neg` / `*2` / `*3` / `*10` |
| +0x04 | uint8 | 标志位：bit0=「有效项」；bit3(0x08)=「值×2」 |
| +0x09 | int32 | 记录索引 `idx`（须 `0 <= idx < L28`） |

**记录表**（0x20B/条）：`+0x00` = 起 bar、`+0x04` = 止 bar（均 bar 索引）。

## 4. 核心算法：把记录区间展开成逐 bar 阶梯函数 [A]

外层：`k=0; while (k < L3c) { item=[base+9+k*0x21]; ... k++ }`，`esi += 0x21`。

单条记录的处理（`ecx` = 当前 `v`，首项若 `ecx==0` 则 `ecx = -item[+0x00]`）：

| 段 | 地址 | 条件 | 写值 | 范围 |
| --- | --- | --- | --- | --- |
| A 填充 | 10002832-4c | `eax < rec[+0x00] && eax < count` | **`ecx*10`** | `out[eax]`，逐 bar 直到 `eax==rec[+0x00]` |
| B 区间 | 1000284e-79 | `eax <= rec[+0x04] && eax < count` | **`ecx`**（若 `item[+4]&8` 则 **`ecx*2`**） | `out[eax]`，`eax` 从 `rec[+0x00]` 到 `rec[+0x04]` |
| C 端点 | 1000287b-96 | `0 < eax < count` | **`ecx*3`** | `out[eax]`（`eax = rec[+0x04]+1`），然后 `eax++` |
| 尾广播 | 100028b3-d8 | `eax < count` | **`ecx*10`**（`rep movsd` 前向复制 8B） | `out[eax..count-1]` 全为同值 |

- 每次循环末尾 `ecx = item[+0x00]`（10002898）→ 传给下一条记录。
- `idx` 越界（`<0` 或 `>=L28`）→ **直接跳出外层循环**（1000280e `jl` / 10002818 `jae` → 100028b3）。
- **无 `-3/+3/0` 立即数写入**（`grep` 全表仅 `or eax,0xffffffff` 一处立即数）⇒ 输出码由 **`v` 缩放**产生 [A]。

## 5. 输出码判定表（推定）[B]

因 `v = item[+0x00]` 取值域推测为 **{+1, -1}**（方向），故 `out[]` ∈ {0, ±1, ±2, ±3, ±10}：

| 写值 | 来源段 | 语义（推定） |
| --- | --- | --- |
| **±3** | 段 C（`v*3`） | **端点/分型 bar**（`-3` = 底分型，`+3` = 顶分型）★ 对应用户公式 `SELECT(VAR2=-3)` |
| ±1 | 段 B（`v`） | 记录区间内部 bar（笔内） |
| ±2 | 段 B（`v*2`，bit3 置位） | 区间内特殊 bar（待仲裁：多级别/多笔？） |
| ±10 | 段 A / 尾广播（`v*10`） | 记录区间的「填充」段（笔间/无结构段） |
| 0 | memset 初值 | 未覆盖 bar |

**结论 [B]**：`-3` 的唯一产生路径 = **段 C（1000287b-96）**，即「记录 `rec[+0x04]` 之后的第一个 bar，取 `v*3`」。
⇒ `SELECT(VAR2=-3)` 选出的就是**每个结构区间结束后的端点 bar**，与「底分型」语义吻合。
**待仲裁**：`v` 是否恒为 ±1（若 `v` 可取其它值，±3 也可由 `v=±1` 之外的组合得到）；`±10`/`±2` 的确切语义。

---

## 6. ch_api 子对象布局（ctor `0x100010d0` 实证）[A]

vtable 首句 `mov [esi],0x10015214`；子对象全部 `call 0x10013f06`(=operator new) 后置 vtable：

| 成员 | 大小 | vtable | 初始化器 | 角色（本批定性） |
| --- | --- | --- | --- | --- |
| `[this+4]` | — | — | arg | `ch_auth*` |
| `[this+8]`  | 0x2c | **0x100153ec** | 直接置句 (0x1000112c-3e) | **obj8** 记录表产出者（`+0x1c` 表指针 / `+0x28` 计数 / `+0x18` 已备标志） |
| `[this+0xc]` | 0x38 | **0x10015474** | 直接置句 | **obj_c** 派生器（`+0x28`/`+0x34`） |
| `[this+0x10]` | 0x60 | **0x10015438** | `0x10009850` | **obj10 结果容器**（`+0x30` 项基址 / `+0x3c` 项数 / `+0x20`,`+0x24`,`+0x28`,`+0x2c` 表镜像） |
| `[this+0x14]` | 0x68 | **0x1001544c** | `0x1000be70` | **obj14** |
| `[this+0x18]` | 0x60 | ? | `0x1000e7c0` | obj18 |
| `[this+0x1c]` | 0x3c | **0x10015488** | 直接置句 | obj1c（常量 `+0x1c=0xc`, `+0x20=0x1a`, `+0x24=9` ← 参数表?） |

obj8 vt = `0x100094b0 / 0x10009500 / 0x10009530 / 0x1000e0b0`（仅 4 槽，其后即字符串字面量）。
obj_c vt[+0xc] 与 obj8 vt[+0xc] **同为 `0x1000e0b0`**；obj10/obj14/obj1c 的 vt[+0xc] 也都是 `0x1000e0b0` ⇒ **家族统一「clear/reset」虚函数** [B]。

## 7. `0x10006670(this, count)` = 容器准备器 [A]

```
if (obj8[+0x18] == 0):                 ; 未备
    obj8->vt[+4]()                     ; 0x10009500  预清
    obj8->vt[+0xc](0, count, 0, out?, 0)  ; 0x1000e0b0 传 count
    if (obj8->vt[+8]() != 0) return -1 ; 0x10009530
if (obj_c[+0x18] == 0):
    obj_c->vt[+4](); obj_c->vt[+0xc](...)
    obj_c[+0x20] = obj8[+0x1c]; obj_c[+0x24] = obj8[+0x28]   ; 表镜像
    obj_c->vt[+8]()
return 0
```

## 8. `0x10009930(P) -> obj10[+0x1c]` = chlib 版 P→类型码 [A]

```
edx = P - 0xb;  [eax+0x1c] = P
if (P-11 <= 0x28) 跳表 (byte @0x100099a8)  -> [eax+0x1c] = f(P)
else               -> [eax+0x1c] = P
```
跳表目标常量：**11→2、12→1、21→4、22→3、31→6、32→5、51→0（及其它→0）**
⇒ 与 TAFLib 包装层常量表**逐值相同** ⇒ **chlib 独立实现同一 P 编码** [A]。
（注意：`0x10009930` 的 `[eax+0x1c]` 写在 **obj10**。

## 9. NChBi(0x10002340) 的 prep 序列 [A]

```
100023c0  push count; call 0x10006670        ; 备 obj8/obj_c
100023d5  obj10->vt[+4]()                    ; 0x100099e0 预清
100023df  ecx = arg4(P as int); eax = obj10; call 0x10009930   ; obj10[+0x1c] = code(P)
100023eb  obj10->vt[+0xc](count, out, arg3, 0, 0)              ; 0x1000e0b0 主计算
10002403  obj10[+0x20]=obj8[+0x1c]; obj10[+0x24]=obj8[+0x28]
10002415  obj10[+0x28]=obj_c[+0x28]; obj10[+0x2c]=obj_c[+0x34]
10002427  obj10->vt[+8](); if fail return -1
10002439  esi = obj10;  eax = obj10[+0x30](项基址); ecx = obj10[+0x3c](项数)
          -> argmax/argmin 内核（batch-1 已验证）
```

## 10. **是否共享内部容器** —— 结论 [A]

| 项 | NChBi 0x10002340 (vt+0x34) | NChBiSta 0x10002770 (vt+0x38) |
| --- | --- | --- |
| obj8 `[this+8]` | **写**（经 0x10006670 备表，+0x1c/+0x28） | **读**（+0x1c 表 / +0x28 计数） |
| obj_c `[this+0xc]` | 读（+0x28/+0x34 镜像进 obj10） | 不用 |
| obj10 `[this+0x10]` | **写**（+0x30/+0x3c 由 vt[+0xc] 生成） | **读**（+0x30 基址 / +0x3c 项数） |
| ctx6 (arg3) | 用（argmax/argmin 数据源） | **不用**（忽略 arg3/arg4） |
| 调 0x10006670 / 0x10009930 | 是 | **否** |

⇒ **结论：NChBi 与 NChBiSta 共享同一 ch_api 实例的 obj8 + obj10 容器**；
**NChBi 负责「计算并填充」，NChBiSta 负责「读取并展开」** [A]。
⇒ 用户公式 `VAR1:=NCHBI(P); VAR2:=NCHBISTA;` 中 **先算 NCHBI 再取 NCHBISTA 是语义必需**（NCHBISTA 自身不触发计算）[A]。
⇒ 但 NChBiSta 的包装层 `0x10012c40` **不调 prep**（只 Authorize + 填 ctx6 + 调 vt[+0x38]）——
   故 NChBiSta 单独调用时依赖「同一实例上 NChBi 已跑过」；否则容器为空 → 输出全 0。

## 11. 数据流图（文本）[A/B]

```
TAFLib 0x10006cc0(this)
   └─ ctx6 = { +0x00 High, +0x04 Open, +0x08 Low, +0x0c Close, +0x10 Volume, +0x14 Amount }   [RData!XTAData::Get*Buffer]
        │
        ▼  (NChBi 路径: TAFLib 0x10012a50 -> ch_api vt[+0x34] = chlib 0x10002340)
chlib 0x10006670(count) ──> obj8.vt[+0xc](count)  => obj8[+0x1c] 记录表(0x20B/条) , obj8[+0x28] 记录数
                                     │
                                     ├─> obj_c[+0x20..0x24] 镜像
                                     ▼
                          obj10.vt[+0xc](count, out, ctx6, ...)  => obj10[+0x30] 端点项数组(0x21B/条) , obj10[+0x3c] 项数
                                     │         (+ obj10[+0x1c] = code(P) 由 0x10009930)
                                     ▼
                     argmax(ctx6.H) / argmin(ctx6.L) 内核  (-DBL_MAX@0x100154c8 / +DBL_MAX@0x100154c0)

        ▼  (NChBiSta 路径: TAFLib 0x10012c40 -> ch_api vt[+0x38] = chlib 0x10002770)
chlib 0x10002770(count, out)   ← 只读 obj8[+0x1c]/[+0x28] 与 obj10[+0x30]/[+0x3c]
   for k in 0..obj10[+0x3c]-1:
       item = obj10[+0x30] + k*0x21
       idx  = item[+0x09]             (须 0 <= idx < obj8[+0x28])
       rec  = obj8[+0x1c] + idx*0x20  (rec[+0x00] 起 bar, rec[+0x04] 止 bar)
       out[..rec[+0]]        = v*10   (段A 填充)
       out[rec[+0]..rec[+4]] = v (或 v*2 若 item[+0x04]&8)   (段B 区间)
       out[rec[+4]+1]        = v*3    (段C 端点 ★)
   out[尾部] = 最后一个 v*10 (rep movsd 广播)
```
- 步长：obj8 记录表 **0x20** 字节/条；obj10 端点项数组 **0x21** 字节/条。
- 索引：`item[+0x09]` → 记录索引；`rec[+0x00]/rec[+0x04]` → bar 区间。
- 输出：`out[]`（double×count），初值 0（memset），值是 **`v` 的 {×10, ×1, ×2, ×3} 缩放**。
- **`0x10002770` 不使用 ctx6**（无行情读取、无 x87 比较）⇒ 是**纯结构展开器**。

---

## 12. 同族槽位全映射（加分项）[A]

工具：`nchbi/map_family_slots.py`（新入仓）；证据：`nchbi/family_slots.txt`（NChB* 族）、`nchbi/family_slots_full.txt`（全导出 117 个）。
方法：对每个 TAFLib 导出反汇编，匹配模式 `mov ecx,[esi+0xbc]; mov edx,[ecx]; mov edx,[edx+0xNN]` → 得槽号；
再用 chlib ch_api 虚表 `0x10015214` 把槽号翻译成 chlib 函数地址。

### 12.1 NChBi 家族槽位表（+0x18 .. +0x60）[A]

| 槽 | chlib 函数 | TAFLib 导出（`CalcProc_*`） | chlib 反汇编证据 |
| --- | --- | --- | --- |
| +0x18 | 0x10001590 | **NChBhh** / **NChBh** | 本批未解剖 |
| +0x1c | 0x10001690 | **NChBhl** | 本批未解剖 |
| +0x20 | 0x10001790 | **NChRef** | 本批未解剖 |
| +0x24 | 0x10001a10 | **NChFx** | 本批未解剖 |
| +0x28 | 0x10001bd0 | **NChFxSta** | 本批未解剖 |
| +0x2c | 0x10001d90 | **NChFxUpDn** | 本批未解剖 |
| +0x30 | 0x10002190 | **NChFxOrder** | 本批未解剖 |
| **+0x34** | **0x10002340** | **NChBi** | `chlib_worker_10002340.txt`（batch-1） |
| **+0x38** | **0x10002770** | **NChBiSta** | `chlib_worker_10002770.txt`（**本批**） |
| +0x3c | 0x10002900 | **NChBiSta2** | `chlib_worker_10002900.txt`（本批，见 §13） |
| +0x44 | 0x10002ea0 | **NChBiZj** | 本批未解剖 |
| +0x48 | 0x10002fc0 | **NChBiZj3** | 本批未解剖（**新定名**） |
| +0x4c | 0x10003180 | **NChBiZjOrder** | 本批未解剖 |
| +0x58 | 0x10003680 | **NChBiFxNum** | 本批未解剖 |
| +0x5c | 0x100038b0 | **NChBiZjNum** | 本批未解剖（**新定名**） |
| +0x60 | 0x10003a90 | **NChBiSpeed** | 本批未解剖 |

### 12.2 全族扩展（+0x78 .. +0xc4）[A]

`?CalcProc_NChDuanKh/Kl/Kd`、`NChZs`、`NChZs_L2` **共用槽 +0x78 = 0x100045f0**（靠 P 区分）；
`NChZsG +0x7c`、`NChZsD +0x80`、`NChZsBs12 +0x84`、`NChZsBs3 +0x88`、`NChZsBreach +0x8c`、
`NChZsL2M +0x90`、`NChZsFj +0x94`、`NChZsDg +0x98`、`NChZsHLTurn +0x9c`、`NChFjZsNum +0xa0`、
`NChZsSel +0xa4`、`NChZsSelPri +0xa8`、`NChZsSelSlPri +0xac`、`NChZsSelSpPri +0xb0`、
`NChMacdArea +0xb8`、`NChSecArea +0xbc`、`Xuech/Xuech2 +0xc4 = 0x10006470`。
⇒ **chlib 的 ch_api 是一个 50+ 虚函数的大接口**，覆盖 NChBhh…NChSecArea…Xuech 全族。

### 12.3 8 个「无 TAFLib 调用者」的槽 [B]

`+0x40=0x10002d80`、`+0x50=0x10003330`、`+0x54=0x10003450`、`+0x64=0x10003cd0`、
`+0x68=0x10004170`、`+0x6c=0x100042f0`、`+0x70=0x100043e0`、`+0x74=0x100044d0`

- 字节模式扫描 TAFLib `.text`（`8B 42/4A/52/5A/62/6A/72/7A NN`）：这 8 个槽 **0 处引用**
  （`+0x64` 的 2 处 `mov eax,[edx+0x64]` 落在 `CalcProc_BuyK`(0x100144e0) 内，`edx` 是 BuyK 私有对象，非 ch_api）。
- ⇒ **这些槽在 TAFLib 侧无调用者**：或为 chlib 内部互调（内部虚拟函数），或为未启用/保留槽 [B]。
- 命名归属：**待仲裁 [C]**（需在 chlib 内查谁调用这些槽，或与其它 TAFLib 导出族比对）。

## 13. 兄弟对照：`0x10002900`(NChBiSta2) [B]

- 与 `0x10002770` **同族同形**：同样 `memset` + `Authorize` + 读 obj8/obj10 表，但**缩放用 `imul`** 而非 `lea`：
  `0x10002a93 fild [ebx-9]`、多处 `imul ebx, esi` / `imul edx, esi` / `imul ecx, esi`（`esi` = 乘数常量）
  ⇒ **NChBiSta2 = 带可配置乘数的 NChBiSta 变体**（NCHBISTA2 允许附加系数）[B]。
- 多个 `fild [esp+0x30/0x34]` 暂存 → 同「整数→double」套路。
- 失败路径同形 `or eax,0xffffffff; ret 0x10`；正常出口 `ret 0x10`。
