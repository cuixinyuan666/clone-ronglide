# docs/27 — NChBi 第三批：NChBiZj/ZjOrder 链与 Out 静态深挖

> 起点 `49d8d66`（origin/old1 0/0）。本批口径：docs/26 §九 的 frida 动态路线因「软件未运行/无人值守」降级为**预备包**（见 §五），
> 主攻**静态覆盖度**——即 docs/26 §九 的备选路线（NChBiZj/NChBiZjOrder 链）＋判定表可静态升级的部分。
> 全部证据文件位于 `tools/re-inventory/nchbi/`，命令见 §七。

## 〇、摘要

1. **T1 NChBiZj（vt[+0x44]=`0x10002ea0`）**：Item21 的**散射器**——`flags bit2` 置位者，`out[barIdx@+0x1d] = value@+0x00`；授权码 **0xEA61**。无 x87 条件。
2. **T2 NChBiZjOrder（vt[+0x4c]=`0x10003180`）**：先调 `vt[+0x5c]`(NChBiZjNum) 把 ZjNum 结果灌入本地 `vector<double>`，
   再按「bit0 有效 ∧ 非 bit3 ∧ recIdx 界 ∧ |ZjNum[barIdx]| ≥ THR」过滤，重排到 `out[Rec20[recIdx+1].startBar]`；授权码同为 **0xEA61**。
3. **T3（本批最大收获）**：**Item21 的写入者确权**为 `obj10->vt[+8]() = 0x10009a20`（按类型码分派到 `0x10009a50` / `0x10009dd0`），
   其数据源是 **obj_c 的 29B 原始记录数组**（`0x1000e1c0` 生产），由此：
   - **docs/26 §7.2 待仲裁 #1 结案**：`Item21.value ≡ ±1（或 0）` **[A]** ⇒ ±3/±2/±10 全为该值整数倍缩放，非独立值域；
   - **flags bit2 语义结案**：`0x1000b000` 内 `or [j+4],4` —— **bit2 = "已配对确认的 Zj 项"**，正是 NChBiZj 的门 **[A]**；
   - 全族（NChBi/Sta/Zj/ZjNum/ZjOrder）**均为 Item21 的纯消费者**，生产链在 obj_c→obj10 之内。

## 一、T1 —— NChBiZj（`0x10002ea0`）

### 1.1 签名与出口 [A]
- `__thiscall` + `ret 0x10`；`this=ecx`；`arg1=count(int)` / `arg2=out(double*)` / `arg3` / `arg4`（后二者本函数内未引用）
- 首段 `memset(arg2, 0, arg1*8)`（`0x1001494c` = thunk→`memset`，IAT `0x100150c4`）⇒ **out 为 double[count]，先清零**
- 成功 `xor eax,eax; ret 0x10`；失败统一 `or eax,-1`

### 1.2 四道门 [A]
1. `obj10 = this[+0x10]`；`BASE = obj10[+0x30]`（Item21 数组）、`CNT = obj10[+0x3c]`（条数）
2. `BASE == 0` → -1
3. `this[+4]`(ch_auth*) == 0 → -1
4. `Authorize(0xEA61)`（`mov edx,[ecx]; call [edx+4]`，`push 0xea61`）失败 → -1
   - ★ **NChBiZj 授权码 = 0xEA61**（与 NChBiSta 同码；**非** 0xEA62）

### 1.3 核心：Item21 散射 [A]
- 遍历 Item21，stride **0x21**，条数 `obj10[+0x3c]`；主循环按 4 条展开（`0x10002f00–0x10002f7e`，`add eax,0x84`），余数走尾循环（`0x10002f80–0x10002fb2`，`add eax,0x21`）
- 单条判定（四个展开体交叉确证）：
  - `test byte ptr [item+0x04], 4` → **bit2 未置位则跳过**
  - `ecx = item[+0x1d]`；`0 <= ecx < count` 越界保护
  - `fild dword ptr [item+0x00]`（int32 → double）
  - **`out[ item.barIdx@+0x1d ] = (double) item.value@+0x00`**
- 四条展开体字段偏移对照（eax 初值 = BASE+0x3e，逐条 +0x84）：

  | 项 | value | flags | idx |
  |---|---|---|---|
  | 0 | `[eax-0x3e]` | `[eax-0x3a]` | `[eax-0x21]` |
  | 1 | `[eax-0x1d]` | `[eax-0x19]` | `[eax]` |
  | 2 | `[eax+4]` | `[eax+8]` | `[eax+0x21]` |
  | 3 | `[eax+0x25]` | `[eax+0x29]` | `[eax+0x42]` |

  相对各 item 基址恒为 **+0x00 / +0x04 / +0x1d**。

### 1.4 与 NChBiSta / NChBi 的关系 [A]
- **共享 obj10**：同读 `this[+0x10]` 的 `[+0x30]`(基址)/`[+0x3c]`(条数) ⇒ NChBiZj 依赖 NChBi 先跑（填 obj10）
- **不读 obj8**：本函数无 `this[+8]` 引用（ZjOrder 才有）
- x87：**0 条件**（仅 `fild`/`fstp`）

## 二、T2 —— NChBiZjOrder（`0x10003180`）

### 2.1 签名与出口 [A]
- `__thiscall` + `ret 0x10`，SEH 帧 + `and esp,-8`
- `arg1=count` / `arg2=out(double*)` / `arg3=透传` / **`arg4=阈值指针`**
- **`THR = (int)( *(double*)(*arg4) )`**（`mov eax,[ebp+0x14]; mov ecx,[eax]; fld [ecx]; call _ftol2@0x100148a0`）
- 首段同为 `memset(out,0,count*8)`

### 2.2 三段结构
**段1（0x100031d5–0x10003237）填本地向量**
- `A = obj8[+0x1c]`、`B = obj8[+0x28]`（obj8 = `this[+8]`）；`BASE = obj10[+0x30]`、`CNT = obj10[+0x3c]`
- 门：`A==0` → -1；`BASE==0` → -1
- 本地 `std::vector<double> vec`（三 dword 清零）→ **`0x10006c00(&vec, count)` = `vec.resize(count)`**
- **调用 `vt[+0x5c]` = NChBiZjNum(count, vec.begin, arg3, arg4)**；返回非 0 → `free(vec)` + -1

**段2（0x10003261–0x10003285）授权门 —— 在调用 ZjNum 之后！**
- `this[+4]==0` 或 `Authorize(0xEA61)` 失败 → `0x10011900`(vec 析构) + -1 ⇒ **授权码同为 0xEA61**

**段3（0x10003287–0x100032fe）过滤 + 重排**
- 遍历 Item21（esi 从 BASE+9 起，stride 0x21）：
  - `flags@+0x04`：**bit0 必须置位**、**bit3 必须清零**
  - `recIdx@+0x09`：`0 <= recIdx < B`
  - `barIdx@+0x1D` → `fabs(vec[barIdx]) ≥ THR`（否则跳过）
  - `recIdx+1 < B`
  - **`out[ *(int*)(A + (recIdx+1)*0x20) ] = (double) value@+0x00`**
    - `A = obj8[+0x1c]` = **Rec20 数组（stride 0x20）**；取 `Rec20[recIdx+1].startBar@+0x00` 作目标下标（写点 0x100032d7–0x100032e7）
- 收尾：析构 vec、`xor eax,eax`

### 2.3 与 T1 的关系（差异段）
- **共享 obj10**（Item21@+0x30/+0x3c）；ZjOrder 额外读 **obj8**（Rec20@+0x1c / 条数@+0x28）
- **门相同**：`Authorize(0xEA61)`
- **ZjOrder 内嵌 Zj 族输出**：先跑 ZjNum 得间隔计数，再据其做阈值过滤
- **"Order" 证伪/证实**：不是"序号排序"，而是**按记录序列重排**——目标下标取 `Rec20[recIdx+1].startBar`（下一段的起始 bar）[A]
- 门位差异：Zj 用 **bit2**；ZjOrder 用 **bit0 ∧ ¬bit3**

## 三、T3 —— Out 向量静态深挖（Item21 全字段确权）

### 3.1 三层数据流 [A]

```
bar 数组 (obj_c[+0x20], stride 0x20, count obj_c[+0x24])
        │  0x1000e1c0  (x87 8 条件分型几何判定)
        ▼
raw 29B 记录 (obj_c[+0x28], stride 0x1D, count obj_c[+0x34])
        │  NChBi(0x10002340) 拷 → obj10[+0x28]/[+0x2c]；同时 obj8 元数据 → obj10[+0x20]/[+0x24]
        ▼
obj10  ── obj10.vt[+8] = 0x10009a20（按 obj10[+0x1c] 类型码分派）──▶ Item21 (obj10[+0x30], stride 0x21, count obj10[+0x3c])
        ├ code 0 (P=51) → 0x10009a50   flags ∈ {0x01, 0x21, 0x11} | 0x08
        └ code 1..6     → 0x10009dd0   flags ∈ {0x00, 0x10, 0x20} | 0x08；并对 bit0 项生成配对件(value=±1, flags=0x20)
                              └ 0x1000b000 置 bit2（Zj 配对确认）
        ▼
Item21 ── 5 个消费者 ──▶ out[]
```

### 3.2 Item21 字段来源表 [A]

| Item21 偏移 | 来源 | 语义 |
|---|---|---|
| `+0x00` | `raw[+0x00]`（code1..6 路径另有 `setne;lea eax,[eax+eax-1]` 合成 ±1） | **value ∈ {0,±1}** |
| `+0x04` | 计算所得（见 3.3） | flags |
| `+0x05` | 1-based 源序号 / 源下标 | ordinal |
| `+0x09` | `raw[+0x05]` | **recIdx** |
| `+0x0d` | `raw[+0x0d]`（double） | 备用几何量 |
| `+0x15` | `raw[+0x15]`（double） | 备用几何量 |
| `+0x1d` | `raw[+0x09]` | **barIdx（out 目标下标）** |

- Item21 整体由本地 33B 缓冲 `rep movsd×8 + movsb` 拷入（`0x10009ada`/`0x10009b74`）
- 源记录 29B 经 `rep movsd×7 + movsb` 拷入（`0x1000e35c`/`0x1000e41d`）

### 3.3 flags 位语义（全表）[A]

| bit | 值 | 置位条件 | 置位点 |
|---|---|---|---|
| 0 | 0x01 | code0：恒置位（首件=1）；code1..6：见下（**不恒置**） | 0x10009acc / 0x10009ac0 前 |
| 1 | 0x02 | — | **未使用** |
| 2 | **0x04** | **`0x1000b000` 配对确认（Zj）** | **0x1000b0bb `or [edi+4],4`** |
| 3 | 0x08 | `raw[+0x04] & 2` | 0x10009b40 / 0x10009ed3（`or …,8`） |
| 4 | 0x10 | code0：`(raw[i-1][+5]+1==raw[i][+5]) ∧ (raw[i-1][+4]&1)`；code1..6：`raw[i][+4]&1` | 0x10009b34 / 0x10009edd |
| 5 | 0x20 | code0：`raw[i][+4] & 1`；code1..6：配对件 | 0x10009b1c / 0x10009ef1 |

**全 .text 扫描**「向字节字段写 bit2」的指令仅 6 处，与本族相关的唯一一处即 `0x1000b0bb`（详见 §3.4）。

### 3.4 ★ bit2 setter = `0x1000b000`（NChBiZj 的门闭合成 [A]）
`0x1000b000(Item21_i)`（eax=obj10/esi；栈参 i；`ret 4`；返回 bool）：
1. `i < 2` → false；`Item21[i].flags & 1` → false（只处理 bit0=0 的项）
2. `j = 0x1000a250(obj10, i)`（**配对查找**，返回 index 或 <0）
3. `j < 0` → true（无配对，直接放行）
4. `Item21[j].value != Item21[i].value` → false
5. `value == 1` 时要求 `g(barIdx[j]) > g(barIdx[i])`（`0x1000a060`）；否则要求 `g(barIdx[j]) < g(barIdx[i])`（`0x1000a080`）
6. `0x1000abb0(...)` 复核通过 → **`Item21[j].flags |= 4`**，返回 true

⇒ **bit2 = "该项已被配对确认为 Zj 点"**；写在后件 `j`。**NChBiZj 的 bit2 门即取此标记**。

调用者：code1..6 路径 `0x10009ff5 call 0x1000b000`；另有 `0x1000b100(obj10, i)`。

### 3.5 ★ docs/26 §7.2 待仲裁 #1 结案 [A]
- `0x1000e1c0` 写 `raw[+0x00] ∈ {0, +1, -1}`（0x1000e280 置 1 / 0x1000e307 与 0x1000e3e2 取 `ecx=-1` / 0x1000e36 初值 0）
- `Item21[+0x00] = raw[+0x00]`（0x10009a50）；code1..6 路径另合成 ±1（0x10009ef5–0x10009f01）
- ⇒ **`Item21.value ≡ ±1（或 0）`**。故 **±3 = 3×value**（NChBiSta 段C）为 ±3 的**唯一**产生路径；±2 = 2×value（bit3）；±10 = 10×value（NChBiSta 段A）。

### 3.6 ★ 升级版输出码判定表

| 函数 | 门 | 动作 | 位置 | 置信 |
|---|---|---|---|---|
| NChBi `0x10002340` | `flags&1` | `out[barIdx] = value` | 0x1000249d | [A] |
| NChBi | `flags&8` | `out[barIdx] *= 2.0`（`fld 2.0@0x100154b8; fmul`） | 0x100024a6 | [A] |
| NChBi | 首件 value 符号 | `>=0`→out[0..N) **argmin**（种子 `+DBL_MAX@0x100154c0`）；`<0`→**argmax**（种子 `-DBL_MAX@0x100154c8`） | 0x10002606/0x100026a4 | [A] |
| NChBi | — | `out[bestIdx] = -2 × firstValue`（`neg eax; add eax,eax`） | 0x10002741–0x10002754 | [A] |
| NChBiSta `0x10002770` | — | 段A `×10`；段B `×1`/`×2`(bit3)；段C `×3`；尾广播 | docs/26 §1.4 | [A] |
| NChBiZj `0x10002ea0` | **`flags&4`** | `out[barIdx] = value` | 0x10002f28 | [A] |
| NChBiZjNum `0x100038b0` | `flags&1` | `out[barIdx] = cnt`（cnt = 自上个 bit0 项以来 value 变化的 bit2 项计数；命中后 cnt=0，`ecx=该件value` 供下轮 `cmp`） | 0x1000393a–0x10003958 | [A] |
| NChBiZjOrder `0x10003180` | `flags&1 ∧ ¬flags&8 ∧ recIdx∈[0,B) ∧ recIdx+1<B ∧ |ZjNum[barIdx]|≥THR` | `out[Rec20[recIdx+1].startBar] = value` | 0x100032a0–0x100032e7 | [A] |

授权码汇总：**NChBi / ZjNum = 0xEA62**；**NChBiSta / NChBiZj / NChBiZjOrder = 0xEA61**（非统一，[A]）。

### 3.7 ±2 / ±10 语义结案（docs/26 §7.2 #3）[A]
- **±2**：`flags bit3` 触发的 `×2`（NChBi 0x100024a6 与 NChBiSta 段B 双证）——"该档强度翻倍"
- **±10**：NChBiSta 段A 独立缩放（docs/26 段A）——"最强档"
- **±3**：NChBiSta 段C
- 三者均为**同一 ±1 基值在不同输出槽位的整数倍**，**不存在**独立值域

## 四、辅助函数辨识（IAT 实证）[A]
- chlib.dll 仅导入 MSVCR80 / MSVCP80 / KERNEL32（**无 TAFLib**）⇒ 再次坐实 chlib 不回主模块
- `0x1001494c` = thunk→**memset**（`0x100150c4`）；`0x100150b0`=**free**；`0x100150b4`=**malloc**
- `0x10006c00` = **`std::vector<double>::resize(n)`**（`nv=malloc(n*8); memset(nv,0,n*8); memcpy(nv,old,size*8); free(old)`）
- `0x10011900` = **`std::vector` 析构/清零**（三指针布局 begin@+0 / cap@+4 / size@+8）
- `0x10009930` = **类型码 setter**：`obj10[+0x1c] = f(P)`（P-0xb 查跳表 `0x10009988`，值∈{2,1,4,3,6,5,0}）
- `0x10009a20` = **类型码分派器**：`obj10[+0x1c] == 0 → 0x10009a50`；`∈[1,6] → 0x10009dd0`；其它 → -1

### obj10 / obj8 / obj_c 关键成员
- `obj10 = this[+0x10]`（vt `0x10015438`）：`+0x1c` 类型码 / `+0x20` Rec20 基址 / `+0x24` Rec20 条数 / `+0x28` raw 基址 / `+0x2c` raw 条数 / `+0x30` **Item21 数组** / `+0x3c` **Item21 条数**
- `obj8 = this[+8]`（vt `0x100153ec`）：`+0x1c` Rec20 基址 / `+0x28` Rec20 条数
- `obj_c = this[+0xc]`（vt `0x10015474`）：`+0x20` bar 数组 / `+0x24` bar 条数 / `+0x28` raw 数组 / `+0x34` raw 条数

## 五、T4 —— frida 动态验证预备包（本轮**未运行**）
- 方案：`tools/re-inventory/nchbi/frida_nchbi3.md`（含 5 个挂点、attach/`-f` 两种运行方式、6 条对拍清单、坑位）
- 脚本：`tools/re-inventory/nchbi/frida_dump_out.js`（可直接用；已按 ASLR 自动取 chlib 基址；每次 read 均有 try/catch）
- 本机 frida **17.23.3**（CLI + frida-python 实测存在）
- 运行时机：用户在场启动交易软件后执行，即可把本表整体升到"运行时实证"

## 六、勘误与待仲裁

### 6.1 勘误（本批自查）[A]
1. **esp 槽换算修正**：初版把 ZjOrder 的 `mov esi,[esp+0x2c]`（call 前 esp=S-0x48）误算为 A 槽；实为 **S-0x1c = &vec 的首 dword = vec.begin**。
   修正依据：`call 0x10006c00` 的 `ret 4` 同时弹返回址与参数，esp 链回到 S-0x44，由此 line40/41/42/25/35 与循环内 `[esp+X]` 全部自洽。
2. **docs/26 §3.3 补充**：`0x1000e0b0` 实为 **5 参 setter**（`[ecx+4..0x14] = args`），非"统一主计算/清空"；该槽（vt[+0x0c]/[+0x20]）在多张虚表重复出现，是通用字段写入器。

### 6.2 待仲裁 [B]/[C]
- **[B] `0x1000a250` 配对查找的确切语义**（Zj 配对按什么规则选 j）——本批只确证其返回 index 且被 `0x1000b000` 使用
- **[B] `0x1000a060` / `0x1000a080`**：取值函数（一个用于 value==1、一个用于 value==-1），是否为 high/low 或 时间序
- **[B] `0x1000abb0`**：`0x1000b000` 的第 6 步复核判据
- **[C] ZjNum 的 `cnt` 语义**到底是"间隔笔数"还是"间隔 bar 数"——需运行时对拍（T4）
- **[C] `arg3`（ZjOrder 透传给 ZjNum）与 `arg4`（阈值指针）在 TAFLib 侧的实参来源**——需上层调用点
- **[C] 本批未做动态验证**（frida 预备包待运行）

## 七、可复现命令

```bash
PY=C:/Users/Administrator/Documents/a_conda/python.exe
cd D:/a_ronglide/clone-ronglide

# 1) T1/T2 反汇编
$PY tools/re-inventory/disasm_func.py 0x10002ea0 --max 0x600 --dll ronglide-app/chlib.dll -o tools/re-inventory/nchbi/chlib_worker_10002ea0.txt
$PY tools/re-inventory/disasm_func.py 0x10003180 --max 0x600 --dll ronglide-app/chlib.dll -o tools/re-inventory/nchbi/chlib_worker_10003180.txt
# 2) x87 条件表（两者均为 0 conditions）
$PY tools/re-inventory/x87_sim.py tools/re-inventory/nchbi/chlib_worker_10002ea0.txt -o tools/re-inventory/nchbi/cond_chlib_10002ea0.txt
$PY tools/re-inventory/x87_sim.py tools/re-inventory/nchbi/chlib_worker_10003180.txt -o tools/re-inventory/nchbi/cond_chlib_10003180.txt
# 3) T3 生产链
$PY tools/re-inventory/disasm_func.py 0x100038b0 --max 0x600 --dll ronglide-app/chlib.dll -o tools/re-inventory/nchbi/chlib_worker_100038b0.txt
$PY tools/re-inventory/disasm_func.py 0x10009a20 --max 0xa00 --dll ronglide-app/chlib.dll -o tools/re-inventory/nchbi/chlib_item21_fill_10009a20.txt
$PY tools/re-inventory/disasm_func.py 0x10009a50 --max 0xa00 --dll ronglide-app/chlib.dll -o tools/re-inventory/nchbi/chlib_item21_body_10009a50.txt
$PY tools/re-inventory/disasm_func.py 0x10009dd0 --max 0x900 --dll ronglide-app/chlib.dll -o tools/re-inventory/nchbi/chlib_item21_code16_10009dd0.txt
$PY tools/re-inventory/disasm_func.py 0x1000b000 --max 0x300 --dll ronglide-app/chlib.dll -o tools/re-inventory/nchbi/chlib_bit2_1000b000.txt
$PY tools/re-inventory/disasm_func.py 0x1000e1c0 --max 0x600 --dll ronglide-app/chlib.dll -o tools/re-inventory/nchbi/chlib_objc_fill_1000e1c0.txt

# 4) obj8/obj10/obj_c 虚表槽 dump（本批内联 python 片段，见 nchbi3_wip.md）
# 5) frida 预备包（未运行）
#    frida -p <PID> -l tools/re-inventory/nchbi/frida_dump_out.js
```

## 八、下一步（第四批）建议

**推荐：NChBi 第四批 —— 生产端（obj_c/obj10）核心补完 + Zj 配对规则**。理由：
1. 本批把**消费端**（5 个 out 消费者）基本做满（[A] 全覆盖），剩余 [B] 全部落在**生产端**：`0x1000e1c0` 的分型几何 8 条件、
   `0x1000a250/0x1000a060/0x1000a080/0x1000abb0`（配对与取值）——补完即打通"bar → 顶底 → Zj → out"全链。
2. 与 **CHBI 第六批（481 条件逐条落地）** 相比，本链**收敛度更高**（候选函数已锁定、命名已确权），单位收益更大；
   CHBI 481 条件属大工程，宜在 NChBi 族闭环后再开。
3. T4 的 frida 预备包随时可跑，一旦用户在场即可把上述全部静态结论一次性升级为运行时实证——**建议第四批把"T4 运行"列为可选第一步**。
