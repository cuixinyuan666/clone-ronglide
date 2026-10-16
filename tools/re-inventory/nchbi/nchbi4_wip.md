# NChBi 第四批 WIP — 生产端分型几何 + Zj 配对链

批次: NChBi 第四批 (2026-10-17), 对应 docs/28
口径: 静态覆盖度为主; frida 动态本轮不跑 (预备包保持 docs 现状)

---

## WIP T1-A — `0x1000e1c0` (obj_c fill, raw 29B 记录生产者) 分型几何解码

### 函数签名/骨架 [A]
- `__thiscall` obj_c fill: `ecx = obj_c*`（函数尾 `ret` 无参 → 无栈参）
- 入参：`obj_c[+0x20]` = **bar 数组首指针**；`obj_c[+0x24]` = **bar 数量 count**
- 早退：`count==0` 或 `arr==0` → `eax=-1`（0x1000e443）
- 前置：`obj_c[+0x18]=1`；`call 0x10006b60(count)` = raw 数组预分配；`obj_c[+0x34]=0`（out_count 清零）
- 主循环：`i`（edi/`[esp+0x1c]`）从 0 到 count-1，`ebp = bar_base - 8 + 0x20*i`，每轮 `ebp+=0x20`

### bar 记录布局 [A]（源数组 stride **0x20**）
| 偏移 | 类型 | 语义（本函数用到） |
|---|---|---|
| +0x00 | f64 | （本函数未用） |
| +0x08 | i32 | 顶分型记录值（TOP 时写入 rec[+0x09]，见 0x1000e280/285） |
| +0x0c | i32 | 底分型记录值（BOTTOM 时写入 rec[+0x09]，见 0x1000e305/308） |
| **+0x10** | **f64** | **HIGH（高点）** ★ |
| **+0x18** | **f64** | **LOW（低点）** ★ |

> 三种字段寻址（`ebp=bar[i]-8`）：`[ebp-8]=bar[i-1]+0x10`(prev.high)、`[ebp]=bar[i-1]+0x18`(prev.low)、
> `[ebp+0x18]=bar[i]+0x10`(cur.high)、`[ebp+0x20]=bar[i]+0x18`(cur.low)、
> `[ebp+0x38]=bar[i+1]+0x10`(next.high)、`[ebp+0x40]=bar[i+1]+0x18`(next.low)

### ★ 8 个分型几何条件逐条解码 [A]
三条 K 线窗口 `bar[i-1] / bar[i] / bar[i+1]`（要求 `1<=i<=count-2`，见 0x1000e220/244 边界门）。

**顶分型（value=+1）** —— 4 条全须成立（0x1000e24c–27e，`test ah,5; jp` 落空 = `<`）：
| # | 地址 | 比较 | 语义 |
|---|---|---|---|
| 1 | 0x1000e24c–257 | prev.high **<** cur.high | 高点高于左邻 |
| 2 | 0x1000e259–264 | prev.low  **<** cur.low  | 低点高于左邻 |
| 3 | 0x1000e266–271 | next.high **<** cur.high | 高点高于右邻 |
| 4 | 0x1000e273–27e | next.low  **<** cur.low  | 低点高于右邻 |

**底分型（value=-1）** —— 4 条全须成立（0x1000e2c3–2fd，`test ah,0x41; jne` 跳出 = `>`）：
| # | 地址 | 比较 | 语义 |
|---|---|---|---|
| 5 | 0x1000e2c3–2ce | prev.high **>** cur.high | 高点低于左邻 |
| 6 | 0x1000e2d4–2df | prev.low  **>** cur.low  | 低点低于左邻 |
| 7 | 0x1000e2e5–2f0 | next.high **>** cur.high | 高点低于右邻 |
| 8 | 0x1000e2f2–2fd | next.low  **>** cur.low  | 低点低于右邻 |

⇒ **恰是缠中说禅标准分型定义**：顶分型 = 中间 K 线高低点均为三根中最高；底分型 = 均为最低。
⇒ **假说证实 [A]**：`raw[+0x00] = +1 → 顶分型`（0x1000e28f `mov [esp+0x20],1`）、`= -1 → 底分型`（0x1000e3ec `mov [esp+0x20],0xffffffff`）。无第三值（本函数 raw[0] 只写 ±1；`0` 初值仅用于 memset 缓冲，若未命中则整条不 emit）。

### 两条 emit 路径 [A]
- **主路径（中间 bar，3 窗）**：命中顶/底 → 写 `rec[+0x0d] = cur.high`(TOP,0x1000e2a5)/`max(prev.high,next.high)`(BOT,0x1000e320–335)；
  `rec[+0x15] = min(prev.low,next.low)`(TOP,0x1000e2ac–c1)/`cur.low`(BOT,0x1000e339)。
  → 记录 `obj_c[+0x34]++`。
- **尾路径（最后 1 根 bar，2 窗）**：仅当 `obj_c[+0x1c]!=0` ∧ `i>=1` ∧ `i+1==count` ∧ `out_count>0`（0x1000e36b–38d）；
  只查 2 条（prev vs cur，顶：0x1000e393–3ab 的 A<X ∧ B<Y；底：0x1000e3c8–3e0 的 A>X ∧ B>Y），
  emit 时 **`or byte [esp+0x24], 2`**（0x1000e3fb）→ **flags bit1 = "尾根合成分型"**。

### rec(=raw 29B) 字段台账 [A]
| 偏移 | 类型 | 来源 |
|---|---|---|
| +0x00 | i32 | **±1**：+1 顶 / -1 底 |
| +0x04 | u8 | bit0 = helper(0x1000e450/0x1000e500) 返回真；bit1 = 尾根合成（0x1000e3fb） |
| +0x05 | i32 | 分型中心 bar 序号 `i`（初值 -1，0x1000e33c 写 edi） |
| +0x09 | i32 | TOP→`bar[i]+0x08`；BOTTOM→`bar[i]+0x0c`（平行 int 字段，语义待 T2/T3 定） |
| +0x0d | f64 | TOP→cur.high；BOTTOM→max(prev.high,next.high) |
| +0x15 | f64 | TOP→min(prev.low,next.low)；BOTTOM→cur.low |

⚠ **尺寸对齐**：raw rec = 7×dword(28) + 1 byte = **0x1D(29)**。而 **Item21 stride 0x21(33) = raw 29B + 尾部追加 4B barIdx@+0x1d**（与 docs/27 Item21 无 +0x1d 冲突的根因 → 勘误候选）。

### 待解（本轮 T1 内继续）
- helper `0x1000e450`(top) / `0x1000e500`(bottom)：返回真代表什么？（bit0 语义）
- `0x10006b60`：raw 数组预分配（疑似 vector reserve）
- bar[+0x08]/[+0x0c] 两个 i32 语义（顶层 bar 数组填充者是谁？）

### WIP T1-B — helper 语义确权（bit0 来源）

**子取数器**（`ret 4`，签名 `al f(eax=obj_c, ecx=idx, [esp+4]=double* out)`）[A]：
- `0x1000e110`：`idx∈[0,obj_c[+0x14])` → `*out = ((double*)obj_c[+0x0c])[idx]`
- `0x1000e0e0`：同构 → `*out = ((double*)obj_c[+0x08])[idx]`
- ⇒ `obj_c[+0x08]` / `obj_c[+0x0c]` 是两条 **double 数组**，长度均 `obj_c[+0x14]`（数组基址 0，无头）。

**TOP 确认器 `0x1000e450`**（`ecx=i, eax=i+1, edx=obj_c*`，`al`=是否确认）[A]：
1. 门：`out_count>0`（需已有上一条记录）∧ `i+1<count` ∧ `i<i+1`；
2. `idx1 = bar[i].+0x04`（i32）须 ∈`[0,obj_c[+0x14])`；`idx2 = bar[i+1].+0x00`（i32）须 ∈`[0,obj_c[+0x14])`；
3. 取 `C[idx1]`（C=`obj_c[+0x0c]`）、`B[idx2]`（B=`obj_c[+0x08]`）、`C[idx2]`；
4. 要求 **`B[idx2] < C[idx1]`**（0x1000e4c8–4d5，严格）；
5. 要求 **`C[idx2] < raw[out_count-1].+0x15`**（0x1000e4d7–4ea；`ebx*0x1d-8+base` = 上一条记录 +0x15）★
   → 上一条 TOP 记录的 +0x15 = `min(prev.low,next.low)`，即**新顶的"确认低"必须低于上一顶的确认低**（严格递减）。

**BOTTOM 确认器 `0x1000e500`** [A]：
1. 同门；`idx1=bar[i].+0x04`、`idx2=bar[i+1].+0x00`；
2. 取 `B[idx1]`、`C[idx2]`、`B[idx2]`；
3. 要求 **`C[idx2] > B[idx1]`**（0x1000e578–585，严格）；
4. 要求 **`B[idx2] > raw[out_count-1].+0x0d`**（0x1000e58a–59a；`-0x10`⇒上一条 +0x0d）★
   → 上一条 BOTTOM 记录的 +0x0d = `max(prev.high,next.high)`，即**新底的"确认高"必须高于上一底的确认高**（严格递增）。

⇒ **flags bit0 = "本分型通过了相对上一条记录的同向单调确认"** [A]。
⇒ **缠论笔语义**：顶/底必须交替且"确认位"逐步抬升/下移（顶的确认低逐步降低、底的确认高逐步升高）——不满足则该分型被降级为 flags bit0=0（仍 emit，但标记为未确认）。

### 附带确权 [A]
- `bar` 记录另含 **两个 i32 @+0x00 / +0x04**，被当作**索引**使用（指向 `obj_c[+0x08]`/`obj_c[+0x0c]` 两条 double 数组，`m=obj_c[+0x14]`）；与用于 rec[+0x09] 的 `+0x08/+0x0c` 是**不同字段**。
- ⇒ bar 布局修正为：`{i32 @+0x00, i32 @+0x04, i32 @+0x08, i32 @+0x0c, f64 HIGH @+0x10, f64 LOW @+0x18}`（stride 0x20）。

### WIP T2 — Zj 配对链 4+N 函数解码

**obj10 成员补映射 [A]**（本批新确权）：
| 偏移 | 语义 | 证据 |
|---|---|---|
| +0x1c | **类型码**（P 派生：0=P51,1=P12,2=P11,3=P22,4=P21,5=P32,6=P31） | 0x1000a20x/0x1000abb0 分派 |
| +0x30 | **Item21 数组基址**（stride 0x21） | 0x1000a250/a190/a210 |
| +0x3c | **Item21 项数 n** | 同上边界检查 |
| +0x44 | **"当前活动项"游标 cur** | 0x1000a190 写、0x1000a210 回退 |
| +0x48 | 置 -1 | 0x1000a1b5 |
| +0x4c | 置 0 | 0x1000a1bc |
| +0x50 | 子对象/向量地址（传入 0x1000ba30） | 0x1000b26f/b465 |
| +0x20 | **bar 数组基址** | 0x1000a060/a080 |
| +0x24 | bar 数量 | 0x1000a060/a080 |
| +0x08 / +0x0c | 两条 double 数组基址（长度 +0x14） | 0x1000e110/e0e0 |
| +0x14 | 上述 double 数组长度 | 0x1000e110/e0e0 |

**`0x1000a250(obj10=ecx, i=eax) → j`** 《★待仲裁 [B] #1 结案》[A]：
```
if i<0 or i>=obj[+0x3c] → return -1
j := i-1; 从 j 向前扫描（每次 j--, 指针 -=0x21）:
    若 Item21[j].flags & 1（bit0 有效）→ 立即 return j
    扫到 j<0 → return -1
```
⇒ **选 j 规则 = 向前找"最近的 bit0 有效项"，无距离约束、无 value 约束（value 相反由 0x1000abb0 另行校验）**。
⇒ 证实 docs/27「0x1000b000 流程」中 `j = 0x1000a250(obj10,i)` 的语义。

**`0x1000a060(obj=ecx, i=eax) → double`** [A]：`i∈[0,obj[+0x24])` → `obj[+0x20][i*0x20 + 0x10]` = **bar[i].HIGH**；越界 → 0.0
**`0x1000a080(obj=ecx, i=eax) → double`** [A]：同构取 `+0x18` = **bar[i].LOW**；越界 → 0.0
⇒ 《★待仲裁 [B] #2 结案》：取值容器 = **obj_c bar 数组（obj10[+0x20]，stride 0x20）**，**非 obj8 Rec20**；`0x1000a060`=HIGH，`0x1000a080`=LOW。

**`0x1000a290(obj=edx, i=eax)`** [A]：向前扫，返回最近的 **`value==1` 且 `flags&1`** 项 → **"最近有效顶"**
**`0x1000a2d0(obj=edx, i=eax)`** [A]：向前扫，返回最近的 **`value==-1` 且 `flags&1`** 项 → **"最近有效底"**

**`0x1000a190(obj=eax/esi, i=ecx)` = 激活项 + 级联清理** [A]：
- `Item21[i].flags = (flags & ~0x02) | 0x01`（**置 bit0、清 bit1**）
- `obj[+0x44]=i`（游标=i）、`obj[+0x48]=-1`、`obj[+0x4c]=0`
- 若 `flags & 0x10`：看 `Item21[i+1]`；若其后项 `+0x04 & 0x20`（bit5）→ `0x1000aeb0(obj,i+1)`；
  若 `Item21[i+1].flags & 1 == 0` → 清 `Item21[i].bit4` 后调 `0x1000a0a0`/`0x1000a0f0`/`0x1000a140`

**`0x1000a210(obj=esi, i=eax)` = 失效化项** [A]：
- 仅当 `flags & 1`：`flags = (flags & ~0x05) | 0x02`（**清 bit0 & bit2、置 bit1**）
- 若 `i >= obj[+0x44]`：`obj[+0x44] = 0x1000a250(obj,i)`（游标回退到前一个有效项）

**`0x1000abb0(obj10=edx, j=ecx, i=eax) → al` 《★待仲裁 [B] #3 复核判据》** [A 骨架 / B 各分支不等式方向]：
1. `j<0` → **true**（0x1000abbd）
2. `i<0 ∨ i>=obj[+0x3c] ∨ j>=i` → **false**
3. `Item21[j].value == Item21[i].value` → **false**（**必须一顶一底**）
4. ebx := value==1 的项（顶）；edi := 另一项（底）
5. 按 `obj[+0x1c]` 类型码分三类：
   - **类 A：type∈{0,1,2}（P=51/12/11）** → 0x1000ace1：要求 `bottom.+0x0d < top.+0x0d` ∧ `bottom.+0x15 < top.+0x15` → 转 0x1000acfb
   - **类 B：type∈{5,6}（P=32/31）** → 0x1000ac39：用 `recIdx@+0x09` 及其前一根 bar，取 **min LOW / max HIGH** 邻域极值，再与 top/bottom 的 `+0x0d`/`+0x15` 比较 → 0x1000acbf → 转 tail
   - **类 C：type∈{3,4}（P=22/21）** → 直接 0x1000acfb
6. **公共 tail（0x1000acfb）**：取 `top.recIdx@+0x09`、`bottom.recIdx`，要求
   **`bar[bottom.recIdx].HIGH < bar[top.recIdx].HIGH` ∧ `bar[bottom.recIdx].LOW < bar[top.recIdx].LOW`** → **true**
   （即"底参考 bar 在高低两个维度上都低于顶参考 bar" = **几何分离确证**）
⇒ 复核判据本质 = **顶底值相反 + 序 (`j<i`) + 参考 bar 几何分离**（分类型附加判据）。
⇒ 与 `0x1000b000` 的关系：`0x1000b000` 第 6 步调 `0x1000abb0`，通过则 `Item21[j].flags |= 4`（bit2 = Zj 配对确认）。

**`0x1000ae50` = 复合配对校验器** [B]：`0x1000a680` → `0x1000a940` → `0x1000a310` → `0x1000abb0` → `0x1000ad60` 全通过返回 1；是"某对是否可配对"的总判据（含 0x1000abb0）。

**`0x1000b100(obj10=[ebp+8], count=[ebp+0xc]) → eax∈{0,1,2}` 用途标注** [B]（399 条，未逐条解）：
- **同向"合并/延伸" driver**：`count<2` 早退；`j=0x1000a250(obj10,count)`；
- 比较 `Item21[count].value` 与 `Item21[j].value`：
  - **不等**（顶底交替）→ 走"新极值"分支：value==1 时用 `0x1000a290` 找最近有效顶比 HIGH、否则用 `0x1000a2d0` 找最近有效底比 LOW；成功返回 **1（顶）/2（底）**；
  - **相等**（同向）→ 走"延伸/吞并"分支（0x1000b20b 起）：用 `0x1000a060`/`0x1000a080` 取 recIdx 处 HIGH/LOW 比较、`0x1000abb0` 复核、`0x1000ae50` 复验，命中则 `0x1000b000` 置 bit2、并用 `0x1000a190`/`0x1000a210` 增删项；`0x14`(20) 为迭代上限。
- 返回 0 = 无操作。⇒ 它是 **NChBi 族（非 Sta）的"笔序列构造主驱动"**，被 `nchbi` 系列槽调用（非本批 out 消费者）。

### Item21.flags 位台账（本批汇总）[A]
| 位 | 值 | 语义 | 证据 |
|---|---|---|---|
| bit0 | 0x01 | **有效/已确认项**（配对扫描只看它） | 0x1000a250/a290/a2d0 |
| bit1 | 0x02 | **已失效/取消** | 0x1000a210 置；0x1000a190 清 |
| bit2 | 0x04 | **Zj 配对确认**（NChBiZj 散射门） | 0x1000b000 / docs/27 |
| bit3 | 0x08 | **×2 标记** | docs/27 |
| bit4 | 0x10 | 级联清理标志 | 0x1000a190 检查/清 |
| bit5 | 0x20 | 后项联动标志 | 0x1000a190（[+0x21+4]&0x20） |

### WIP T3 — 全链综合 + 判定表升级

**全链（bar → 顶底 → Zj → out）** [A]：
```
obj_c[+0x20] bar[] (stride 0x20, n=obj_c[+0x24])
  └ 0x1000e1c0  3根K线分型(8条件) → value=±1, 上一条单调确认 → flags bit0
obj_c[+0x28] raw[] (stride 0x1D=29B, n=obj_c[+0x34])
  └ 0x10009a20(obj10.vt[+8]) → 0x10009a50(P51) / 0x10009dd0(code1..6)
obj10[+0x30] Item21[] (stride 0x21=33B = raw29 + barIdx@+0x1d, n=obj10[+0x3c])
  └ 0x1000b100 合并driver → 0x1000a250(前向bit0) / 0x1000a290(顶) / 0x1000a2d0(底)
    0x1000b000 pair→bit2 (经 0x1000abb0 复核)    0x1000a060 HIGH / 0x1000a080 LOW
obj8 Rec20 (stride 0x20: startBar,endBar) + Item21
  └ 5 消费者: NChBiSta(0x10002770) / NChBiZj(0x10002ea0) / NChBiZjOrder(0x10003180) / NChBiZj3 / NChBiZjNum
out[]
```

**判定表升级（docs/26 §7.2 + docs/27 §6.2）**：
| 项 | 原 | 现 | 依据 |
|---|---|---|---|
| Item21.value ≡ ±1 | [B] | **[A]** | 0x1000e1c0 只写 ±1；0x1000e1c0/0x10009a50/0x10009dd0 |
| ±2 / ±10 语义 | [B] | **[A]** | ±2=bit3×2；±10=Sta段A（batch3 + 本批 bit 台账） |
| Item21 +0x09/+0x1d 偏移"未对齐" | [B] | **[A]** | 手写紧凑结构：4+1(flags)+4 ⇒ 后续字段自然落在 +0x05/+0x09；Item21 尾部再追加 4B barIdx ⇒ +0x1d |
| `0x1000a250` 配对规则 | [B] | **[A]** | 前向扫最近 flags&1 项；无距离/value 约束 |
| `0x1000a060`/`0x1000a080` 取值 | [B] | **[A]** | 取 obj_c bar 数组 HIGH(+0x10)/LOW(+0x18)，非 obj8 |
| `0x1000abb0` 复核判据 | [B] | **[A 骨架]**（分支不等式 [B]） | value相反 + j<i + 按类型码 3 分支 + 公共几何分离 |
| ZjNum `cnt` 语义 | [C] | [C] | 需运行时对拍 |
| ZjOrder arg3/arg4 来源 | [C] | [C] | 需上层 TAFLib 调用点 |
| 8 无调用者槽命名 | [C] | [C] | 未动 |
| 0x10002340 [esp+0xc] 初值 -1 | [C] | [C] | 未动 |
| bar 数组填充者（obj[+0x00..+0x0c] i32 语义） | — | [B] 新 | 本批新增待办 |

### WIP-END T3
