# docs/28 — NChBi 第四批：生产端分型几何与 Zj 配对

- 目标模块：`chlib.dll`（106496 B，ImageBase 0x10000000）
- 工具：`tools/re-inventory/disasm_func.py --dll`、`x87_sim.py`、`scan_member.py`
- 置信标注：**[A]** = 反汇编直证；**[B]** = 强推断（有地址支撑，方向性待仲裁）；**[C]** = 待运行时/上层证据
- 口径：本轮**静态**为主；T4（frida 动态）**未运行**（需用户在场启动交易软件）

---

## 〇、摘要

本批打通了 **bar → 顶底分型 → raw 记录 → Item21 → Zj 配对 → out** 的生产端主链：

1. **`0x1000e1c0`（obj_c fill）= 标准缠论 3 根 K 线分型判定** [A]。8 条几何条件逐条解码：顶分型 = 中间 K 线高低点均为三根中最高（value=+1）；底分型 = 均为最低（value=-1）。并含"相对上一条记录的单调确认器"，产出 `flags bit0`。
2. **raw 29B 记录 → Item21 33B 记录** 的结构关系确权 [A]：`Item21 = raw(29B) + 尾部 barIdx(4B)@+0x1d`，解释了 docs/26 §7.2 #2 的"+1 未对齐"疑点。
3. **Zj 配对链 4+N 函数解码** [A]：`0x1000a250`（前向找最近 bit0 有效项）、`0x1000a060`/`0x1000a080`（取 bar HIGH/LOW）、`0x1000a290`/`0x1000a2d0`（找最近有效顶/底）、`0x1000a190`/`0x1000a210`（激活/失效项）、`0x1000abb0`（顶底合法对复核）。
4. **判定表升级**：把 docs/26 §7.2 与 docs/27 §6.2 的 6 个 [B] 项中的 5 个升为 [A]。

---

## 一、T1 —— `0x1000e1c0`（obj_c fill，raw 记录生产者）

### 1.1 签名与骨架 [A]

`__thiscall`：`ecx = obj_c*`（函数尾 `ret` 无栈参）。

| 步骤 | 地址 | 语义 |
|---|---|---|
| 入参 | 0x1000e1cd/d1 | `obj_c[+0x20]` = bar 数组首指针；`obj_c[+0x24]` = bar 数量 n |
| 早退 | 0x1000e1db/e3/e443 | `n==0` 或 `arr==0` → `eax=-1` |
| 前置 | 0x1000e1ed–1f1 | `obj_c[+0x18]=1`；`0x10006b60(n)` 预分配 raw 数组 |
| 清计数 | 0x1000e1fa | `obj_c[+0x34]=0`（raw 条数） |
| 主循环 | 0x1000e20c–431 | `i` 从 0 到 n-1，`ebp = bar_base - 8 + 0x20*i`，每轮 `ebp += 0x20` |

### 1.2 bar 数组布局 [A]（stride **0x20**）

| 偏移 | 类型 | 语义 |
|---|---|---|
| +0x00 | i32 | 索引（指向 `obj_c[+0x08]` 数组；见 1.5） |
| +0x04 | i32 | 索引（指向 `obj_c[+0x0c]` 数组；见 1.5） |
| +0x08 | i32 | 写入 raw[+0x09]（TOP 时） |
| +0x0c | i32 | 写入 raw[+0x09]（BOTTOM 时） |
| **+0x10** | **f64** | **HIGH（高点）** |
| **+0x18** | **f64** | **LOW（低点）** |

三种字段寻址（`ebp = bar[i] - 8`）：

| 表达式 | 实际地址 | 语义 |
|---|---|---|
| `[ebp-8]` | bar[i-1]+0x10 | prev.HIGH |
| `[ebp]` | bar[i-1]+0x18 | prev.LOW |
| `[ebp+0x18]` | bar[i]+0x10 | **cur.HIGH** |
| `[ebp+0x20]` | bar[i]+0x18 | **cur.LOW** |
| `[ebp+0x38]` | bar[i+1]+0x10 | next.HIGH |
| `[ebp+0x40]` | bar[i+1]+0x18 | next.LOW |

### 1.3 ★ 8 条分型几何条件逐条解码 [A]

三根 K 线窗口 `bar[i-1] / bar[i] / bar[i+1]`（边界门：`1<=i<=n-2`，见 0x1000e220/244）。

**顶分型（value=+1）** —— 4 条全须成立（`test ah,5; jp` 落空 = `<`）：

| # | 地址 | 比较 | 语义 |
|---|---|---|---|
| 1 | 0x1000e24c–257 | prev.HIGH **<** cur.HIGH | 高点高于左邻 |
| 2 | 0x1000e259–264 | prev.LOW **<** cur.LOW | 低点高于左邻 |
| 3 | 0x1000e266–271 | next.HIGH **<** cur.HIGH | 高点高于右邻 |
| 4 | 0x1000e273–27e | next.LOW **<** cur.LOW | 低点高于右邻 |

**底分型（value=-1）** —— 4 条全须成立（`test ah,0x41; jne` 跳出 = `>`）：

| # | 地址 | 比较 | 语义 |
|---|---|---|---|
| 5 | 0x1000e2c3–2ce | prev.HIGH **>** cur.HIGH | 高点低于左邻 |
| 6 | 0x1000e2d4–2df | prev.LOW **>** cur.LOW | 低点低于左邻 |
| 7 | 0x1000e2e5–2f0 | next.HIGH **>** cur.HIGH | 高点低于右邻 |
| 8 | 0x1000e2f2–2fd | next.LOW **>** cur.LOW | 低点低于右邻 |

> **结论 [A]**：恰为**缠中说禅标准分型定义**。`raw[+0x00] = +1 → 顶分型`（0x1000e28f），`= -1 → 底分型`（0x1000e3ec）。
> 本函数 raw[0] 只写 ±1 ⇒ **docs/26 §7.2 #1 再确认：`Item21.value ≡ ±1`**。
> 对应 `x87_sim.py` 输出：14 conditions（含 min/max 2 条与尾路径 4 条），与手工解码**逐条一致**。

### 1.4 两条 emit 路径 + raw 记录字段台账 [A]

- **主路径（中间 bar，3 窗）**：
  - TOP：`raw[+0x0d] = cur.HIGH`（0x1000e2a5）；`raw[+0x15] = min(prev.LOW, next.LOW)`（0x1000e2ac–c1）
  - BOTTOM：`raw[+0x0d] = max(prev.HIGH, next.HIGH)`（0x1000e320–335）；`raw[+0x15] = cur.LOW`（0x1000e339）
- **尾路径（末根 bar，2 窗）**：仅当 `obj_c[+0x1c]!=0` ∧ `i>=1` ∧ `i+1==n` ∧ `out_count>0`（0x1000e36b–38d）；
  只查 prev vs cur 两条；emit 时 **`or byte [esp+0x24], 2`**（0x1000e3fb）⇒ **`flags bit1 = 尾根合成分型`**。

**raw 记录（stride 0x1D = 29 B）**：

| 偏移 | 类型 | 来源 |
|---|---|---|
| +0x00 | i32 | **±1**（+1 顶 / -1 底） |
| +0x04 | u8 | bit0 = 确认器返回真；bit1 = 尾根合成 |
| +0x05 | i32 | 分型中心 bar 序号 `i`（初值 -1，0x1000e33c） |
| +0x09 | i32 | TOP→`bar[i]+0x08`；BOTTOM→`bar[i]+0x0c` |
| +0x0d | f64 | TOP→cur.HIGH；BOTTOM→max(prev.HIGH,next.HIGH) |
| +0x15 | f64 | TOP→min(prev.LOW,next.LOW)；BOTTOM→cur.LOW |

**尺寸对齐 [A]（结案 docs/26 §7.2 #2）**：29 = 4(value)+1(flags)+4(ordinal)+4(refIdx)+8+8。1 字节 flags 使后续 int 落在 `+0x05/+0x09` 奇数偏移；
而 **Item21 stride 0x21(33) = raw 29B + 尾部追加 4B `barIdx@+0x1d`** ⇒ 两者的"+1 未对齐"均为**手写紧凑序列化**的自然结果。

### 1.5 helper 确认器（`flags bit0` 来源）[A]

**子取数器**（`ret 4`，`al f(eax=obj_c, ecx=idx, [esp+4]=double* out)`）：

| 函数 | 语义 |
|---|---|
| `0x1000e110` | `idx∈[0,obj_c[+0x14])` → `*out = ((double*)obj_c[+0x0c])[idx]` |
| `0x1000e0e0` | 同构 → `*out = ((double*)obj_c[+0x08])[idx]` |

⇒ `obj_c[+0x08]` / `obj_c[+0x0c]` 是两条 **double 数组**，长度均 `obj_c[+0x14]`（数组基址即偏移 0）。

**TOP 确认器 `0x1000e450`**（`ecx=i, eax=i+1, edx=obj_c*`）[A]：

1. 门：`out_count>0` ∧ `i+1<n` ∧ `i<i+1`；
2. `idx1 = bar[i]+0x04`、`idx2 = bar[i+1]+0x00` 均须 ∈ `[0, obj_c[+0x14])`；
3. 取 `C[idx1]`（C=`obj_c[+0x0c]`）、`B[idx2]`（B=`obj_c[+0x08]`）、`C[idx2]`；
4. 要求 **`B[idx2] < C[idx1]`**（0x1000e4c8–4d5，严格）；
5. 要求 **`C[idx2] < raw[out_count-1].+0x15`**（0x1000e4d7–4ea；`out_count*0x1d-8+base` = 上一条 +0x15）★

**BOTTOM 确认器 `0x1000e500`** [A]：

1. 同门；
2. 取 `B[idx1]`、`C[idx2]`、`B[idx2]`；
3. 要求 **`C[idx2] > B[idx1]`**（0x1000e578–585，严格）；
4. 要求 **`B[idx2] > raw[out_count-1].+0x0d`**（0x1000e58a–59a，`-0x10` ⇒ 上一条 +0x0d）★

> **结论 [A]**：`flags bit0 = "本分型相对上一条记录通过同向单调确认"`。
> 上一条 TOP 的 `+0x15 = min(prev.LOW,next.LOW)`（"确认低"）、上一条 BOTTOM 的 `+0x0d = max(prev.HIGH,next.HIGH)`（"确认高"）；
> 即 **顶的确认低须逐步降低、底的确认高须逐步升高**（缠论笔的交替抬升语义）。不满足 → 仍 emit，但 `bit0=0`。

---

## 二、T2 —— Zj 配对链

### 2.1 obj10 成员补映射 [A]

| 偏移 | 语义 | 证据 |
|---|---|---|
| +0x1c | **类型码**（0=P51, 1=P12, 2=P11, 3=P22, 4=P21, 5=P32, 6=P31） | 0x1000abb0 分派 |
| +0x30 | **Item21 数组基址**（stride 0x21） | 0x1000a250/a190/a210 |
| +0x3c | **Item21 项数 n** | 同上边界检查 |
| +0x44 | **"当前活动项"游标 cur** | 0x1000a190 写 / 0x1000a210 回退 |
| +0x48 | 置 -1 | 0x1000a1b5 |
| +0x4c | 置 0 | 0x1000a1bc |
| +0x50 | 子对象/向量地址（传入 0x1000ba30） | 0x1000b26f/b465 |
| +0x20 | **bar 数组基址** | 0x1000a060/a080 |
| +0x24 | bar 数量 | 0x1000a060/a080 |
| +0x08 / +0x0c | 两条 double 数组基址（长度 +0x14） | 0x1000e110/e0e0 |
| +0x14 | 上述 double 数组长度 | 0x1000e110/e0e0 |

### 2.2 `0x1000a250`（配对查找）《★ docs/27 §6.2 #1 结案》[A]

```
f(obj10=ecx, i=eax) → j:
  if i<0 or i>=obj[+0x3c] → -1
  j := i-1
  while j >= 0:
      if Item21[j].flags & 1:  return j     ; bit0 有效
      j--; ptr -= 0x21
  return -1
```

⇒ **规则 = 向前找"最近的 bit0 有效项"；无距离约束、无 value 约束**（value 相反由 `0x1000abb0` 另行校验）。

### 2.3 `0x1000a060` / `0x1000a080`（取值）《★ docs/27 §6.2 #2 结案》[A]

| 函数 | 语义 |
|---|---|
| `0x1000a060(obj=ecx, i=eax)` | `i∈[0,obj[+0x24])` → `obj[+0x20][i*0x20 + 0x10]` = **bar[i].HIGH**；越界 0.0 |
| `0x1000a080(obj=ecx, i=eax)` | 同构取 `+0x18` = **bar[i].LOW**；越界 0.0 |

⇒ 取值容器 = **obj_c bar 数组（`obj10[+0x20]`，stride 0x20）**，**非 obj8 Rec20**；`0x1000a060`=HIGH，`0x1000a080`=LOW。

### 2.4 `0x1000a290` / `0x1000a2d0`（定值查找）[A]

| 函数 | 语义 |
|---|---|
| `0x1000a290` | 向前扫，返回最近的 **`value==1` 且 `flags&1`** 项 → **"最近有效顶"** |
| `0x1000a2d0` | 向前扫，返回最近的 **`value==-1` 且 `flags&1`** 项 → **"最近有效底"** |

### 2.5 `0x1000a190`（激活项）/ `0x1000a210`（失效项）[A]

**`0x1000a190(obj=eax/esi, i=ecx)` = 激活 + 级联清理**：

- `Item21[i].flags = (flags & ~0x02) | 0x01`（**置 bit0、清 bit1**）
- `obj[+0x44]=i`（游标=i）、`obj[+0x48]=-1`、`obj[+0x4c]=0`
- 若 `flags & 0x10`：看 `Item21[i+1]`；若 `Item21[i+1].+0x04 & 0x20`（bit5）→ `0x1000aeb0(obj,i+1)`；
  若 `Item21[i+1].flags&1 == 0` → 清 `Item21[i].bit4` 后调 `0x1000a0a0`/`0x1000a0f0`/`0x1000a140`

**`0x1000a210(obj=esi, i=eax)` = 失效化**：

- 仅当 `flags & 1`：`flags = (flags & ~0x05) | 0x02`（**清 bit0 & bit2、置 bit1**）
- 若 `i >= obj[+0x44]`：`obj[+0x44] = 0x1000a250(obj,i)`（游标回退到前一有效项）

### 2.6 `0x1000abb0`（复核判据）《★ docs/27 §6.2 #3 结案》[A 骨架 / B 分支方向]

`al f(obj10=edx, j=ecx, i=eax)`：

1. `j<0` → **true**（0x1000abbd）
2. `i<0 ∨ i>=obj[+0x3c] ∨ j>=i` → **false**
3. `Item21[j].value == Item21[i].value` → **false**（**必须一顶一底**）
4. `ebx := value==1 的项`（顶）；`edi := 另一项`（底）
5. 按 `obj[+0x1c]` 类型码分三类：
   - **类 A：type∈{0,1,2}（P=51/12/11）** → 0x1000ace1：`bottom.+0x0d < top.+0x0d` ∧ `bottom.+0x15 < top.+0x15` → 转 0x1000acfb
   - **类 B：type∈{5,6}（P=32/31）** → 0x1000ac39：用 `refIdx@+0x09` 及其前一根 bar，取 **min LOW / max HIGH** 邻域极值，再与 top/bottom 的 `+0x0d`/`+0x15` 比较 → 0x1000acbf → 转 tail
   - **类 C：type∈{3,4}（P=22/21）** → 直接 0x1000acfb
6. **公共 tail（0x1000acfb）**：取 `top.refIdx@+0x09`、`bottom.refIdx`，要求
   **`bar[bottom.refIdx].HIGH < bar[top.refIdx].HIGH` ∧ `bar[bottom.refIdx].LOW < bar[top.refIdx].LOW`** → **true**（几何分离确证）

⇒ 复核判据本质 = **顶底值相反 + 序 `j<i` + 参考 bar 几何分离**（按 P 类型附加判据）。
⇒ 与 `0x1000b000` 的关系：`0x1000b000` 第 6 步调 `0x1000abb0`，通过则 `Item21[j].flags |= 4`（**bit2 = Zj 配对确认**，即 NChBiZj 的散射门）。

### 2.7 `0x1000ae50` / `0x1000b100`（组合器与 driver）

- **`0x1000ae50` = 复合配对校验器** [B]：`0x1000a680` → `0x1000a940` → `0x1000a310` → `0x1000abb0` → `0x1000ad60` 全通过返回 1。
- **`0x1000b100(obj10=[ebp+8], count=[ebp+0xc]) → eax∈{0,1,2}` 用途标注** [B]（399 条，未逐条解）：
  - **同向"合并/延伸" driver**：`count<2` 早退；`j = 0x1000a250(obj10,count)`；
  - 比较 `Item21[count].value` 与 `Item21[j].value`：
    - **不等**（顶底交替）→ 走"新极值"分支：value==1 用 `0x1000a290` 找最近有效顶比 HIGH、否则用 `0x1000a2d0` 找最近有效底比 LOW；成功返回 **1（顶）/2（底）**；
    - **相等**（同向）→ 走"延伸/吞并"分支（0x1000b20b 起）：用 `0x1000a060`/`0x1000a080` 比 recIdx 处 HIGH/LOW、`0x1000abb0` 复核、`0x1000ae50` 复验，命中则 `0x1000b000` 置 bit2、并用 `0x1000a190`/`0x1000a210` 增删项；`0x14`(20) 为迭代上限。
  - 返回 0 = 无操作。⇒ **NChBi 族"笔序列构造主驱动"**（非本批 out 消费者）。

### 2.8 Item21.flags 位台账（本批汇总）[A]

| 位 | 值 | 语义 | 证据 |
|---|---|---|---|
| bit0 | 0x01 | **有效/已确认项**（配对扫描只看它） | 0x1000a250/a290/a2d0 |
| bit1 | 0x02 | **已失效/取消** | 0x1000a210 置；0x1000a190 清 |
| bit2 | 0x04 | **Zj 配对确认**（NChBiZj 散射门） | 0x1000b000 / docs/27 |
| bit3 | 0x08 | **×2 标记** | docs/27 |
| bit4 | 0x10 | 级联清理标志 | 0x1000a190 检查/清 |
| bit5 | 0x20 | 后项联动标志 | 0x1000a190（`[+0x21+4] & 0x20`） |

---

## 三、T3 —— 全链综合与判定表升级

### 3.1 全链数据流 [A]

```
obj_c[+0x20] bar[]  (stride 0x20, n = obj_c[+0x24])
   └─ 0x1000e1c0  3 根 K 线分型(8 条件) → value=±1 + 上一条单调确认 → flags bit0
obj_c[+0x28] raw[]  (stride 0x1D=29B, n = obj_c[+0x34])
   └─ 0x10009a20 (obj10.vt[+8]) → 0x10009a50 (P51) / 0x10009dd0 (code1..6)
obj10[+0x30] Item21[]  (stride 0x21=33B = raw 29B + barIdx@+0x1d, n = obj10[+0x3c])
   └─ 0x1000b100 合并 driver
       ├─ 0x1000a250 前向找 bit0 有效项      ├─ 0x1000a290 找最近有效顶
       ├─ 0x1000a2d0 找最近有效底            ├─ 0x1000a060 HIGH / 0x1000a080 LOW
       ├─ 0x1000b000 配对 → bit2 (经 0x1000abb0 复核、0x1000ae50 复验)
       └─ 0x1000a190 激活项 / 0x1000a210 失效项
obj8 Rec20 (stride 0x20: startBar,endBar) + Item21
   └─ 5 消费者: NChBiSta(0x10002770) / NChBiZj(0x10002ea0) / NChBiZjOrder(0x10003180) / NChBiZj3 / NChBiZjNum
out[]
```

### 3.2 生产端函数台账

| 函数 | 输入 | 输出 | 关键常量/门 | 置信 |
|---|---|---|---|---|
| `0x1000e1c0` | obj_c（`+0x20` bar, `+0x24` n） | raw[]（obj_c[+0x28]，`+0x34` 计数） | 3 窗 8 条件；`obj_c[+0x1c]` 尾根门 | [A] |
| `0x1000e450` / `0x1000e500` | obj_c, i, i+1 | `al` 确认位 | 上一条 `+0x15`（顶）/`+0x0d`（底） | [A] |
| `0x1000e110` / `0x1000e0e0` | obj_c, idx, out* | `obj_c[+0x0c]`/`[+0x08]` 数组取值 | 长度 `obj_c[+0x14]` | [A] |
| `0x1000a250` | obj10, i | j（<0 = 无） | 前向扫 `flags&1` | [A] |
| `0x1000a290` / `0x1000a2d0` | obj10, i | j（<0 = 无） | 前向扫 `value==±1 ∧ flags&1` | [A] |
| `0x1000a060` / `0x1000a080` | obj10, i | bar[i].HIGH / LOW | 界 `obj10[+0x24]` | [A] |
| `0x1000a190` / `0x1000a210` | obj10, i | 改 Item21[i].flags + 游标 | bit0↔bit1 互斥；游标 `+0x44` | [A] |
| `0x1000abb0` | obj10, j, i | `al` 合法对 | value 相反；类型码 3 分支；几何分离 | [A/B] |
| `0x1000ae50` | obj10, ? | `al` 可配对 | 5 连环校验 | [B] |
| `0x1000b100` | obj10, count | 0/1/2 | 同向合并 driver；上限 20 | [B] |

### 3.3 判定表升级

| 项 | 原 | 现 | 依据 |
|---|---|---|---|
| Item21.value ≡ ±1 | [B] | **[A]** | 0x1000e1c0 只写 ±1（本批）+ batch3 |
| ±2 / ±10 语义 | [B] | **[A]** | ±2 = bit3 ×2；±10 = NChBiSta 段 A 缩放 |
| Item21 `+0x09/+0x1d` 偏移"未对齐" | [B] | **[A]** | 手写紧凑结构（4+1+4…）+ 尾部追加 4B barIdx |
| `0x1000a250` 配对规则 | [B] | **[A]** | 前向扫最近 `flags&1` |
| `0x1000a060`/`0x1000a080` 取值 | [B] | **[A]** | obj_c bar 数组 HIGH/LOW |
| `0x1000abb0` 复核判据 | [B] | **[A 骨架]** | value 相反 + `j<i` + 类型 3 分支 + 几何分离 |
| ZjNum `cnt` 语义 | [C] | [C] | 需运行时对拍 |
| ZjOrder arg3/arg4 来源 | [C] | [C] | 需上层 TAFLib 调用点 |
| 8 个无调用者槽命名 | [C] | [C] | 未动 |
| `0x10002340` `[esp+0xc]` 初值 -1 | [C] | [C] | 未动 |
| bar 数组填充者 / `+0x00..0x0c` i32 语义 | — | **[B] 新增** | 本批新增待办 |

---

## 四、T4 —— frida 动态验证预备包（本轮**未运行**）

保持批次三现状，不改动：

- `tools/re-inventory/nchbi/frida_nchbi3.md`（方案文档）
- `tools/re-inventory/nchbi/frida_dump_out.js`（可直接运行脚本）
- 本机 frida 17.23.3 实测在位；用户在场时一条命令即可把上述 [B]/[C] 整体升为运行时实证。

---

## 五、勘误与待仲裁

### 5.1 勘误（本批自查）[A]

1. **`docs/27` 的 Item21 字段表与 raw 记录字段表曾混用**：raw 记录为 29 B（**无** `+0x1d`），`+0x1d` 的 barIdx 仅存在于 33 B 的 Item21。本批已明确区分。
2. **`bar` 布局**：此前未确认 `+0x00/+0x04`；本批确证它们是**索引**（指向 `obj_c[+0x08]/[+0x0c]` 两条 double 数组），与用于 `raw[+0x09]` 的 `+0x08/+0x0c` 是**不同字段**。
3. **`obj_c[+0x14]` 不是 "K 线数"**：它是 `obj_c[+0x08]/[+0x0c]` 两条 double 数组的**长度**（`obj_c[+0x24]` 才是 bar 数）。

### 5.2 待仲裁 [B]/[C]

- **[B] bar 数组的填充者**：谁写 `obj_c[+0x20]` 与 `obj_c[+0x24]`？`bar[+0x00..+0x0c]` 四个 i32 的确切定义（索引到 `obj_c[+0x08]/[+0x0c]` 的语义）。（`scan_member.py` 当前扫的是 TAFLib，未支持 `--dll`，本批未追。）
- **[B] `0x1000abb0` 类 B 分支（P=32/31）与类 A 的分支不等式方向**：已给出结构，方向性需 frida 或逐条 x87 复核。
- **[C] ZjNum 的 `cnt` 语义**（间隔笔数 or 间隔 bar 数）——需运行时对拍。
- **[C] `arg3`（ZjOrder 透传 ZjNum）与 `arg4`（阈值指针）在 TAFLib 侧实参来源**——需上层调用点。
- **[C] 8 个无调用者槽的命名归属**；`0x10002340` 窗口长度 `[esp+0xc]` 初值 -1 来源。
- **[C] 本批未做动态验证**（frida 预备包待运行）。

---

## 六、可复现命令

```bash
PY=C:/Users/Administrator/Documents/a_conda/python.exe
cd /d/a_ronglide/clone-ronglide

# 1) T1 生产端（obj_c fill，已完整到函数尾）
$PY tools/re-inventory/disasm_func.py 0x1000e1c0 --max 0x600 --dll ronglide-app/chlib.dll \
    -o tools/re-inventory/nchbi/chlib_objc_fill_1000e1c0.txt
$PY tools/re-inventory/x87_sim.py tools/re-inventory/nchbi/chlib_objc_fill_1000e1c0.txt \
    -o tools/re-inventory/nchbi/cond_chlib_1000e1c0.txt          # 14 conditions

# 2) T1 helper 确认器
$PY tools/re-inventory/disasm_func.py 0x1000e450 --max 0x1c0 --dll ronglide-app/chlib.dll
$PY tools/re-inventory/disasm_func.py 0x1000e500 --max 0x1c0 --dll ronglide-app/chlib.dll
$PY tools/re-inventory/disasm_func.py 0x1000e110 --max 0x140 --dll ronglide-app/chlib.dll
$PY tools/re-inventory/disasm_func.py 0x1000e0e0 --max 0x140 --dll ronglide-app/chlib.dll

# 3) T2 配对链
$PY tools/re-inventory/disasm_func.py 0x1000a250 --max 0x260 --dll ronglide-app/chlib.dll \
    -o tools/re-inventory/nchbi/chlib_pair_0x1000a250.txt
$PY tools/re-inventory/disasm_func.py 0x1000a060 --max 0x260 --dll ronglide-app/chlib.dll
$PY tools/re-inventory/disasm_func.py 0x1000a080 --max 0x260 --dll ronglide-app/chlib.dll
$PY tools/re-inventory/disasm_func.py 0x1000abb0 --max 0x300 --dll ronglide-app/chlib.dll \
    -o tools/re-inventory/nchbi/chlib_recheck_0x1000abb0.txt
$PY tools/re-inventory/disasm_func.py 0x1000b100 --max 0x300 --dll ronglide-app/chlib.dll \
    -o tools/re-inventory/nchbi/chlib_recheck_0x1000b100.txt
# 另见：0x1000a290 / 0x1000a2d0 / 0x1000a190 / 0x1000a210 / 0x1000ae50（内联命令见 nchbi4_wip.md）

# 4) T4 frida 预备包（未运行）
#    frida -p <PID> -l tools/re-inventory/nchbi/frida_dump_out.js
```

---

## 七、下一步（第五批）建议

生产端主链已打通（`0x1000e1c0` → `0x1000b100` → `0x1000abb0`），剩余 [B]/[C] 多需**运行时**或**上层调用点**。推荐排序：

1. **首选：NChBiZj3 / NChBiZjNum 补完**（`vt[+0x48]=0x10002fc0`、`vt[+0x5c]=0x100038b0`）
   —— 同族、收敛快；本批已把其依赖的 `0x1000a250`/`0x1000a060`/`0x1000a080` 全部确权，边际成本最低，可顺势结清「ZjNum `cnt` 语义」的静态侧证据。
2. **次选：进入 NChZs 族**（`NCHZS` / `NCHZSG` / `NCHZSBS12`，授权码 EA61–63）
   —— 新的家族、覆盖面更大；`0x1000b000`/`0x1000a250` 等共享基础设施已解，可复用本批方法学。
3. **CHBI 第六批（481 条件）**：由于 CHBI 与 NChBi 共用 chlib 基础设施（`0x1000b000` 等已确权），其单位边际成本本批后下降，可作第三顺位。

> 另：若用户在场，**建议先跑 frida 预备包**（`frida_nchbi3.md` + `frida_dump_out.js`），可一次性把本批的 [B]（`0x1000b100` 分支、`0x1000abb0` 类 B 方向）与 [C]（ZjNum `cnt`）升为 [A]。
