# NChBi 第六批（收官）WIP —— 边做边落盘

> 批次：NChBi 第六批（收官），2026-10-17
> 主文档：`docs/30-NChBi-第六批-收官.md`
> 任务：T1 FxNum / T2 Speed / T3 Rec20 段连续性不变式（★最高价值）/ T4 "3" 含义 / T5 cnt 增量条件

---

## WIP-A — T1 NChBiFxNum（`0x10003680`, EA62）

- 签名：`ret 0x10` ⇒ 4 参（末位 P/context）；帧内 6 个局部槽自洽（**注意 `push ebp` @0x100036d9 必须读，否则 `[esp+0x24]` 误算为返回地址槽**）。
- 容器：只吃 obj10（Item21，stride 0x21，`[+0x30]` base / `[+0x3c]` count）；不吃 obj8/Rec20。
- x87：`cond_chlib_10003680.txt` = **0 条条件**（纯整数链）。
- 语义 [A]：`out[barIdx(k)] = ord(k) − ord(k−1) + 1`
  - `ord = Item21[+0x05]`（分型中心 bar 序号）；`barIdx = Item21[+0x1d]`。
  - 首个 Item21 无前项 ⇒ 跳过。
- 与 ZjNum 对照表（单位分歧）：
  | 维度 | ZjNum | FxNum |
  |---|---|---|
  | 门 | bit0 写 + bit2 计数 | bit0 写（无 bit2） |
  | 字段 | value(+0x00), barIdx(+0x1d) | ord(+0x05), barIdx(+0x1d) |
  | 运算 | 运行计数器 +1 | 一项 − 前一项 +1 |
  | **单位** | **Zj 项数** | **bar 距离（K 线根数）** |
  | 首项 | 处理 | 跳过 |
- ⇒ docs/27 §6.2「间隔笔数 vs bar 数」之争在本族内两指标并存：ZjNum↔项数、FxNum↔bar 数。

---

## WIP-B — T2 NChBiSpeed（`0x10003a90`, EA62）

- 签名：`ret 0x10`；单步 0x21（非展开）。
- 六道门：obj10 非空 / obj8 非空 / 授权 EA62 / `A==0` 跳过 / `SPAN==0` 跳过 / `obj8[+0x28]!=0`。
- x87：`cond_chlib_10003a90.txt` = **1 条条件**（`A == 0.0`）。
- ★ 公式（`x87_expr.py` 符号求解，初始栈 `[1000.0, 0.0]`）：
  ```
  out[barIdx(k)] = |(A - B) * 1000.0 / A| / SPAN  ==  1000.0 * |A - B| / (A * SPAN)
  ```
  每轮结束后栈精确回到 `[1000.0, 0.0]`；出口两条 `fstp st(0)` 恰清这两个哨兵。
- 语义：每 bar 相对涨跌幅度（‰）= 缠论"速度/斜率"。
- 常量：`0x10015558 = 1000.0`（邻位 `0x10015550=5.0`、`0x10015560=0.25`）。
- ★ 工具勘误（影响后续所有 x87 链）：
  1. D8/DC + 单寄存器 ⇒ `ST(0)=ST(0) op ST(i)`，**不弹栈**（`D8 C0 = fadd st,st` 原地加倍为反例）。
  2. DE「P」形态才弹栈，`FDIVRP ST(i),ST(0)` = `ST(i)=ST(0)/ST(i)`。
- obj8 补映射 [A]：`+0x08/+0x0c` 价数组 A/B、`+0x14` len、`+0x18` flag、`+0x1c/+0x28` Rec20 base/cnt。

---

## WIP-C — T3 Rec20 生产者与段连续性不变式（★ 最高价值）

- 定位生产者：obj8 ctor `0x100094b0`（vt=`0x100153ec`）；vt `+0x04=0x10009500`(clear)、**`+0x08=0x10009530`(rec20 生产者)**、`+0x0c=0x1000e0b0`(通用 setter)。
- Rec20 布局（`rep movsd ecx=8` 确证，stride 0x20）：
  `+0x00 startBar / +0x04 endBar / +0x08 idxA / +0x0c idxB / +0x10 p1(f64) / +0x18 p2(f64)`。
- 生产者主循环关键写点：
  - `0x100095fe  mov [esp+0x24], edx` —— **EXTEND：每次非 emit 迭代置 `endBar=i`**。
  - `0x100096d0  mov [esp+0x24], edx` —— EMIT 后新段 `endBar=i`。
  - `0x100096d8  mov [esp+0x20], edx` —— **EMIT 后新段 `startBar=i`**。
  - `0x100096c5  rep movsd (ecx=8)` —— 刷出 8 dword（0x20 B）。
- ★ 不变式 [A]：**`Rec20[k].endBar + 1 == Rec20[k+1].startBar` 恒成立（k<cnt−1）**
  ⇒ 段记录构成对 `[0,len−1]` 的连续划分。
- 推论：Zj3 的 `out[Rec20[recIdx].endBar+1]` 与 ZjOrder 的 `out[Rec20[recIdx+1].startBar]` **同槽** ⇒ 二者差异仅为过滤门。

---

## WIP-D — T4 "3" 含义 + T5 cnt 条件

- T4：`CalcProc_NChBiZj`(0x10012d20) 与 `CalcProc_NChBiZj3`(0x10012d90) **逐字节同构**，仅授权码(EA61→EA62)/槽(+0x44→+0x48)不同，皆 `ret 0xc`。
  ⇒ "3" = 导出名枚举序号，非参数 [A]。
- T5：ZjNum 递增条件 `bit2 ∧ ¬bit0 ∧ value≠lastValue` 的 `≠lastValue` = **滤除同向重复项**（被配对器拒的项仍留在 Item21 中）≈ "反向判据" [B]。
- 运行时验证并入 frida 预备包：挂 `0x100038b0` 出口 dump `obj10[+0x30]` 的 value/flags 序列。

---

## 新增工具 / 证据

- `x87_expr.py`（新工具）：符号化 x87 栈模拟器，把 fld/fmul/fdivrp/... 链还原成公式。
- `speed_x87_trace.txt`：Speed 计算路径符号轨迹（9 行）。
- `obj8_push_10009500.txt`（19 行 clear）/ `obj8_m2_10009530.txt`（195 行 ★ 生产者）。
- `cond_chlib_10003680.txt`（0 条件）/ `cond_chlib_10003a90.txt`（1 条件）。
