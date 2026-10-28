# ChZhongShu 族第二批 —— 核心算法与步进输出

> 批次：ChZhongShu 族第二批（2026-10-28）
> 目标：补全 `ChZhongShu` / `ChZhongShuG` / `ChZhongShuD` 三支核心 worker 的数据流。
> 证据：`tools/re-inventory/chzhongshu/chlib_worker_*.txt`、原始 `TAFLib.dll`、共享容器/迭代器分析。
> 置信度：[A] 原始指令与既有容器证据；[B] 多处调用关系一致；[C] 仍需运行时对拍。

---

## 〇、结论

1. `0x1002cd00` 与 `0x1002cee0` 是同一份 157 指令模板：分别读取每条记录的 `+0x50` 与 `+0x54` 单精度字段。它们不是“寻找全局最大/最小值”，而是按记录顺序生成**阶梯序列**。[A]
2. G/D 只接受 `record[+0x28] ∈ {1,2,3,4}` 的记录；该记录价格大于零时更新当前持有价，否则沿用前值。价格小于、等于零或 unordered 均不会更新。[A]
3. 每个记录的序号来自 `record[+0x00]`，输出下标使用 `serial - 1`。两个记录序号间的空档填充上一次持有的价格；输出数组在扫描前按 `count * 8` 字节清零。[A]
4. 主 worker `0x1002ca30` 同样复制容器快照并逐条写出，但取 `record[+0x28]` 作为输出值；它另调用 `0x10061920`，用输入序列首个 double 经 `_ftol` 转换的整数与状态对象首字段初始化/对齐。该 helper 的深层语义尚未完全展开。[A/C]
5. `0x1003f150` 在本链仍是 `W->m[0]` 的按值快照（深拷贝），不是业务算法。真实执行的条件仍是 EA61 授权通过；本批没有使用付费功能界面验证，运行时逐点对拍留待后续。

---

## 一、三支核心 worker 的参数与容器

### 1.1 `ChZhongShuG/D` 参数

由包装器的寄存器与压栈顺序还原：

| 入口 | ECX | EDX | 栈参数（从 `[esp+4]` 起） | 含义 |
|---|---|---|---|---|
| `0x1002cd00` | `count` | 新分配的 worker 对象 | `state = this[+0xb0]`, `out` | 输出中枢高点阶梯 |
| `0x1002cee0` | `count` | 新分配的 worker 对象 | `state = this[+0xb0]`, `out` | 输出中枢低点阶梯 |

worker 通过 `state` 取得 `W->m[0]`，调用 `0x1003f150` 复制出迭代快照；按既有布局，每条记录步长 `0xA0`。

### 1.2 记录字段

| 偏移 | 本批观察到的用途 | 证据 |
|---|---|---|
| `+0x00` | 1 基记录序号；写输出时减 1 | 两个 worker 均执行 `mov edi,[record] / sub edi,1` |
| `+0x28` | 记录类别/状态码；只处理 1、2、3、4 | 两个 worker 有四路 `cmp [record+0x28], imm` |
| `+0x50` | G 序列采样的 float 字段 | `0x1002cd00: fld dword [record+0x50]` |
| `+0x54` | D 序列采样的 float 字段 | `0x1002cee0: fld dword [record+0x54]` |

`+0x50/+0x54` 与旧文档所称“高/低”相符，但字段的业务命名仍以动态样本对照为最终证据。[B/C]

---

## 二、G/D 阶梯序列伪码

```text
function ChZhongShuG_or_D(count, state, out, fieldOffset):
    if state == null: return -1
    if count > 0: memset(out, 0, count * 8)

    records = deep_copy(state.W.m0)   // 0x1003f150 -> 0x1006a4e0
    cursor = 0
    held = 0.0

    for record in records:            // stride 0xA0
        i = record.serial - 1          // serial at +0x00
        price = float32(record[fieldOffset]) converted to double

        if i > cursor:
            repeat out[cursor .. i-1] = held
            cursor = i

        if record.kind in {1, 2, 3, 4} and price > 0.0:
            held = price

        out[cursor] = held
        cursor += 1

    free(records)
    return 0
```

### 2.1 比较方向核实

G 路径 `0x1002ce68–0x1002ce8c` 与 D 路径 `0x1002d048–0x1002d06c` 相同：先压入 0，再压入当前 double，`fcom st(1)` 比较当前值与 0；`test ah,0x41` 命中小于/相等/unordered。只有比较结果为**严格大于 0**时才更新 `held`。

这纠正了第一批文档中“若 ST0 > ST1 则跳转”的简化表述：`jne` 实际在小于、相等或 unordered 时跳转；跳转路径丢弃候选值，保留旧值。

### 2.2 空档填充

当 `serial - 1 > cursor`，worker 将 `held` 写到当前输出位置，再用重叠的 `rep movsd` 向后扩展该 8 字节值，直到新序号前一格。随后当前记录占据 `out[serial - 1]`。这产生每个记录序号区间保持常值的阶梯输出。

---

## 三、主序列 `ChZhongShu`

`0x1002ca30` 的职责与 G/D 不同：

1. `count > 0` 且 worker 对象非空时，先将 `out[0:count]` 清零。
2. 从 `inputHolder` 取输入序列首个 double，调用 `_ftol` 得到整数；并把该整数与 `state` 首字段传给 `0x10061920`。该 helper 长达 4292 条指令、还会调用迭代器/容器辅助函数；此处只确认实参来源，尚不把它概括成简单的“首 bar 初始化”。
3. 检查 worker 对象 vtable 的授权回调，授权码为 `0xEA61`；失败则返回 `-1`。
4. 对 `state->W->m[0]` 取快照并遍历记录。输出位置由 `record[+0x00] - 1` 决定，输出值取 `record[+0x28]`，中间缺口清零，写入值经整数转 double。
5. 释放快照并返回 0。包装器最终返回成功标志；底层 worker 的错误返回值没有被包装器显式检查。

主序列的简化伪码：

```text
function ChZhongShu(count, state, inputHolder, out, worker):
    if count <= 0 or worker == null: return -1
    memset(out, 0, count * 8)
    first = trunc_toward_zero(**inputHolder)
    helper_10061920(state.firstField, first)  // 内部算法待解
    if !worker.Authorize(0xEA61): return -1

    records = deep_copy(state.W.m0)
    for record in records:
        i = record.serial - 1
        out[i] = double(record.kind)           // +0x28
    free(records)
    return 0
```

上段对 `0x10061920` 的副作用、首尾越界保护与类别写入的输入范围保留待核项；正式复刻前需做原生数组对拍。[C]

---

## 四、G/D 二进制同构与异常路径

归一化后，`0x1002cd00` 与 `0x1002cee0` 的控制流、栈布局、授权、复制、填充循环、释放路径完全同构；差异仅为 float 读取偏移 `+0x50` / `+0x54`。[A]

- `state == null`：返回 `-1`。
- 授权失败：释放已创建的临时对象后返回 `-1`；输出此前已清零。
- 正常扫描结束：释放快照并返回 `0`。
- `count <= 0`：不执行清零；主序列的早退条件也在初始化与遍历前。

---

## 五、注入与动态验收计划

项目已有 `inject_authorize_bypass.py`、`inject_func_perm_bypass.py`、`inject_cmd_perm_bypass.py`。下一次对真实 GUI 公式做动态对拍时，先只启用完成该菜单/公式所需的 hook，记录目标 worker 的进入次数、`count`、输出缓冲前后内容与 EA61 调用码；不要把观察回调挂在正在执行核心算法的线程上（沿用零插桩对拍经验）。本批未启动 `MainApp.exe`，也未运行这些临时绕过脚本，因此没有动态命中数据。

REA 复核：`rea info TAFLib.dll` 确认 x86 PE 与已登记 SHA-256 `d277f1b647e4a5c1c570b0bd69eb0f3955737b65e35332a62d0da4f80ef9b588` 一致。由于本机版本对 32 位 PE 的 VA 解析已知有误，本批未用其 xrefs/decompile 输出作为函数语义证据。

---

## 六、待办

1. 在 EA61 受控授权的原生调用环境内，为 `ChZhongShuG/D` 提供小型 `m0` 记录序列，逐点核对类别 1–4、非正价格、序号空档与尾部零值。
2. 展开 `0x10061920` 的实际作用，确认它是否改写 `state->W`、输出首格或其它上下文。
3. 对照实际公式 `BIZHONGSHU / BIZHONGSHUG / BIZHONGSHUD` 的 TAF 源表达式，验证数组是中枢类别、高点、低点序列还是被后续公式变换。
4. 按 `docs/14-付费功能与指标总览.md` 的剩余保护函数优先级启动下一族；本轮只完成 ChZhongShu 族第二批，85 个保护函数的全量剩余仍需逐批推进。
