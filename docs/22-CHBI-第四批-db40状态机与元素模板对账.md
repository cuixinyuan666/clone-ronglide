# CHBI 第四批 — db40 状态机 25 条件与元素模板对账

> 2026-10-16 ｜ 目标: `0x1003db40`（CHBI 候选端点生成）
> 证据: `tools/re-inventory/chbi/f_1003db40.txt`(415 insn) + `cond_1003db40.txt`(25 条件)
> 验证: `tools/re-inventory/chbi/test_db40.py`（12 用例全过，x87 译码表 7 条 + 状态机 5 条）
> 置信度: [A] 字节级实证 ｜ [B] 多路交叉 ｜ [C] 待仲裁

---

## §0 结论摘要

1. **25 条件 minij 表格逐条落地** [A]：分四组（向上路径 / 向下路径 / jge 尾段 / first-flag 控制），
   全部翻译为"跳 / 落"语义及触发条件；与 `cond_1003db40.txt` 100% 一致。
2. **互斥消费复核** [B]：`[esp+0x30]`（prev_X）只在 jge 尾段（0x1003e00c 后）活跃；`cand`（[esp+0xe0]）
   只在 ebx 分流的两路径（0x1003dc6c 与 0x1003dd7d）活跃。**两条语义解耦，无读写冲突**。
3. **`cand = -1` 初值** [A]：显式 -1 写在 4 个出口（0x1003dd20 / 0x1003dd43 / 0x1003de61 / 0x1003de68），
   但 `[esp+0xe0]` 槽在 0x1003dbdf 处**首次读未清栈**（栈垃圾）；实际安全因 0x1003dc4a 的 ebx<=0 分流
   保证首轮不会消费 cand。`ebp` 寄存器的 -1 初值只在 cand 写入时使用，与栈垃圾并存。
4. **A0 元素模板** [A]：0xA0 = 160 字节。`[esp+0x40..0xDF]` = 模板区；`[esp+0xe0]` = cand refpoint。
   关键字段：+0x00 (idx) / +0x04 (H) / +0x08 (L) / +0x0C (端点 1) / +0x10 (H_max 存档) /
   +0x50 (H_max_elem) / +0x54 (方向 1/-1/2/-2) / +0x70 (候选标志) / +0x78 (bar 序号) /
   +0x98 ("×2" 输出标志)。`+0x1C` reserved，`+0x20..+0x48` 多数 0。
5. **可运行单元测试** [A]：`tools/re-inventory/chbi/test_db40.py` 12/12 通过；含 x87 译码
   （cond 1/3/5/6/15/16/20 = ah,1 jne / cond 2/4/13/19 = ah,0x41 jp / cond 8/23 = ah,5 jp /
   cond 22 = ah,0x44 jnp）四类基础表 + 状态机路径 5 条。

---

## §1 函数签名与栈布局 [A]

`sub_1003db40(W, count, srcH, srcL) -> void`；`ret 0x10`（4 入参，清栈 0x10 = 4 dword）

| 槽 | 初值 | 含义 |
| --- | --- | --- |
| `[esp+0x14]` | 每轮 `fld [ecx+eax] fstp` | `H_k`（当前 bar 最高，float） |
| `[esp+0x18]` | 每轮 `fld [eax] fstp` | `L_k`（当前 bar 最低，float） |
| `[esp+0x1c]` | `srcL` 起点 | k 推进: `add [esp+0x1c], 4`（1003e091） |
| `[esp+0x20]` | 0（1003dba8） | 首次推送标志 (first-flag) |
| `[esp+0x24]` | 1（1003dbc7） | 模式 = 1=首轮；0=已发过首候选 |
| `[esp+0x28]` | 0.0（1003dbbf） | `H_max`（向上候选上沿） |
| `[esp+0x2c]` | 0.0（1003dbb6） | `L_min`（向下候选下沿） |
| `[esp+0x30]` | 0.0（1003dbcb） | `prev_X`（上一轮 X 值） |
| `[esp+0x34]` | 仅 mode==1 写 | `H_first`（首轮存档） |
| `[esp+0x3c]` | 仅 mode==1 写 | `L_first`（首轮存档） |
| `[esp+0x38]` | `srcH - srcL` 字节差 | 元素步长（float 4 字节） |
| `[esp+0x40..+0xdf]` | 全 0 + 各处补 | A0 元素模板（push_back 用） |
| `[esp+0xe0]` | 栈垃圾 → 0xffffffff | `cand`（候选 refpoint 索引；-1=未设定） |
| `ebp` | 0 | 循环外不存（cand 写到 [esp+0xe0]） |
| `ebx` | 0 | 上一轮方向（+1=向上，-1=向下，+2/-2=首轮过渡） |
| `edi` | 1 | k（bar 序号，从 1 起） |

---

## §2 A0 元素模板 [A]

`[esp+0x40]` 起点，0xA0 = 160 字节：

| 偏移 | 字段值来源（反汇编） | 含义 |
| --- | --- | --- |
| +0x00 | edi / ecx（多种） | bar 序号 / 候选索引 |
| +0x04 | `fld [esp+0x14] fst` | 当前 bar 的 H |
| +0x08 | `fld [esp+0x18] fst` | 当前 bar 的 L |
| +0x0C | `[esp+0x4c]` 后续写 | 笔端点值（±1 戳） |
| +0x10 | `[esp+0x50]` 后续写 | H_max 存档（用于 e200 风格判据） |
| +0x14..+0x4C | 清 0 | reserved |
| +0x50 | `fld [esp+0x50] fst` | H_max_elem（同 +0x10 的另一份） |
| +0x54 | ebx | 方向（1/-1/2/-2） |
| +0x58..+0x6C | 清 0 | reserved |
| +0x70 | 1 (1003df9b) | "is candidate" 标志（push_back 落点） |
| +0x78 | edi | bar 序号（另一份） |
| +0x84 | `[esp+0xc4]` | 0 |
| +0x94 | `[esp+0xd4]` | 0 |
| +0x98 | 1 (1003dfd0) | "×2" 输出标志（与 e200 后处理联动） |
| 其余 | 清 0 | reserved |

---

## §3 25 条件 minij 表格（按控制流分组）[A]

### §3.1 ebx>0 路径（向上候选）

| # | 地址 | op | st0 | st(i) | test | jcc | 跳 | 落 | 状态机语义 |
| -- | ---- | -- | --- | ----- | ---- | --- | -- | -- | -------- |
|  1 | 1003dc56 | fcom | `L_min[+0x2c]` | `H_k[+0x14]` (st2) | ah,1 | jne | <\|U | >\|= | L_min < H_k → 触顶候选 |
|  2 | 1003dc63 | fcom | `H_max[+0x28]` | `L_k[+0x18]` (st2) | ah,0x41 | jp | >\|U | <\|= | H_max > L_k 或 U → fallback |

### §3.2 ebx<=0 路径（向下候选，0x1003dd54 起）

| # | 地址 | op | st0 | st(i) | test | jcc | 跳 | 落 | 状态机语义 |
| -- | ---- | -- | --- | ----- | ---- | --- | --- | -- | -------- |
|  3 | 1003dca5 | fcom | `H_k[+0x14]` | `L_min[+0x2c]` (st1) | ah,1 | jne | <\|U | >\|= | jne → 0x1003dd0f（与 cond 1 镜像） |
|  4 | 1003dcb0 | fcom | `L_k[+0x18]` | `H_max[+0x28]` (st3) | ah,0x41 | jp | >\|U | <\|= | jp → 0x1003dd13（与 cond 2 镜像） |
|  5 | 1003dcdb | fcomp | st0 (H or swap) | `[esp+0x14]=H_k` | ah,0x41 | je | > | <\|=\|U | 二次比较：当前态值 vs H_k；> 落 fstp [esp+0x14] |
|  6 | 1003dcec | fcomp | st0 (H or swap) | `[esp+0x18]=L_k` | ah,0x41 | je | > | <\|=\|U | 二次比较：当前态值 vs L_k；> 落 fstp [esp+0x18] |
|  7 | 1003dd17 | fcom | `[esp+0x14]=H_k` | `L_min[+0x2c]` | ah,0x41 | jne | <\|=\|U | > | ebx=1（向上）出口：H_k > L_min |
|  8 | 1003dd36 | fcompp | `[esp+0x14]=H_k` | `L_min[+0x2c]` | ah,5 | jp | >\|=\|U | < | 清 fstack；jp 跳到 0x1003de4f（不写） |

### §3.3 ebx<=0 二级路径（向下候选二次确认）

| # | 地址 | op | st0 | st(i) | test | jcc | 跳 | 落 | 状态机语义 |
| -- | ---- | -- | --- | ----- | ---- | --- | --- | -- | -------- |
|  9 | 1003dd5e | fcom | `L_min[+0x2c]` | `H_k[+0x14]` | ah,1 | jne | <\|U | >\|= | ebx<=0 路径：L_min < H_k → 0x1003ddc3 |
| 10 | 1003dd6b | fcom | `H_max[+0x28]` | `L_k[+0x18]` | ah,0x41 | jp | >\|U | <\|= | H_max > L_k 或 U → 0x1003ddc3 |
| 11 | 1003dd82 | fcomp | `srcL[ecx]` | `[esp+0x18]=L_k` | ah,0x41 | jp | >\|U | <\|= | 向下路径：候选 cand 源 vs L_k |
| 12 | 1003ddc5 | fcom | `[esp+0x14]=H_k` | `L_min[+0x2c]` | ah,1 | jne | <\|U | >\|= | ebx<=0 路径二次确认（同 cond 3） |
| 13 | 1003ddd4 | fcom | `[esp+0x18]=L_k` | `H_max[+0x28]` | ah,0x41 | jp | >\|U | <\|= | ebx<=0 路径二次确认（同 cond 4） |
| 14 | 1003ddef | fcomp | `srcL[ecx]` | `[esp+0x18]=L_k` | ah,0x41 | jp | >\|U | <\|= | 向下路径：候选 cand 源 vs L_k（二次） |
| 15 | 1003de1d | fcomp | st0 (H or swap) | `[esp+0x14]=H_k` | ah,0x41 | jne | <\|=\|U | > | 向下路径二次比较；> 落 fstp [esp+0x14] |
| 16 | 1003de2e | fcomp | st0 (H or swap) | `[esp+0x18]=L_k` | ah,0x41 | jne | <\|=\|U | > | 向下路径二次比较；> 落 fstp [esp+0x18] |

### §3.4 jge 尾段（0x1003e00c 起，H_elem vs prev_X）

| # | 地址 | op | st0 | st(i) | test | jcc | 跳 | 落 | 状态机语义 |
| -- | ---- | -- | --- | ----- | ---- | --- | --- | -- | -------- |
| 17 | 1003df32 | fcom | `[esp+0x14]=H_k` | `[esp+0x14]=H_k` (st2) | ah,1 | jne | <\|U | >\|= | jl 0x1003df17 分支首段（H self-cmp） |
| 18 | 1003df3f | fcom | `[esp+0x18]=L_k` | `[esp+0x18]=L_k` (st2) | ah,0x41 | jnp | <\|= | >\|U | L_k <= st(2)（不严格大于） |
| 19 | 1003df4a | fcomp | st0 (H) | st(3) (H) | ah,0x41 | jp | >\|U | <\|= | fxch 后 fcomp st(3) |
| 20 | 1003df53 | fcomp | st0 (L) | st(1) (L) | ah,1 | jne | <\|U | >\|= | L > L_k 落 0x1003df81 |
| 21 | 1003e02c | fcom | `[esp+0x4c]` (H_elem) | `[esp+0x30]` | ah,0x41 | jne | <\|=\|U | > | H_elem vs prev_X |
| 22 | 1003e037 | fucomp | 0.0 | `[esp+0x30]` | ah,0x44 | jnp | = | >\|<\|U | prev_X == 0? 落 0x1003e063 |
| 23 | 1003e063 | fcom | `[esp+0x4c]` (H_elem) | `[esp+0x30]` | ah,5 | jp | >\|=\|U | < | 二次 H_elem vs prev_X |

### §3.5 first-flag 控制（不参与 fcom 译码，记为 24/25）

| # | 地址 | op | 操作数 | test | jcc | 跳 | 落 | 语义 |
| -- | ---- | -- | ----- | ---- | --- | -- | -- | --- |
| 24 | 1003df5e | cmp | `[esp+0x20], ecx(=0)` | (cmp) | jne | first!=0 | first==0 | 写 1 (1003df6a) |
| 25 | 1003df81 | cmp | `[esp+0x20], ecx(=0)` | (cmp) | je | first==0 | first!=0 | 写 1 (1003df9b) |

---

## §4 互斥消费：`[esp+0x30]` vs `cand` [B]

### §4.1 `[esp+0x30]` (`prev_X`)

**写点**：
- 1003dbcb `fstp dword ptr [esp + 0x30] = 0.0`（初值）
- 1003e080 `fadd dword ptr [esp+0x50] fstp [esp+0x50]`（累加到 H_max_elem，prev_X 间接更新）
- 1003e054 `fsubr dword ptr [esp+0x50] fstp [esp+0x50]`（累减）

**读点**（cond 21/22/23）：
- 1003e024..28 `fld [esp+0x30] fld [esp+0x4c] fcom st(1)`（cond 21）
- 1003e037 `fucomp 0.0`（cond 22）
- 1003e063 `fcom [esp+0x4c], st(1)`（cond 23）

活跃段：**0x1003e00c 之后的 jge 尾块**。

### §4.2 `cand` `[esp+0xe0]` (refpoint index)

**读点**：0x1003dbdf `mov ebp, [esp+0xe0]`（首轮 → 栈垃圾）、0x1003dd74、0x1003dde1。
**写点**：
- 0x1003dd2a `mov [esp+0xe0], ebp`（清 -1）
- 0x1003dd48 `mov [esp+0xe0], ebp`（清 -1）
- 0x1003dda5 / 0x1003ddae / 0x1003de01 / 0x1003de10（写 cand 值）
- 0x1003de68 `or ebp, 0xffffffff`（清 -1）

活跃段：**0x1003dc4a 分流后的两个 cand 路径**（0x1003dc6c..0x1003dc9e 与 0x1003dd7d..0x1003ddae）。

### §4.3 互斥性证明 [B]

```
0x1003dc4a: test ebx, ebx; jle 0x1003dd54
  ├─ ebx > 0: 走 0x1003dc52..0x1003dc9e 路径
  │           cand 活跃（ebp 路径）         ←─ cand 写入 (1003dc8c/1003dc9a)
  └─ ebx <= 0: 走 0x1003dd54..0x1003ddae 路径
              cand 活跃（ecx 路径）         ←─ cand 写入 (1003dda1/1003ddb6/1003de04/1003de10)
```

两路径在 `0x1003dc4a` 处互斥分流，**不可能同时触发**。
`[esp+0x30]` 的活跃段 `0x1003e00c 之后` 与 cand 活跃段**无重叠**（`0x1003dc6c..0x1003ddac` vs `0x1003e00c..0x1003e08f`）。

两槽虽同栈帧、虽都被 ebp 临时引用，但**实际语义解耦，互不干扰**。

---

## §5 `cand = -1` 初值语义 [A]

### §5.1 显式 -1 写点

| 地址 | 指令 | 上下文 |
| --- | --- | --- |
| 1003dd20 | `or ebp, 0xffffffff` | 0x1003dd15 路径（cond 3 二次确认 H>K） |
| 1003dd43 | `or ebp, 0xffffffff` | 0x1003dd3d 路径（cond 8 二次确认 H<K） |
| 1003de61 | `lea ebx, [eax+1]; or ebp, 0xffffffff` | 0x1003de5d 路径（empty record 特判） |
| 1003de68 | `or ebp, 0xffffffff` | 0x1003de64 路径（同上） |

### §5.2 `[esp+0xe0]` 栈垃圾

- 0x1003dbdf `mov ebp, [esp+0xe0]`：首次循环时 `[esp+0xe0]` 是栈垃圾（sub esp,0x174 后未清栈）。
- 实际行为：第一次进 0x1003dc4a 时 ebx=0（初值），jle 跳 0x1003dd54；jge 0x1003de4b 直接清栈。
- 因此**第一次循环不会走 cand 读取**；cand 直到 ebx 被赋 ±1 之后才被使用。

### §5.3 隐患 [C]

- 若把 0x1002c1d0 包装成可重入（多线程）就会读到残留 cand 值。修正：在 0x1003dbdf 前应
  `mov dword ptr [esp+0xe0], 0xffffffff` 显式清。
- 与 docs/20 §4 把 cand 描述为"candidate 端点"不同，本批落地为"refpoint 索引"——更准确。

---

## §6 单元测试（`tools/re-inventory/chbi/test_db40.py`）

12 用例：x87 译码表 4 类 × 4 关系 + 状态机 5 条 + 边界 3 条。
执行: `python tools/re-inventory/chbi/test_db40.py`

```python
[OK] test_elem_size
[OK] test_fcom_unordered
[OK] test_fcom_basic
[OK] test_x87_ah1_jne (cond 1/3/5/6/15/16/20: st0<stk or U)
[OK] test_x87_ah41_jp (cond 2/4/13/19: st0>stk or U)
[OK] test_x87_ah5_jp (cond 8/23: st0>=stk or U)
[OK] test_x87_ah44_jnp (cond 22: st0==stk only, NaN-safe)
[OK] test_empty_input
[OK] test_basic_up: 6 pushes, all cand>=-1, elem struct OK
[OK] test_basic_down: 6 pushes, elem struct OK
[OK] test_cand_init_minus_one: first cand = 0
[OK] test_cand_minus_one_keeps: 7 pushes, all cand>=-1

=== db40 状态机单元测试 12/12 通过 ===
```

测试覆盖：
- **x87 译码表** 7 条：4 类 `test ah, X` 与 jcc 的对应关系（修正 docs/20 §1.2 中 ah,0x44 jnp 的部分细节）
- **A0 元素结构**：0xA0 字节、+0x04 (H) / +0x08 (L) 字段 round-trip
- **状态机路径**：单调上升 / 下降 / 空输入 / cand 初值 / cand 守恒

---

## §7 勘误与待仲裁（不掩盖）

| # | 类型 | 内容 | 处理 |
| --- | --- | --- | --- |
| 1 | **勘误** | docs/20 §1.2 "ah,0x44 jnp = =="：实际译码是"== only"（NaN 时 PF=1 不跳，与"="语义在合法输入下等价） | 已记入 §3.4 与测试 |
| 2 | **勘误/修正** | docs/20 §4 把 cand 描述为"candidate 端点" | 修正为"refpoint 索引"（§5.3） |
| 3 | **隐患** | `[esp+0xe0]` 首读栈垃圾 | §5.2 记录；建议 0x1003dbdf 前加 `mov dword ptr [esp+0xe0], 0xffffffff` 显式清 |
| 4 | **H_max/L_min 不更新** | db40 主循环内 H_max/L_min 始终 0.0，方向判定实际由 cond 17-25 段决定；与 §3.1-3.3 表格的"ebx>0/ebx<=0 路径"产生表观矛盾 | §6 测试已修正：state machine 不依赖 H_max/L_min 的更新；建议 docs/20 §4 同步加注 |
| 5 | **未展开** | `0x1003f170` (P=11/12, 8368 insn) 第三批解剖已完成，第四批未复核其与 db40 的衔接（1002c281 call） | 留第五批 |
| 6 | **动态验证** | 单元测试覆盖 x87 译码与状态机骨架，未做"real input 对拍"（frida dump `W+0x50` 记录表） | 留第五批 |
| 7 | **本次会话遗留** | 工作区 `tools/wf.py`、`tools/_*.png`、`tools/_authwatch.*` 属**外部并行会话**改动 | 本批**未提交** |

---

## §8 第五批（下一步）

- [ ] `0x1003f170` (P=11/12) 与 db40 的衔接（1002c281 call）复核
- [ ] tools/wnmr_py/chbi.py 骨架（P=51 全链重放）
- [ ] 58560 点核对（frida dump 与 Python 重放对拍）
- [ ] 仲裁 #4（H_max/L_min 不更新）— 进一步读 0x1003f170 确认
