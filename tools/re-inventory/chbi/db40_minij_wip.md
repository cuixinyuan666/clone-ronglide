# db40 状态机 minij 表格（WIP — 边做边落）

> 来源: `tools/re-inventory/chbi/f_1003db40.txt`（415 insn, ret 0x10, 单 ret）
> 25 条件已逐条落入下表；所有跳转目标与 cond_1003db40.txt 一致
> 置信度: [A] 字节级实证 ｜ [B] 多路交叉 ｜ [C] 待仲裁

---

## §0 函数签名与栈布局 [A]

`sub_1003db40(W, count, srcH, srcL) -> void`；`ret 0x10`（4 入参）

| 槽 | 初值 | 含义 |
| --- | --- | --- |
| `[esp+0x14]` | 每轮 `fld [ecx+eax] fstp` | `H_k`（当前 bar 最高，浮点） |
| `[esp+0x18]` | 每轮 `fld [eax] fstp` | `L_k`（当前 bar 最低，浮点） |
| `[esp+0x1c]` | `srcL` 起点 | k 推进: `add [esp+0x1c], 4`（1003e091） |
| `[esp+0x20]` | 0（1003dba8） | 首次推送标志 (first-flag)：0=已推过候选；1=尚未推（1003df6a/1003df9b 写 1；1003df90 清 0） |
| `[esp+0x24]` | 1（1003dbc7） | 模式 = 1=首轮；0=已发过首候选（1003dc38 写 0；1003dfd0 重置 1） |
| `[esp+0x28]` | 0.0（1003dbbf） | `H_max`（向上候选上沿） |
| `[esp+0x2c]` | 0.0（1003dbb6） | `L_min`（向下候选下沿） |
| `[esp+0x30]` | 0.0（1003dbcb） | `prev_X`（上一轮 X 值，与 e200 收尾共用） |
| `[esp+0x34]` | 仅 mode==1 写 | `H_k`（首轮存档） |
| `[esp+0x3c]` | 仅 mode==1 写 | `L_k`（首轮存档） |
| `[esp+0x38]` | `srcH - srcL` 字节差 | 元素步长（float 4 字节） |
| `[esp+0x40..+0xdf]` | 全 0 + 各处补 | A0 元素模板（push_back 用） |
| `[esp+0xe0]` | 栈垃圾 → 0xffffffff | `cand`（候选 refpoint 索引；-1=未设定） |
| `ebp` | 0 | 循环外不存（cand 写到 [esp+0xe0]） |
| `ebx` | 0 | 上一轮方向（+1=向上，-1=向下，+2/-2=首轮过渡） |
| `edi` | 1 | k（bar 序号，从 1 起） |

A0 元素模板字段（[esp+0x40] 起点）：

| 偏移 | 来源 | 含义 |
| --- | --- | --- |
| +0x00 | edi/ecx | bar 序号 / 候选索引 |
| +0x04 | `fld [esp+0x14] fst` | `H` |
| +0x08 | `fld [esp+0x18] fst` | `L` |
| +0x0C | `fld [esp+0x4c]` 后写 | 笔端点值（±1 戳） |
| +0x10 | 同 +0x50 | 端点值 2 |
| +0x14..+0x4C | 清 0 | reserved |
| +0x50 | `fld [esp+0x50] fst` | H_max（用于 e200 判据） |
| +0x54 | ebx | 方向（1/-1/2/-2） |
| +0x58..+0x6C | 清 0 | reserved |
| +0x70 | 1 (1003df9b) | "is candidate" 标志 |
| +0x78 | edi | bar 序号 |
| +0x84 | `[esp+0xc4]` | 0 |
| +0x94 | `[esp+0xd4]` | 0 |
| +0x98 | 1 (1003dfd0) | "×2" 输出标志（与 e200 后处理联动） |
| 其余 | 清 0 | reserved |

---

## §1 状态机骨架 [A]

```
for k = 1 .. count-1:                   ; 1003dc00..1003e0a3
  load H_k, L_k from srcH/L[k-1]        ; 1003dc1b..1003dc28 (sub ecx,edx stride = 4)
  fstack: st0=L_k, st1=H_k              ; 1003dc2c/30
  if mode==1:
      swap → [esp+0x34]=H_k, [esp+0x3c]=L_k
      mode=0                              ; 1003dc36..46
  if ebx>0:                              ; 1003dc4a jle 0x1003dd54
      /* 上轮向上 → 检查是否触顶 */
      ┌─ cond 1: L_min ?H_k              ; 1003dc56 fcom st(2)
      ├─ cond 2: H_max ?L_k              ; 1003dc63 fcom st(2)
      └─ 选 cand (ebp 路径 0x1003dc6c..0x1003dc9e)
  elif ebx<=0:                           ; 0x1003dd54 jge 0x1003de4b
      /* 上轮向下 / 首轮 → 检查是否触底 */
      ┌─ cond 3: L_min ?H_k              ; 1003dd5e fcom st(2)
      ├─ cond 4: H_max ?L_k              ; 1003dd6b fcom st(2)
      └─ 选 cand (ecx 路径 0x1003dd7d..0x1003ddae)
  fcomp/fcompp: 二次比较 [esp+0x14/0x18] vs st(1) ; 1003dcdb..1003de42
  → 写 ebx=1/-1/2/-2 (方向)
  → 写 cand=[esp+0xe0]                  ; 1003dd2a/1003dd48
  → 装 A0 元素 [esp+0x40..+0xdf]        ; 1003de6b..1003defe
  ┌─ jge 0x1003e00c: cond 14..16         ; e200 风格判据 (H<max, L>min)
  └─ jl 0x1003df17: cond 17..21          ; db40 内部态转换
  push_back(W, &A0)                      ; 0x1006a5e0 (call 4 次)
  k++ 推进 [esp+0x1c]+=4, edi+=1         ; 1003e091..9c
```

注：fcom st(i) 不弹栈；fcomp 弹一；fcompp 弹二；fld 压栈；fst 不弹；fstp 弹一。

---

## §2 25 条件逐条（minij 表格）

| # | 地址 | op | st0 | st(i) | test | jcc | 跳 | 落 | 状态机语义 |
| -- | ---- | -- | --- | ----- | ---- | --- | -- | -- | -------- |
|  1 | 1003dc56 | fcom | L_min[+0x2c] | H_k[+0x14] | ah,1 | jne | <\|U | >\|= | ebx>0 路径：L_min < H_k 即触顶候选 |
|  2 | 1003dc63 | fcom | H_max[+0x28] | L_k[+0x18] | ah,0x41 | jp | >\|U | <\|= | H_max > L_k 或 unordered → fallback |
|  3 | 1003dca5 | fcom | H_k[+0x14] | L_min[+0x2c] | ah,1 | jne | <\|U | >\|= | jne → 0x1003dd0f（与 cond 1 镜像，二次确认） |
|  4 | 1003dcb0 | fcom | L_k[+0x18] | H_max[+0x28] | ah,0x41 | jp | >\|U | <\|= | jne → 0x1003dd13（与 cond 2 镜像） |
|  5 | 1003dcdb | fcomp | st0 (H or swap) | [esp+0x14]=H_k | ah,0x41 | je | > | <\|=\|U | 二次比较：当前态值 vs H_k；> 落 fstp [esp+0x14] |
|  6 | 1003dcec | fcomp | st0 (H or swap) | [esp+0x18]=L_k | ah,0x41 | je | > | <\|=\|U | 二次比较：当前态值 vs L_k；> 落 fstp [esp+0x18] |
|  7 | 1003dd17 | fcom | [esp+0x14]=H_k | L_min[+0x2c] | ah,0x41 | jne | <\|=\|U | > | ebx=1（向上）出口：H_k > L_min |
|  8 | 1003dd36 | fcompp | [esp+0x14]=H_k | L_min[+0x2c] | ah,5 | jp | >\|=\|U | < | 清 fstack；jp 跳到 0x1003de4f（不写） |
|  9 | 1003dd5e | fcom | L_min[+0x2c] | H_k[+0x14] | ah,1 | jne | <\|U | >\|= | ebx<=0 路径：L_min < H_k → 0x1003ddc3 |
| 10 | 1003dd6b | fcom | H_max[+0x28] | L_k[+0x18] | ah,0x41 | jp | >\|U | <\|= | H_max > L_k 或 U → 0x1003ddc3 |
| 11 | 1003dd82 | fcomp | srcL[ecx] | [esp+0x18]=L_k | ah,0x41 | jp | >\|U | <\|= | 向下路径：候选 cand 源 vs L_k |
| 12 | 1003ddc5 | fcom | [esp+0x14]=H_k | L_min[+0x2c] | ah,1 | jne | <\|U | >\|= | ebx<=0 路径二次确认（同 cond 3） |
| 13 | 1003ddd4 | fcom | [esp+0x18]=L_k | H_max[+0x28] | ah,0x41 | jp | >\|U | <\|= | ebx<=0 路径二次确认（同 cond 4） |
| 14 | 1003ddef | fcomp | srcL[ecx] | [esp+0x18]=L_k | ah,0x41 | jp | >\|U | <\|= | 向下路径：候选 cand 源 vs L_k（二次） |
| 15 | 1003de1d | fcomp | st0 (H or swap) | [esp+0x14]=H_k | ah,0x41 | jne | <\|=\|U | > | 向下路径二次比较；> 落 fstp [esp+0x14] |
| 16 | 1003de2e | fcomp | st0 (H or swap) | [esp+0x18]=L_k | ah,0x41 | jne | <\|=\|U | > | 向下路径二次比较；> 落 fstp [esp+0x18] |
| 17 | 1003df32 | fcom | [esp+0x14]=H_k | [esp+0x14]=H_k (st2) | ah,1 | jne | <\|U | >\|= | jge 路径：H_k 与 st(2) 比（实际是自身副本）|
| 18 | 1003df3f | fcom | [esp+0x18]=L_k | [esp+0x18]=L_k (st2) | ah,0x41 | jnp | <\|= | >\|U | jnp: L_k <= st(2)（不严格大于）|
| 19 | 1003df4a | fcomp | st0 (H) | st(3) (H) | ah,0x41 | jp | >\|U | <\|= | fxch 后 fcomp st(3) |
| 20 | 1003df53 | fcomp | st0 (L) | st(1) (L) | ah,1 | jne | <\|U | >\|= | L > L_k 落 0x1003df81 |
| 21 | 1003e02c | fcom | [esp+0x4c] (H_elem) | [esp+0x30] | ah,0x41 | jne | <\|=\|U | > | jge 0x1003e00c 后: H_elem vs prev_X |
| 22 | 1003e037 | fucomp | 0.0 | [esp+0x30] | ah,0x44 | jnp | = | >\|<\|U | prev_X == 0? 落 0x1003e063 |
| 23 | 1003e063 | fcom | [esp+0x4c] (H_elem) | [esp+0x30] | ah,5 | jp | >\|=\|U | < | 二次 H_elem vs prev_X |
| 24 | 1003df5e | cmp | [esp+0x20] (first-flag) | 0 | (cmp) | jne | first-flag!=0 | first-flag==0 | 写 1 (1003df6a) |
| 25 | 1003df81 | cmp | [esp+0x20] (first-flag) | 0 | (cmp) | je | first-flag==0 | first-flag!=0 | 写 1 (1003df9b) |

> 注：cond 21/22/23 是 jge 分支尾段（1003e00c..0x1003e08f）——即"前一根 X 与 0 比较 + 与当前 H 比较"；
> cond 24/25 是 first-flag 写入控制（jne 0x1003e091 / jmp 0x1003e091）。
> cond 17..20 是 jl 分支（0x1003df11..0x1003dfad）首段——内部态转换 H/L 自身比较。

---

## §3 互斥消费：`[esp+0x30]` vs `cand` [B]

- `[esp+0x30]` (`prev_X`): 由 1003dbcb `fstp [esp+0x30]=0.0` 初值；每轮 1003e0a3..0x1003e0a3 不写，
  实际只在两处被"消费"：
  - 1003e024..28 `fld [esp+0x30] fld [esp+0x4c] fcom st(1)`（cond 21）
  - 1003e037 `fucomp 0.0`（cond 22 测"是否归零"）
  - 1003e063 `fcom [esp+0x4c], st(1)`（cond 23，二次）
  - 写回：1003e080 `fadd [esp+0x50] fstp [esp+0x50]`（即 prev_X 累加到 H_max_elem 字段）
  - 写回：1003e054 `fsubr [esp+0x50] fstp [esp+0x50]`（累减）

- `cand` `[esp+0xe0]` (refpoint index): 仅在 0x1003dbdf 读 / 0x1003dd2a 与 0x1003dd48 写 `0xffffffff` / 0x1003dda5 写 ebp / 0x1003ddae 写 ebp+1（路径 1003ddae）/ 0x1003dde1 读 / 0x1003de01..0e10 写。

**互斥消费** [B]：在 0x1003dc6c..0x1003dc9e 段，cand（ebp 路径）只在 **ebx>0** 路径活跃；在 0x1003dd7d..0x1003ddae 段，cand（ecx 路径）只在 **ebx<=0** 路径活跃。两条路径在 1003dc4a 处分流，**不可能同时触发**。
而 `[esp+0x30]` 只在 jge 段（0x1003e00c 之后）被使用，与 cand 的活跃段**不重叠**。
因此两槽虽同栈帧、虽都被 ebp 临时引用，但实际语义解耦。

---

## §4 `cand = -1` 初值语义 [A]

- 1003dbdf `mov ebp, [esp+0xe0]`：第一次循环时 `[esp+0xe0]` 是栈垃圾（sub esp,0x174 后未清栈）。
- 实际行为：第一次进 1003dc4a 时 ebx=0（初值），jle 跳 0x1003dd54；jge 0x1003de4b（直接 fstp 清栈）路径。
- 因此第一次循环不会走 cand 读取；cand 直到 ebx 被赋 ±1 之后才被使用。
- 但栈垃圾是隐患：若把 0x1002c1d0 包装成可重入（多线程）就会读到残留。修正：1003dbdf 前应 memset / mov 0xffffffff。
- 0x1003dd20 / 0x1003dd43 / 0x1003de61 显式 `or ebp, 0xffffffff` 写 -1；这是 cand "未设定" 的规范值。
- 结论 [A]：cand=-1 表示"当前无有效候选 refpoint"，写入发生在 1003dd20/1003dd43/1003de61/1003de68（四个出口都清 -1）。
- 与 0x1003dbdf 的栈垃圾形成"两路并存"：正常运行走显式 -1；首次/异常走垃圾；与 1003dc4a 的 ebx<=0 分流保证了不会误用。
- docs/20 §4 把 cand 描述为"candidate 端点"；本批落地为"refpoint 索引"——更准确。

---

## §5 单元测试（`tools/re-inventory/chbi/test_db40.py`）

见同目录测试文件。
