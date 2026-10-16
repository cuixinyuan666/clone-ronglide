# docs/30 — NChBi 第六批（收官）：FxNum / Speed 逐条展开 + Rec20 段连续性不变式

> 批次：NChBi 第六批（监控方派发 2026-10-17 05:47）
> 前置：第五批 `9a87029`（Zj3/ZjNum 补完）
> 本批口径：**frida 动态不运行**（需用户在场）；主攻静态收口，目标「整族静态覆盖度 ~100%」。
> 目标：T1 FxNum / T2 Speed 逐条展开（[C]→定）、T3 Rec20 段连续性不变式（[B]→定）、T4 "Zj3" 的 "3"、T5 cnt 增量条件。

---

## 〇、摘要

| 项 | 结论 | 置信 |
|---|---|---|
| **T1 NChBiFxNum `0x10003680`** = `out[barIdx(k)] = ord(k) − ord(k−1) + 1`（相邻分型 **bar 间距**）；授权 EA62；只读 obj10；0 x87 条件 | 完成 | [A] |
| **T2 NChBiSpeed `0x10003a90`** = `out[barIdx(k)] = 1000 × \|A − B\| / (A × SPAN)`（每 bar 相对涨跌 ‰，即"速度/斜率"）；授权 EA62；读 obj8+obj10；1 x87 条件（`A==0` 守卫） | 完成 | [A] |
| ★ **T3 `Rec20[k].endBar + 1 == Rec20[k+1].startBar` 恒成立** ⇒ Zj3 与 ZjOrder 目标**同槽**（docs/29 §4.2 [B] 结案） | 完成 | [A] |
| **T4 "Zj3" 的 "3"**：包装体与 `CalcProc_NChBiZj` **逐字节同构**，仅授权码(EA61→EA62)与槽(+0x44→+0x48)不同，同为 3 参 ⇒ "3" 是导出名/枚举序号，**非参数** | 完成 | [A] |
| **T5 cnt 增量条件**：`bit2 ∧ ¬bit0 ∧ value ≠ lastValue` 中的"不等"用于滤除同向重复项 | 完成 | [B] |
| 新工具 `x87_expr.py`（符号化 x87 栈模拟器）——同时纠正了两处 x87 语义（D8/DC 寄存器形态**不弹栈**；P 形态操作数次序） | 完成 | [A] |

**族内 9 支静态覆盖度**：NChBi / Sta / Sta2 / Zj / **Zj3** / ZjOrder / **ZjNum** / **FxNum** / **Speed** 全部完成解剖 ⇒ **~100%**。

---

## 一、T1 —— NChBiFxNum（`vt[+0x58] = 0x10003680`）

证据：`tools/re-inventory/nchbi/chlib_worker_10003680.txt`（**函数区间 0x10003680–0x100038ad**，`ret 0x10`）、
`cond_chlib_10003680.txt`（**0 x87 条件**）。

### 1.1 签名与栈基点 [A]

`__thiscall ret 0x10` ⇒ 4 参数；**仅用 arg1(=n)/arg2(=out)**。
序言 `sub esp,0x18` + push ebx/esi/edi(3) + memset 的 3 个 cdecl 参数（`add esp,0xc` 回收）+ **line35 `push ebp`**
⇒ 循环内 **esp = P-0x28**。

> ★ 铁律实例：若漏掉 line35 的 `push ebp`，会把 `[esp+0x24]` 误判为「返回地址槽」。
> 本批已按 +4 修正后各槽自洽（见下表）。

| 槽 | 位置 | 内容 | 赋值点 |
|---|---|---|---|
| `[esp+0x10]` | P-0x18 | **结果暂存**（写入 out 的值） | 0x10003749 等 |
| `[esp+0x14]` | P-0x14 | **cnt = Item21 项数** | 0x100036ae（该点 esp=P-0x24，故写作 +0x10） |
| `[esp+0x18]` | P-0x10 | 相对偏移 `0xffffffc2 − Item21base` | 0x10003719 |
| `[esp+0x1c]` | P-0xc | 相对偏移 `0xffffffe3 − Item21base` | 0x100036ef |
| `[esp+0x20]` | P-8 | 相对偏移 `4 − Item21base` | 0x100036fa |
| `[esp+0x24]` | P-4 | 相对偏移 `0x25 − Item21base` | 0x10003705 |
| `[esp+0x2c]` | P+4 | arg1 = n | — |
| `[esp+0x30]` | P+8 | arg2 = out | — |

（4 个「相对偏移」是编译器的地址缓存：`edx = (const − Item21base) + eax`，随后 `[edx + Item21base + 5]` 即该组某项的 `+0x05`；
eax 每组前进 `0x84`，故 const 也按组滚动 ⇒ 每组末项缓存被下一组 block0 复用，四路串起来 = "每一项减它的前一项"。）

### 1.2 门 / 失败出口表 [A]

| # | 判据 | 地址 |
|---|---|---|
| 0 | `memset(out, 0, n*8)` | 0x1000369b（thunk 0x1001494c） |
| 1 | `obj10[+0x30] != 0`（Item21 base） | 0x100036a3 / 0x100036ac / 0x100036b2 |
| 2 | `this[+4] != 0`（ch_auth） | 0x100036c0 |
| 3 | `Authorize(0xEA62)` | 0x100036ce（`push 0xea62`） |
| 4 | `cnt >= 4` 才走四路展开 | 0x100036df / 0x100036e2 |

失败出口 0x100036b4（`or eax,-1`）；成功出口 0x100038a7（`xor eax,eax`）。
★ **不读 obj8**（与 Zj/ZjNum 同）——只依赖 obj10。

### 1.3 主体 [A]

四路展开（`add eax,0x84`，eax 原点 = Item21base+0x3e，第 n 组 +n*0x84）+ 尾部单步（0x10003835–0x100038a2，`0x21`）：

| 路 | flags | ord(`+0x05`) | barIdx(`+0x1d`) | 减数 = 前一项的 `+0x05` |
|---|---|---|---|---|
| 0 (`4n`) | `[eax-0x3a]` | `[eax-0x39]` | `[eax-0x21]` | 经 `[esp+0x18]` 缓存 → `Item21[4n-1][+5]` |
| 1 (`4n+1`) | `[eax-0x19]` | `[eax-0x18]` | `[eax]` | 经 `[esp+0x1c]` → `Item21[4n][+5]` |
| 2 (`4n+2`) | `[eax+8]` | `[eax+9]` | `[eax+0x21]` | 经 `[esp+0x20]` → `Item21[4n+1][+5]` |
| 3 (`4n+3`) | `[eax+0x29]` | `[eax+0x2a]` | `[eax+0x42]` | 经 `[esp+0x24]` → `Item21[4n+2][+5]` |

```
for k in 0..cnt-1:
    if (!(flags[k] & 1)) continue;                 // ★ 唯一门 = bit0
    if (lastIdx < 0 || k <= lastIdx) goto update;  // 首项跳过（无前项）
    b = barIdx[k];  if (b<0 || b>=n) goto update;
    out[b] = (double)(ord[k] - ord[prev] + 1);      // +0x05 之差 + 1
 update: lastIdx = k; prevOff = 0x21*k;
```

### 1.4 语义与「单位」对照表 [A]

> **NChBiFxNum = 相邻分型的 bar 间距（含两端，`ord(k) − ord(k−1) + 1`）**
> `ord = Item21[+0x05]`（分型中心 bar 序号，docs/28 §1.4）、`barIdx = Item21[+0x1d]`。
> 首个 Item21 无前项 ⇒ 跳过。

| 维度 | ZjNum `0x100038b0`（第五批） | **FxNum `0x10003680`（本批）** |
|---|---|---|
| 门 | bit0 写 / bit2 计数 | **bit0 写**（无 bit2） |
| 取值字段 | `value(+0x00)`、`barIdx(+0x1d)` | **`ord(+0x05)`**、`barIdx(+0x1d)` |
| 运算 | **运行计数器 +1** | **一项 − 前一项 +1** |
| **单位** | **Zj 项数** | **bar 距离（K 线根数）** |
| 首项 | 处理（out=0） | **跳过** |
| 容器 / 授权 / memset / 4 路展开 0x84 / 尾 0x21 | obj10 / EA62 / 同 / 同 / 同 | obj10 / EA62 / 同 / 同 / 同 |

> ⇒ docs/27 §6.2「间隔**笔数** vs **bar 数**」之争在本族内**两个指标并存且各有导出**：
> **ZjNum ↔ Zj 项数**、**FxNum ↔ bar 数**。（两者互为对照证据，双双升 [A]。）

---

## 二、T2 —— NChBiSpeed（`vt[+0x60] = 0x10003a90`）

证据：`tools/re-inventory/nchbi/chlib_worker_10003a90.txt`（0x10003a90–0x10003cc1，`ret 0x10`）、
`cond_chlib_10003a90.txt`（**1 x87 条件**）。

### 2.1 签名 / 帧 [A]
`__thiscall ret 0x10`；序言 `push ebp; mov ebp,esp; and esp,0xfffffff8; sub esp,0x34`（帧指针 + 8 字节对齐）。
arg1 = `[ebp+8]` = **n**；arg2 = `[ebp+0xc]` = **out**；arg3/arg4 未用。

### 2.2 六道门 / 失败出口表 [A]

| # | 判据 | 地址 |
|---|---|---|
| 0 | `memset(out, 0, n*8)` | 0x10003aaf |
| 1 | `obj8[+0x08] != 0`（价数组 A） | 0x10003ada / 0x10003af0 |
| 2 | `obj8[+0x0c] != 0`（价数组 B） | 0x10003af6 / 0x10003af8 |
| 3 | `obj8[+0x1c] != 0`（Rec20 base） | 0x10003afe / 0x10003b00 |
| 4 | **`obj_c[+0x28] != 0`** | 0x10003b06–0x10003b0d |
| 5 | `obj10[+0x30] != 0`（Item21 base） | 0x10003b13 / 0x10003b15 |
| 6 | `this[+4] != 0` + `Authorize(0xEA62)` | 0x10003b1b / 0x10003b2d（`push 0xea62`） |

失败出口 0x10003cb8（`or eax,-1`）；成功出口 0x10003cad（`xor eax,eax`）。

### 2.3 主体 [A]（单步 0x21，非展开）

```
for k in 0..cnt-1:                                // Item21[k]; edi = &Item21[k].barIdx
    if (!(flags[k] & 1)) continue;                 // bit0
    if (lastIdx < 0) goto update;                  // 首项跳过
    b = barIdx[k]; if (b<0 || b>=n) goto update;
    if (value[k] == value[prev]) continue;         // ★ 必须"反向"（顶底交替）
    idxP = recIdx[prev]; idxC = recIdx[k];         // [+0x09]
    if (idxP/idxC 越界 [0,obj8[+0x14])) continue;
    iA = Rec20[idxP][ (value[prev]==1)? +0x08 : +0x0c ];
    iB = Rec20[idxC][ (value[k]  ==1)? +0x08 : +0x0c ];
    if (iA/iB 越界 [0,obj8[+0x14])) continue;
    A = (value[prev]==1 ? obj8[+0x08] : obj8[+0x0c])[iA];   // 前分型"价"
    B = (value[k]  ==1 ? obj8[+0x08] : obj8[+0x0c])[iB];    // 本分型"价"
    if (A == 0.0) continue;                                  // ★ x87 条件 1/1
    SPAN = Rec20[idxC][+0x04] - Rec20[idxP][+0x00] + 1;
    if (SPAN == 0) continue;                                 // 第二个除零守卫
    out[barIdx[k]] = 1000.0 * |A - B| / (A * SPAN);
 update: lastIdx = k; prevOff = 0x21*k;
```

### 2.4 ★ 公式（符号 x87 栈模拟确证）[A]

新工具 `tools/re-inventory/nchbi/x87_expr.py` 对 0x10003c33–0x10003c76 求解，初始栈 `[1000.0, 0.0]`：

```
out[barIdx(k)] = |(A - B) * 1000.0 / A| / SPAN   ==   1000.0 * |A - B| / (A * SPAN)
```

**且每轮结束后栈精确回到 `[1000.0, 0.0]`** —— 既验证了模型，也解释了函数出口 0x10003ca9 的两条 `fstp st(0)`
恰为清空这两个哨兵。

**语义**：`1000 × |Δ价| / (参考价 × bar 跨度)` = **每 bar 相对涨跌幅（‰）** ⇒ 即缠论语境下的**"速度/斜率"**。
- `A == 0.0 → 跳过` 正是**防除零**（A 在分母）—— 反证公式正确。
- `SPAN == 0 → 跳过` 为第二个除零守卫。
- 常量 `0x10015558 = 1000.0`（本批实测；邻位 0x10015550 = 5.0、0x10015560 = 0.25）。

### 2.5 ★ 工具勘误（重要，影响后续所有 x87 链）[A]
初版 `x87_expr.py` 把 D8/DC 寄存器形态按"弹栈"建模，导致 fn 内栈无法回衡、并输出退化公式（0）。
修正两条 Intel 语义后自洽：
1. **D8/DC + 单寄存器操作数 ⇒ `ST(0) = ST(0) op ST(i)`，不弹栈**
   （反例检验：`D8 C0 = fadd st(0),st(0)` 是"原地加倍"惯用法，显然不弹）。
2. **DE 「P」形态才弹栈**，且 `FDIVRP ST(i),ST(0)` = `ST(i) = ST(0)/ST(i)`（`FDIVP` 反之）。

### 2.6 obj8 补映射（本批新增 [A]）
Speed 揭示 obj8 同时持有**价数组**与**段记录数组**：

| 偏移 | 语义 |
|---|---|
| `+0x08` / `+0x0c` | `double*` 两条**价数组** A / B |
| `+0x14` | 价数组长度 len |
| `+0x18` | flag（生产时置 1） |
| `+0x1c` / `+0x28` | **Rec20 段记录 base / cnt** |

---

## 三、T3 —— Rec20 段连续性不变式（★ 本批最高价值，[A] 结案）

### 3.1 定位生产者 [A]
- 全 .text 扫 `[+0x1c]`/`[+0x28]` 写点 + 虚表立即数写入 ⇒ **obj8 构造器 `0x100094b0`**（0x100094b3 写 vt `0x100153ec`）。
- **obj8 虚表 `0x100153ec`**：`+0x00=0x100094b0`(析构) / `+0x04=0x10009500`(**clear**) /
  **`+0x08=0x10009530`(★ Rec20 生产者)** / `+0x0c=0x1000e0b0`(通用 5 参 setter)。
- 证据：`obj8_push_10009500.txt`（19 行）、`obj8_m2_10009530.txt`（195 行）。

### 3.2 Rec20 记录布局 [A]
由 emit 处的 `rep movsd ecx=8`（0x100096c5 / 0x10009718，一次刷出 0x20 B）确证：

| 偏移 | 类型 | 语义 | 写入点 |
|---|---|---|---|
| +0x00 | i32 | **startBar** | 0x10009599（初值 0）/ 0x100096d8（emit：设为当前 i） |
| +0x04 | i32 | **endBar** | 0x100095fe（**每次"延伸"迭代设为当前 i**）/ 0x100096d0 |
| +0x08 | i32 | idxA（价数组 A 下标） | 0x100095a1 / 0x10009665 / 0x100096de |
| +0x0c | i32 | idxB（价数组 B 下标） | 0x1000959d / 0x100096ea |
| +0x10 | f64 | p1（= A[i]） | 0x10009584 / 0x100096d4 |
| +0x18 | f64 | p2（= B[i]） | 0x10009591 / 0x100096e2 |

（与 Zj3 只用 `+0x00/+0x04`、Speed 用 `+0x00/+0x04/+0x08/+0x0c` 完全吻合。）

### 3.3 生产者主循环 [A]
```
produce(this = obj8):
    len = this[+0x14]; A = this[+0x08]; B = this[+0x0c]
    if (!len || !A || !B) return -1
    reserve(this+0x1c, len);  this[+0x18] = 1;  this[+0x28] = 0
    buf = {startBar:0, endBar:0, idxA:0, idxB:0, p1:A[0], p2:B[0]}
    for i in 1..len-1:
        if (<价格条件 A>) goto EMIT
        if (<价格条件 B>) goto EMIT
    EXTEND:  buf.endBar = i;            // ★ 0x100095fe —— 每次非 emit 迭代都执行
             <与上一段 p1/p2 比较，必要时改 buf.idxA / buf.idxB>
             goto NEXT
    EMIT:    vec[cnt] = buf; cnt++;     // 刷出已完结段；然后给"下一段"赋初值：
             buf.endBar = i;            // ★ 0x100096d0
             buf.startBar = i;          // ★ 0x100096d8
             buf.idxA = i; buf.p2 = B[i]; buf.idxB = i
    NEXT:    i++
    vec[cnt] = buf; cnt++               // 0x10009704 收尾 emit
```

### 3.4 ★ 不变式 [A]

> **`Rec20[k].endBar + 1 == Rec20[k+1].startBar` 恒成立（k < cnt−1）**
> ⇒ 段记录构成对 `[0, len−1]` 的**连续划分**（无空洞 / 无重叠）。

**结构论证**（不依赖运行时）：
1. 迭代只有两类：**非 emit 迭代必走 0x100095f9**（唯一入口），因而**必把 `endBar = i`**（0x100095fe）；
   **emit 迭代**在刷出后把**下一条**记录 `startBar` 设为当前 `i`（0x100096d8）。
2. ⇒ 若第 k+1 段在第 `i` 次迭代"开段"，则第 k 段最后一次 `endBar` 赋值必为 `i−1`
   （来源二选一：上一迭代的 0x100095fe，或上一条 emit 的 0x100096d0 —— 两者都等于 `i−1`；
   若第 k 段是首段，其 `endBar` 初值 0 且此时 `i = 1` ⇒ `0+1 = 1` 同样成立）。
3. 连续 emit（零长段 `[i−1,i−1]`）亦满足（上一条 `endBar = i−2`，本条 `startBar = i−1`）。

### 3.5 对 docs/29 §4.2 [B] 的结案 [A]
⇒ **NChBiZj3 的写入槽 `out[Rec20[recIdx].endBar + 1]` 与 NChBiZjOrder 的 `out[Rec20[recIdx+1].startBar]`
在 `recIdx+1 < cnt` 时是同一槽**。
故二者差异**仅为过滤门**（Zj3: `bit2`；ZjOrder: `bit0 ∧ ¬bit3 ∧ |ZjNum[barIdx]| ≥ thr`），**非目标位置**。

---

## 四、T4 —— "Zj3" 中 "3" 的含义（[B] → [A]收口）

`CalcProc_NChBiZj`（0x10012d20）与 `CalcProc_NChBiZj3`（0x10012d90）**逐字节同构**：

| 差异项 | Zj | Zj3 |
|---|---|---|
| Authorize 立即数 | `0xEA61`（0x10012d2a） | `0xEA62`（0x10012d9a） |
| 虚表槽 | `[edx+0x44]`（0x10012d73） | `[edx+0x48]`（0x10012de3） |
| 其余（帧 / `0x10006cc0` 取行情 / 4 参推送 / `ret 0xc`） | **完全相同** | **完全相同** |

⇒ 包装体**不传额外整型参数、无字面 3**；两者对本函数的调用参数形状一致（n / out / &buf / P）。
**结论 [A]**："Zj3" 是**导出名层面的枚举序号**（族内第 3 变体），**不是运行参数或值域标记**。
（至于作者为何编号 3，属命名学，无字节证据；标 [C]。）

---

## 五、T5 —— cnt 增量条件语义（[B] 收口）

ZjNum 的递增条件 `flags.bit2 ∧ ¬flags.bit0 ∧ value ≠ lastValue`（详见 docs/29 §二）：

- `lastValue` = **上一个 bit0 项（有效分型）的 value**，只在 bit0 分支更新。
- 追加 `value ≠ lastValue` 的必要性：docs/28 §2.6 已确权 `pair_recheck`(0x1000abb0) 第 3 步
  「`value[j] == value[i]` ⇒ false（必须一顶一底）」——即**配对器会拒绝同向对**，
  但**被拒项仍留在 Item21 数组中**。故该不等式正是**滤除同向重复项**。
- ⇒ **`value ≠ lastValue` ≈ "该项是反向的"**（等价于"笔方向交替"的机械判据），**置信 [B]**
  （[A] 需运行时确认 Item21 中同向相邻项的实际出现率）。
- 最小验证设计（并入 frida 预备包）：挂 `0x100038b0` 出口，dump `obj10[+0x30]` 的 `value/flags` 序列，
  统计 bit2∧¬bit0 项中 `value == lastValue` 的比例；>0 即实证"该判据非平凡"。

---

## 六、勘误与待仲裁

### 6.1 勘误（本批自查）[A]
1. **栈基点**：FxNum 的 `push ebp`（0x100036d9）易被漏读，导致 `[esp+0x24]` 被误算为返回地址槽。
   已在 §1.1 显式给全 6 个局部槽的绝对位置。
2. **x87 语义两处纠正**（§2.5）：D8/DC 寄存器形态**不弹栈**；DE「P」形态才弹栈且反向除/减的操作数次序为 `ST(i) = ST(0) op ST(i)`。
   此勘误影响**此前所有基于"寄存器形态弹栈"的推导**（本批仅 Speed 受影响，其余函数为纯整数链，不受影响）。
3. **obj8 语义修正**：第五批记「obj8 = Rec20（+0x1c/+0x28）」，本批补全其**同时持有价数组**（+0x08/+0x0c/+0x14）。
4. **Speed 的 "输出 |value|" 表述过简**：实为 `1000×|A−B|/(A×SPAN)`，"|·|" 只是链条中的 `fabs`（0x10003c70）。

### 6.2 待仲裁 [B]/[C]
- **[B] Item21[+0x05] 与 Item21[+0x1d] 是否同值**：FxNum 用前者、Zj/Zj3 用后者作 bar 下标；
  若同值则 FxNum = 标准"分型间距"，否则 [+0x1d] 另有语义（"笔端点 bar"）。需 obj10 fill（0x10009a20 链）复核。
- **[B] `obj_c[+0x28]` 在 Speed 中的用途**（第 4 道门）——本批未展开 obj_c 该字段。
- **[C] "Zj3" 编号 3 的命名缘由**（§四）。
- **[C] T5 的运行时验证**（§五）。
- **[C] 本批未做动态验证**（frida 预备包保持现状，待用户在场）。

---

## 七、可复现命令

```bash
DLL=ronglide-app/chlib.dll
PY=C:/Users/Administrator/Documents/a_conda/python.exe

# 1) 本批两个主角（已在第五批落盘，本批复核函数尾）
$PY tools/re-inventory/disasm_func.py 0x10003680 --max 0x500 --dll "$DLL" \
    -o tools/re-inventory/nchbi/chlib_worker_10003680.txt   # FxNum: 0x10003680-0x100038ad
$PY tools/re-inventory/disasm_func.py 0x10003a90 --max 0x500 --dll "$DLL" \
    -o tools/re-inventory/nchbi/chlib_worker_10003a90.txt   # Speed: 0x10003a90-0x10003cc1

# 2) x87 条件表
$PY tools/re-inventory/x87_sim.py tools/re-inventory/nchbi/chlib_worker_10003680.txt \
    -o tools/re-inventory/nchbi/cond_chlib_10003680.txt     # => 0 conditions
$PY tools/re-inventory/x87_sim.py tools/re-inventory/nchbi/chlib_worker_10003a90.txt \
    -o tools/re-inventory/nchbi/cond_chlib_10003a90.txt     # => 1 condition (A==0.0)

# 3) ★ Speed 公式符号求解（新工具）
$PY tools/re-inventory/nchbi/x87_expr.py tools/re-inventory/nchbi/speed_x87_trace.txt \
    --stack "1000.0,0.0"                                    # => |((A-B)*1000.0/A)|/SPAN

# 4) T3: obj8 生产者
$PY tools/re-inventory/disasm_func.py 0x100094b0 --max 0x120 --dll "$DLL"   # obj8 ctor
$PY tools/re-inventory/disasm_func.py 0x10009500 --max 0x120 --dll "$DLL" \
    -o tools/re-inventory/nchbi/obj8_push_10009500.txt      # clear
$PY tools/re-inventory/disasm_func.py 0x10009530 --max 0x300 --dll "$DLL" \
    -o tools/re-inventory/nchbi/obj8_m2_10009530.txt        # ★ Rec20 生产者

# 5) T4: Zj / Zj3 包装体对比（同构证明）
$PY tools/re-inventory/disasm_func.py 0x10012d20 --max 0x80     # Zj  (0xEA61 / +0x44)
$PY tools/re-inventory/disasm_func.py 0x10012d90 --max 0x80     # Zj3 (0xEA62 / +0x48)

# 6) 看板刷新
$PY tools/re-inventory/verify_status.py --write
```

---

## 八、下一步建议

**NChBi 族静态覆盖度已达 ~100%**（9 支全解 + 共享基础设施 + Rec20 契约）。下一步二选一：

1. **（首选）NChZs 族 kickoff** —— `NChZs` / `NChZsG` / `NChZsBs12`（槽 `+0x78` 起，授权码 EA61–63）。
   论证：**方法学与基础设施可直接复用** —— 本族已确权的 `obj8`（价数组 + Rec20 段记录 + 连续性不变式）、
   `obj10`（Item21 + flags 位台账）、配对器 `0x1000b000`/`0x1000a250`、通用 setter `0x1000e0b0`、
   以及 `x87_expr.py` 等工具链，在 NChZs 族大概率是**同一套容器契约**（中枢本质上是"笔段的再聚合"）。
   ⇒ 单位边际成本最低、覆盖面（中枢/走势）最大。
2. **（次选）CHBI 第六批：0x1003f170 的 481 条条件逐条落地**（docs/23 §七 遗留 [C]）。
   论证：条件数与收敛度均高于 NChZs 的未知量，单批产出更"完整"但更枯燥；且与 NChBi 无共享容器
   （CHBI 走 TAFLib 侧），复用度低于方案 1。

> 若用户在场，**优先跑 frida 预备包**（`frida_nchbi3.md` + `frida_dump_out.js`），
> 可一次性把 §六 的 [B]/[C]（Item21 `+0x05` vs `+0x1d`、T5 运行时比例、Speed 数值对拍）升为 [A]。
