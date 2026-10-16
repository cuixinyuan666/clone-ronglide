# docs/29 — NChBi 第五批：NChBiZj3 / NChBiZjNum 补完 + ZjNum cnt 语义静态结清

> 批次：NChBi 第五批（监控方派发 2026-10-17 05:45）
> 前置：第四批 `3c90c7a`（生产端分型几何与 Zj 配对）
> 本批口径：**frida 动态不运行**（需用户在场启动交易软件），主攻**静态覆盖度**；frida 预备包保持现状（`tools/re-inventory/nchbi/frida_nchbi3.md` + `frida_dump_out.js`）。
> 目标：T1 NChBiZj3 解剖 / T2 NChBiZjNum 解剖（含 cnt 语义结案）/ T3 同族总览 + 文档一致性微修。

---

## 〇、摘要

| 项 | 结论 | 置信 |
|---|---|---|
| NChBiZj3 `0x10002fc0` = Item21 散射器，写入点 `out[Rec20[recIdx].endBar+1]`，门 = `flags.bit2`，授权码 **0xEA62** | 完成 | [A] |
| NChBiZj3 与 NChBiZj **唯一差别 = 目标下标**（Zj 用 `Item21[+0x1d]`；Zj3 用 `Rec20[recIdx][+0x04]+1`） | 完成 | [A] |
| NChBiZjNum `0x100038b0` = 计数器散射器，授权码 **0xEA62**，**只吃 obj10（不读 obj8）** | 完成 | [A] |
| ★ **ZjNum `cnt` 单位 = Item21 条目数，不是 bar 数**（docs/27 §6.2 [C] 静态结案；以 bar 为单位的假设**证伪**） | 完成 | [A] |
| 全族 9 支槽位/地址/授权码/容器依赖总览 + 授权码分组规律（EA61 vs EA62） | 完成 | [A] |
| "Zj3" 中"3"的语义 | **函数体无字面 3**；判定为枚举第 3 变体名 | [B] |
| docs/26 §九「`NCHBI.next`」表述微修 | 1 行修正 | [A] |

---

## 一、T1 —— NChBiZj3（`vt[+0x48] = 0x10002fc0`）

证据：`tools/re-inventory/nchbi/chlib_worker_10002fc0.txt`（153 insn，尾 `0x1000317c ret 0x10`）、
`cond_chlib_10002fc0.txt`（**x87 条件 0 条**）。

### 1.1 签名与栈槽换算 [A]

`__thiscall` + `ret 0x10` ⇒ **4 个 dword 参数**；本函数实际只读 arg1/arg2（尾部两参未用）。
序言 `sub esp,8` → 入口 P 处：`[esp+0xc]`=arg1、`[esp+0x10]`=arg2；push 4 寄存器 → push 3(cdecl memset) → `add esp,0xc` 后**循环内 esp = P-0x18**。

| 槽 | 位置 | 内容 | 赋值点 |
|---|---|---|---|
| arg1 | P+4 | **n（bar 数）** | 调用者 |
| arg2 | P+8 | **out[]（double*）** | 调用者 |
| local0 | P-8 | nRec = `obj8[+0x28]` | 0x10002fea（此时 esp=P-0x24） |
| local1 | P-4 | Item21 base = `obj10[+0x30]` | 0x10002ffc（此时 esp=P-0x18） |
| `[esp+0x10]` | P-8 | = nRec（循环内比对） | — |
| `[esp+0x14]` | P-4 | = Item21 base | — |
| `[esp+0x1c]` | P+4 | = n | — |
| `[esp+0x20]` | P+8 | = out | — |

> 提示（铁律）：0x10002fea 与 0x10002ffc 虽写同一"逻辑局部",但**处于不同代码点、esp 不同**（P-0x24 vs P-0x18），逐条比对时必须各按各的基点换算。

### 1.2 四道门 + 授权 [A]

| # | 判据 | 地址 | 语义 |
|---|---|---|---|
| 0 | `memset(out, 0, n*8)`（thunk `0x1001494c`） | 0x10002fcf–0x10002fdc | 输出清零 |
| 1 | `obj8[+0x1c] != 0` | 0x10002fe1, 0x10002ffa, 0x10003000 | Rec20 记录表存在 |
| 2 | `obj10[+0x30] != 0` | 0x10002fee, 0x10003006, 0x10003008 | Item21 端点项数组存在 |
| 3 | `this[+4] != 0` | 0x1000300e–0x10003012 | `ch_auth*` 存在 |
| 4 | `Authorize(0xEA62)` = `this[+4]->vt[+4](0xEA62)` | 0x10003018–0x10003029（`push 0xea62` @0x10003020） | **授权码 0xEA62** |

失败出口：`0x10003172`（`or eax,-1`）；成功出口：`0x10003166`（`xor eax,eax`）。

> ★ **与 NChBiZj 的授权码不同**：Zj(0x10002ea0) 推 `0xEA61`（0x10002eea），Zj3 推 `0xEA62`。二者**不是同一许可单元**。

### 1.3 主体：Item21 遍历（4 路展开 + 0x21 单步收尾）[A]

- 展开循环 0x1000302f–0x10003113：`eax` 起始 = Item21base+0x2a，每轮 `add eax,0x84`（132 = 4×0x21），第 k 轮覆盖 `Item21[4k..4k+3]`。
- 尾部循环 0x1000311d–0x10003164：`ecx = Item21base + esi*0x21 + 9`（`shl ecx,5` + `lea ecx,[esi+ecx+9]` 合成 `esi*0x21`），`add ecx,0x21` 单步。
- 每条 Item21（stride 0x21）逐项判定与写入：

```
flags = [item+0x04]
if (flags & 4) {                       // ★ bit2 门（唯一门）
    idx = [item+0x09]                  // recIdx (int32)
    if (idx < 0 || idx >= nRec) skip   // 0x1000305d cmp [esp+0x10]
    slot = Rec20[idx][+0x04] + 1       // 0x10003063 shl 5; 0x10003066 [ecx+edi+4]; 0x1000306a add 1
    if (slot < 0 || slot >= n) skip    // 0x1000306d js; 0x1000306f cmp [esp+0x1c]
    out[slot] = (double)[item+0x00]    // 0x10003075 fild dword; 0x1000307c fstp qword
}
```

- 四路展开体内字段偏移**交叉确证**：

| 路 | flags | recIdx | value |
|---|---|---|---|
| 0 | 0x10003050 `[eax-0x26]` | 0x10003056 `[eax-0x21]` | 0x10003075 `[eax-0x2a]` |
| 1 | 0x1000307f `[eax-5]` | 0x10003085 `[eax]` | 0x100030a3 `[eax-9]` |
| 2 | 0x100030ad `[eax+0x1c]` | 0x100030b3 `[eax+0x21]` | 0x100030d2 `[eax+0x18]` |
| 3 | 0x100030dc `[eax+0x3d]` | 0x100030e2 `[eax+0x42]` | 0x10003101 `[eax+0x39]` |

（以 `eax = Item21base+0x2a` 为原点，四组均落在 `j*0x21 + {0x04, 0x09, 0x00}` ⇒ 布局恒定。）

### 1.4 语义与同族复用关系 [A]

> **NChBiZj3 = 「对每个 `flags.bit2` 置位的 Item21：`out[ Rec20[recIdx].endBar + 1 ] = (double)value`」**

**与 NChBiZj（0x10002ea0）对比** —— 逐段同构、**只差目标下标**：

| 维度 | NChBiZj | NChBiZj3 |
|---|---|---|
| memset | 同 | 同 |
| 容器 | **只读 obj10** | 读 obj8 + obj10 |
| 门 | `flags.bit2` | `flags.bit2`（同） |
| 下标 | `Item21[+0x1d]`（barIdx 直取） | `Rec20[Item21[+0x09]][+0x04] + 1` |
| 值 | `(double)Item21[+0x00]` | 同 |
| 授权 | 0xEA61 | 0xEA62 |

**与 NChBiZjOrder（0x10003180）对比**：

| 维度 | NChBiZj3 | NChBiZjOrder |
|---|---|---|
| 门 | `bit2` | `bit0 ∧ ¬bit3 ∧ |ZjNum[barIdx]| ≥ thr` |
| 目标槽 | `Rec20[recIdx][+0x04]+1` | `Rec20[recIdx+1][+0x00]`（若段连续则**同槽**） |
| ZjNum 依赖 | 无（不调 vt[+0x5c]） | **先调 vt[+0x5c]** |
| 额外输入 | 无 | arg3/arg4 |
| 授权 | 0xEA62（在门之后、循环之前） | 0xEA61（**在 ZjNum 调用之后**） |

⇒ 三者构成一族**同内核（Item21 散射）不同筛/下标**的变体；Zj3 是其中**最精简**的一支（无 obj8 之外的额外依赖、无 ZjNum、无阈值）。

**shared kernel 判定**：Zj/Zj3/ZjOrder/ZjNum **共享同一 Item21 遍历内核**（同 stride 0x21、同 4 路展开、同越界三段式保护、同 memset 前置、同 `ch_auth->vt[+4]` 授权调用形态），但**无函数级复调用**（各自内联展开，非 call 共享）。判据：四函数体内 `add eax,0x84` / `add [..],0x21` 各出现 1 次，且彼此无 call 关系（调用目标统计仅见 `0x1001494c` 与虚表 `eax`）。

### 1.5 "Zj3" 的 3 [B]

- 函数体**无字面常量 3**：全部立即数为 `0xEA62 / 0x21 / 0x84 / 0x20 / 0x04 / 0x09 / 0x1d / 1`，无 3。
- 槽位 +0x44/+0x48/+0x4c 相邻 ⇒ **"3" 更可能是枚举中第 3 个变体的名字**（Zj / **Zj3** / ZjOrder），非运行参数。
- 备选假设（**无证据**）：写入点 = 「段尾 bar 的下一个 bar」= 下一笔起点，与缠论「分型/笔的三段结构」的"第 3 位置"呼应。
- 坐实路径（未做）：反汇编 TAFLib 侧 `?CalcProc_NChBiZj3@`(0x10012d90) 的包装体，看是否比 Zj 多构造一个整型实参。

---

## 二、T2 —— NChBiZjNum（`vt[+0x5c] = 0x100038b0`）与 cnt 语义结清

证据：`tools/re-inventory/nchbi/chlib_worker_100038b0.txt`（161 insn，尾 `0x10003a7f ret 0x10`）。

### 2.1 签名与门 [A]

- 序言 `push ecx` 分配 1 个 local（P-4）；push 4 寄存器 → push 3(memset) → `add esp,0xc` ⇒ 循环内 **esp = P-0x14**。
  - `[esp+0x10]` = local = **计数器**（初值 0）
  - `[esp+0x18]` = arg1 = **n**；`[esp+0x1c]` = arg2 = **out[]**
- 门：`obj10[+0x30] != 0`（0x100038dc）、`this[+4] != 0`（0x100038eb）、`Authorize(0xEA62)`（0x100038f8）。
  ★ **不读 obj8/Rec20**；★ **不读 arg3/arg4**（ZjOrder 会传但本函数从不使用）。
- 失败出口 0x100038e0（`or eax,-1`）；成功出口 0x10003a78（`xor eax,eax`）。

### 2.2 算法（4 路展开 + 0x21 单步收尾）[A]

```
counter = 0 ; lastValue = 0                       // 0x10003903 xor ecx,ecx
for each Item21[k] in order:                      // stride 0x21
    f = [item+0x04]                               // flags
    if (f & 1):                                   // bit0 = 有效项
        if (0 <= [item+0x1d] < n):                 // barIdx
            out[ [item+0x1d] ] = (double)counter   // fild [esp+0x10]; fstp out[ecx*8]
        lastValue = [item+0x00]                    // value
        counter = 0
    elif (f & 4):                                  // bit2 = 已配对 Zj 项
        if ([item+0x00] != lastValue):             // 与上一个 bit0 项方向不同
            counter += 1
```

证据地址（四路 + 尾部一致）：

| 路 | bit0 判定 | 写入 | bit2 判定 | 递增 |
|---|---|---|---|---|
| 0 | 0x10003928 `test dl,1` | 0x10003942 `fstp [edx+ecx*8]` | 0x10003952 `test dl,4` | 0x1000395c `add [esp+0x10],1` |
| 1 | 0x10003964 | 0x1000397d | 0x1000398d | 0x10003997 |
| 2 | 0x1000399f | 0x100039b9 | 0x100039c9 | 0x100039d3 |
| 3 | 0x100039db | 0x100039f5 | 0x10003a05 | 0x10003a0f |
| 尾 | 0x10003a38 | 0x10003a51 | 0x10003a61 | 0x10003a6b |

（每路 bit0 分支同时做 `mov ecx,[..-0x3e]` 记 lastValue + `mov [esp+0x10],0` 清零：0x10003945/0x10003948、0x10003980/0x10003983 …）

### 2.3 ★ cnt 单位判定 —— docs/27 §6.2 [C] 结案 [A]

**结论：`cnt` 的计数单位 = Item21 条目数；"bar 数"假设静态证伪。**

三条硬证据：
1. **步进恒为 0x21**：主循环 `add eax,0x84`（=4×0x21）、尾部 `add eax,0x21` / `add [ecx],0x21`；计数器**每个条目至多 +1**（0x1000395c 等）。
2. **代码中无任何 bar 差值运算**：函数全程**从不读取 barIdx 之外的坐标**，更没有 `barIdx[k] - barIdx[k-1]` 之类的差。⇒ cnt 与 K 线根数无因果链。
3. **Item21 的粒度 = 分型记录**：docs/28 §1.4 已确权 obj_c raw 每检出一个分型产一条 29B 记录，Item21（stride 0x21）由 obj_c raw 填充（docs/27 T3）⇒ **Item21 条目 ≡ 分型/Zj 记录**。

⇒ 语义：`out[barIdx]`（在有效项处写出）= **自上一个有效项以来、满足「bit2 ∧ 方向翻转」的 Zj 项个数**。
即 **cnt 是"分型/Zj 项计数"（近似"笔数"量纲），不是"bar 数"**。

### 2.4 对 docs/27 门条件的语义修正 [A]

docs/27 记 ZjOrder 的过滤门为 `|ZjNum[barIdx]| ≥ THR`，当时 THR 语义 [C]。现由 §2.2 可知 `ZjNum[*]` 是**条目计数**，故：

> **THR 的语义 = "在相邻两个有效分型之间至少经历 THR 个 Zj 项"，而非"至少隔 THR 根 K 线"。**

ZjOrder 里的 `fabs`（0x100032c3）对非负计数值属冗余但无害。

### 2.5 最小可验证实验（并入 frida 预备包，未运行）[设计]

挂 `0x100038b0` 出口，dump `out[]` 的非零项及其下标，同时记录同一次运行中 `obj10[+0x30]` 的 Item21 数组；
将"非零项 = 计数器值"与"该 bar 与上一有效 bar 的实际 bar 距离"对比：**若二者不相等即实证"非 bar 数"**（预期不相等）。
一条命令可用：`tools/re-inventory/nchbi/frida_dump_out.js`（脚本挂点已含本函数），运行说明见 `frida_nchbi3.md`。

---

## 三、T3 —— 同族总览与文档一致性微修

### 3.1 NChB* 族总览（一表结清）

来源：`family_slots_full.txt`（槽 ↔ 导出名 ↔ chlib 地址）+ 本批新证据。

| 导出 | vt 槽 | 地址 | 授权码 | 容器依赖（读） | 输出语义 | 文档 |
|---|---|---|---|---|---|---|
| `NChBi` | +0x34 | 0x10002340 | EA62 | obj8[+0x1c/+0x28] + obj10[+0x30/+0x3c]；**写 obj10[+0x28]** | 主计算：Item21/Rec20 重排与端点填充 | docs/25, 26 |
| `NChBiSta` | +0x38 | 0x10002770 | EA61 | obj8[+0x1c] + obj10[+0x30] | 结构展开：`out = value×{1,2,10}`；段C 唯一 ±3 | docs/26 |
| `NChBiSta2` | +0x3c | 0x10002900 | EA61 | obj8[+0x1c/+0x28] + obj10[+0x30/+0x3c] | 兄弟展开器（含多条 fcom/fcomp 真比较） | docs/26 |
| `NChBiZj` | +0x44 | 0x10002ea0 | EA61 | obj10（不读 obj8） | `out[Item21.barIdx] = value`（bit2） | docs/27 |
| **`NChBiZj3`** | +0x48 | **0x10002fc0** | **EA62** | obj8 + obj10（**只读**） | `out[Rec20[recIdx].endBar+1] = value`（bit2） | **docs/29** |
| `NChBiZjOrder` | +0x4c | 0x10003180 | EA61 | obj8 + obj10 + 临时 vector | ZjNum 过滤后 `out[Rec20[recIdx+1].startBar] = value` | docs/27 |
| `NChBiFxNum` | +0x58 | 0x10003680 | EA62 | obj10（不读 obj8） | 计数器→out[]（4 路展开，含 -0x1d 偏移常量）[B] | docs/29 |
| **`NChBiZjNum`** | +0x5c | **0x100038b0** | **EA62** | obj10（不读 obj8） | 计数器：见 §二 | **docs/29** |
| `NChBiSpeed` | +0x60 | 0x10003a90 | EA62 | obj8[+0x1c/+0x28] + obj10[+0x30/+0x3c] | `out[..] = |value|`（fabs；额外门 `obj8[+0x28]!=0`） | docs/29 |

**观察**：
- **授权码按子功能分组**：EA61 = {Sta, Sta2, Zj, ZjOrder}；EA62 = {NChBi, Zj3, ZjNum, FxNum, Speed}。
  ⇒ 本族**并非统一授权**；Zj(EA61) 与 Zj3(EA62) 跨组，说明二者可独立许可。
- **容器契约**：全族输入只来自 obj8（Rec20）与 obj10（Item21）两处；其中 **Zj / ZjNum / FxNum 只吃 obj10** ⇒ 这三支仅需 `NCHBI` 一步即可运行（无需依赖 Rec20）。
- 族内**无跨函数 call 复用**：共享的是**内联内核**（Item21 遍历 + 越界三段式 + memset 前置 + 授权调用形态），非函数调用。

### 3.2 docs/26 §九 表述微修 [A]

- 原文（docs/26 行 416）：`> 已写入看板 \`docs/19\` 的 \`NCHBI.next\`。`
- 看板 docs/19 的实际格式为每目标条目下的 `> 下一步: <文本>`，**不存在 `NCHBI.next` 这一字段名**（第三方评审指出）。
- 修正为：`> 已写入看板 \`docs/19\` 的「NChBi」条目「下一步」。`（1 行改动，与看板保持一致。）

---

## 四、勘误与待仲裁

### 4.1 勘误（本批自查）[A]

1. **栈基点必须逐代码点换算**：Zj3 的 local0（nRec）写于 0x10002fea（esp=P-0x24），local1（Item21base）写于 0x10002ffc（esp=P-0x18）；
   两者地址不同（P-8 与 P-4），若按同一 esp 基点读会串槽。已在 §1.1 表格显式标注各自基点。
2. **Zj3 授权码不是 0xEA61**：上一批 docs/27 记录 Zj/ZjOrder = EA61，易被误推为"Zj 族统一 EA61"；实测 **Zj3 = 0xEA62**（0x10003020）。本批已在 §3.1 建"授权码分组"表消除该误导。
3. **ZjNum 不读 arg3/arg4**：ZjOrder 传 4 参给 vt[+0x5c]，但 ZjNum 仅用 arg1/arg2 —— docs/27 曾把 arg3 记为"透传给 ZjNum 的实参"，实际该实参**未被子函数使用**。

### 4.2 待仲裁 [B]/[C]

- **[A] 本体行为已确定**，以下为命名/上位语义：
  - **[B] "Zj3" 中 "3" 的含义**（§1.5）：倾向枚举序号；坐实需查 `CalcProc_NChBiZj3`(0x10012d90) 包装体。
  - **[B] `Rec20[k].endBar + 1` 与 `Rec20[k+1].startBar` 是否恒等**：Zj3/ZjOrder 目标同槽的前提是**段连续**。
    本轮未验证 Rec20 的连续性不变式（属 obj8 填充方职责，见 docs/28 T1/T2）；若不连续，Zj3 与 ZjOrder 目标就**不同**。**建议列为第六批必查项。**
  - **[B] cnt 的增量条件语义**：`bit2 ∧ ¬bit0 ∧ value ≠ lastValue` —— "value 翻转"是否等价于"笔方向交替"，需对照 docs/28 §2.8 的 flags 位台账与配对器（0x1000b000）产出。
  - **[C] `NChBiFxNum`（0x10003680）未逐条展开**：已确权 授权 EA62 / 只读 obj10 / 输出为计数器；其与 ZjNum 的差异段（是否有额外累计/分段）留待后续。
  - **[C] `NChBiSpeed`（0x10003a90）未逐条展开**：已确权 授权 EA62 / 读 obj8+obj10 / 输出 `|value|`；其"速度"语义（是否基于 Rec20 相邻段价差）留待后续。
  - **[C] ZjNum/Zj3 的 arg1（n）在 TAFLib 侧由谁提供**：本轮未展开上层包装体。

---

## 五、可复现命令

```bash
DLL=ronglide-app/chlib.dll
PY=C:/Users/Administrator/Documents/a_conda/python.exe

# 1) 本批两个主角
$PY tools/re-inventory/disasm_func.py 0x10002fc0 --max 0x700 --dll "$DLL" \
    -o tools/re-inventory/nchbi/chlib_worker_10002fc0.txt      # Zj3
$PY tools/re-inventory/disasm_func.py 0x100038b0 --max 0x700 --dll "$DLL" \
    -o tools/re-inventory/nchbi/chlib_worker_100038b0.txt      # ZjNum

# 2) x87 条件表
$PY tools/re-inventory/x87_sim.py tools/re-inventory/nchbi/chlib_worker_10002fc0.txt \
    -o tools/re-inventory/nchbi/cond_chlib_10002fc0.txt        # => 0 conditions

# 3) 族总览用到的三支（本轮已跑）
$PY tools/re-inventory/disasm_func.py 0x10003680 --max 0x500 --dll "$DLL" \
    -o tools/re-inventory/nchbi/chlib_worker_10003680.txt      # FxNum
$PY tools/re-inventory/disasm_func.py 0x10003a90 --max 0x500 --dll "$DLL" \
    -o tools/re-inventory/nchbi/chlib_worker_10003a90.txt      # Speed

# 4) 槽位/导出名映射（已入仓）
$PY tools/re-inventory/nchbi/map_family_slots.py -o tools/re-inventory/nchbi/family_slots.txt

# 5) 看板刷新
$PY tools/re-inventory/verify_status.py --write
```

---

## 六、下一步（第六批）建议

**NChBi 族已完成 9 支中的 6 支深解剖**（NChBi / Sta / Sta2 / Zj / Zj3 / ZjOrder / ZjNum ≈ 7 支），剩余 FxNum、Speed 为计数器/绝对值类（结构同构、边际成本低）。

**推荐（首选）：NChBi 族收官** —— 补完 `NChBiFxNum`(0x10003680)、`NChBiSpeed`(0x10003a90)，并闭环 §4.2 的
**Rec20 段连续性不变式**（决定 Zj3/ZjOrder 目标是否同槽）。理由：同族、依赖已全部确权、单位收益最高，1 批可把整族静态覆盖度推到 ~100%。

**次选：NChZs 族**（`NChZs` / `NChZsG` / `NChZsBs12`，槽 +0x78…+0xb4，授权码 EA61–63）
—— 覆盖面更大（中枢/走势），且本批/第四批已解出的共享基础设施（`0x1000b000` 配对、obj8/obj10 契约）可直接复用，方法学迁移成本低。

**第三顺位：CHBI 第六批（481 条件）** —— 与 NChBi 共用 chlib 基础设施，边际成本在本批后进一步下降，可作第三顺位。

> 另：若用户在场，**优先跑 frida 预备包**（`frida_nchbi3.md` + `frida_dump_out.js`），可一次性把本批 §4.2 的 [B]/[C]（Zj3/ZjOrder 同槽、cnt 非 bar 数）升为运行时实证 [A]。
