# NChBi 第五批 WIP（Zj3 / ZjNum 补完 + 族总览）

起点：origin/old1 = `4242308`（第四批已验收）。本轮 frida 不运行，主攻静态。

---

## WIP-A T1 NChBiZj3（vt[+0x48] = 0x10002fc0）

证据：`chlib_worker_10002fc0.txt`（153 insn，`ret 0x10`）、`cond_chlib_10002fc0.txt`（**0 x87 条件**）。

### A1 签名与入口 [A]
- `__thiscall chlib`，`ret 0x10` = **4 个 dword 参数**；本函数仅用 arg1/arg2（尾部两参数未读）。
- 栈换算（sub 8 → push 4 reg → push 3(cdecl memset) → add 0xc，循环内 esp=P-0x18）：
  - arg1 = `[esp+0xc]`(入口 P+4) = **n（bar 数）**；arg2 = `[esp+0x10]`(P+8) = **out[]（double*）**
  - local0(P-8) = nRec = `obj8[+0x28]`（Rec20 计数，line17 于 esp=P-0x24 写入）
  - local1(P-4) = Item21 base = `obj10[+0x30]`（line23 于 esp=P-0x18 写入）
  - 循环内：`[esp+0x10]`=nRec、`[esp+0x14]`=Item21base、`[esp+0x1c]`=n(arg1)、`[esp+0x20]`=out(arg2)

### A2 四道门 + 授权 [A]
1. `memset(out, 0, n*8)`（line1-13，thunk 0x1001494c）
2. `Rec20base(obj8[+0x1c]) != 0`（line14-15,24）
3. `Item21base(obj10[+0x30]) != 0`（line18-19,25-26）
4. `ch_auth(this[+4]) != 0`（line27-28）
5. `Authorize(0xEA62)`（line29-35，`mov eax,[edx+4]; push 0xea62; call eax`）
   ★ **授权码 = 0xEA62**（与 NChBi/0x10002340 同；**与 NChBiZj(0xEA61) 不同！**）
失败出口 line147-153（`or eax,-1`），正常出口 line140-146（`xor eax,eax`）。

### A3 主体：Item21 遍历（4 路展开）+ bit2 门 [A]
- 循环以 `eax += 0x84`（132 = 4×33）展开，第 k 轮处理 `Item21[j..j+3]`；尾部 line113-139 以 `0x21` 单步收尾。
- 每条 Item21（stride 0x21）判定：
  - `flags = [item+4]`，`test byte [..], 4` → **bit2**（line45/61/77/93/121）
  - 门通过后：`idx = [item+9]`（recIdx）→ 越界保护 `0<=idx<nRec`
  - `slot = Rec20[idx][+0x04] + 1`（`shl ecx,5` + `[ecx+edi+4]` + `add ecx,1`；Rec20 stride 0x20）
  - 越界保护 `0<=slot<n`（`js` + `cmp [esp+0x1c]`）
  - `fild dword [item+0x00]`（int32 → double）`fstp qword [out + slot*8]`

### A4 语义 [A]
> **NChBiZj3 = 「对每个 flags.bit2 置位的 Item21：`out[ Rec20[recIdx].endBar + 1 ] = (double)value`」**
- 与 **NChBiZj** 唯一差别 = **目标下标**：Zj 用 `Item21[+0x1d]`（barIdx 直取）；Zj3 用 `Rec20[recIdx][+0x04]+1`。
- 与 **NChBiZjOrder** 目标下标**同槽**（若 Rec20 段连续则 `Rec20[k].endBar+1 == Rec20[k+1].startBar`），但门不同：
  ZjOrder = `bit0 ∧ ¬bit3 ∧ |ZjNum[barIdx]|≥thr`；Zj3 = `bit2`（且不需 ZjNum / 不调 vt[+0x5c]）。
- 写入值恒 `(double)value ∈ {±1}`，**无 ×3 缩放** ⇒ 再次佐证 docs/26 §6「±3 只出自 NChBiSta 段C」。
- 读取容器：**obj8（Rec20，只读）+ obj10（Item21，只读）**；不写任何容器（纯散射器）。

### A5 "Zj3" 的 3 的含义 [B]
- 函数体内**无字面常量 3**（全部立即数：0xEA62 / 0x21 / 0x84 / 0x20 / 0x04 / 0x09 / 0x1d …）。
- 槽位相邻（+0x44/+0x48/+0x4c）⇒ **"3" 更可能是枚举里的第 3 个变体名（Zj / Zj3 / ZjOrder）**，非运行参数。
- 备选举证假设：写入点 = 「段尾 bar 的下一个 bar」= **下一笔的起点**，与缠论"分型/笔三段结构"里的「第 3 个位置」契合；**无直接证据**，标 [B]。
- 待仲裁：如需坐实，查 TAFLib 侧 `CalcProc_NChBiZj3`(0x10012d90) 的入参构造（是否多传一个整型参数）——本轮未展开。

---

## WIP-B T2 NChBiZjNum（vt[+0x5c] = 0x100038b0）—— cnt 语义静态侧结清

证据：`chlib_worker_100038b0.txt`（161 insn，`ret 0x10`）。

### B1 签名与门 [A]
- 栈：`push ecx` 分配 1 个 local（P-4）。循环内 `[esp+0x10]`=local(计数器)、`[esp+0x18]`=n(arg1)、`[esp+0x1c]`=out(arg2)。
- `memset(out,0,n*8)`；门：`Item21base(obj10[+0x30])!=0`、`ch_auth!=0`、`Authorize(0xEA62)`。
  ★ **不读 obj8/Rec20**（与 Zj3/ZjOrder 不同）。
- **实际只读 arg1/arg2**（arg3/arg4 由 ZjOrder 传入但本函数从不读）。

### B2 算法（4 路展开 + 步长 0x21）[A]
```
counter = 0 ; lastValue = 0            ; ecx 初值 0 (line37)
for each Item21[k] in order:           ; stride 0x21
    f = flags[k]                       ; [+0x04]
    if (f & 1):                        ; bit0 = 有效项
        if (0 <= barIdx[k] < n):       ; barIdx = [+0x1d]
            out[barIdx[k]] = (double)counter
        lastValue = value[k]           ; value = [+0x00]
        counter = 0
    elif (f & 4):                      ; bit2 = 已配对 Zj 项
        if (value[k] != lastValue):    ; 与上一个 bit0 项方向不同
            counter += 1
```
- 证据地址：bit0 分支 line46-59 / 65-78 / 84-97 / 103-116 / 133-146（`test dl,1` → `fild [esp+0x10]` → `fstp out[ecx*8]`）；
  bit2 分支 line60-64 / 79-83 / 98-102 / 117-121 / 147-151（`test dl,4` → `cmp value,ecx; je skip; add [esp+0x10],1`）。

### B3 ★ cnt 单位判定（docs/27 §6.2 [C] 结案）[A]
- **cnt 的计数单位 = Item21 条目数**：循环恒以 `0x21` 步进，**每个条目至多 +1**；代码中**没有任何 bar 差值/坐标运算**参与计数。
- ⇒ **cnt ≠ "bar 数"**（不是 `barIdx` 之差，也不是 K 线根数）。**以 bar 为单位的假设静态证伪**。
- Item21 条目本身对应 **分型/Zj 记录**（docs/28 §1：obj_c raw 每检出一个分型产一条 29B 记录 → Item21 同粒度）
  ⇒ 语义上 **cnt ≈ "两个有效点之间的 Zj 项（分型）计数"**（[A] 单位=条目，[B] 条目=分型，因 fill 粒度由 docs/28 佐证）。
- 输出 = `(double)counter`（非负整数），写在**有效项(bit0)所在 barIdx** 处；其余位置保持 0（memset 初值）。

### B4 ZjNum ↔ ZjOrder 关系 [A]
- ZjOrder（0x10003180 line22-51）先 `vector<double>::resize(n)`（0x10006c00）再 `vt[+0x5c](this, n, vec.begin, arg3, arg4)`，
  然后以 `|ZjNum[barIdx]| ≥ thr` 过滤。→ **vec[k] = ZjNum 输出 = 该 bar 处的计数器值**。
- 计数单位既非 bar，则该阈值语义 = "**在两次有效分型之间至少经历 thr 个 Zj 项**"，而非"至少隔 thr 根 K 线"。**这是对 docs/27 门条件语义的修正**。
- 最小可验证实验（与 frida 预备包合并，一条挂点即可坐实）：挂 0x100038b0 出口，dump `out[]` 非零项 + 对应 barIdx；与"bar 距离"对比 ⇒ 若二者不等即证"非 bar 数"。

### WIP-END-B

---

## WIP-C T3 同族总览 + 文档一致性微修

### C1 NChB* 族槽位全表（来源 family_slots_full.txt + 本批新证据）[A]

| 导出 | vt 槽 | chlib 地址 | 授权码 | 容器依赖（读/写） | 输出语义（一句） | 文档 |
|---|---|---|---|---|---|---|
| NChBi | +0x34 | 0x10002340 | **EA62** | 读 obj8[+0x1c/+0x28] + obj10[+0x30/+0x3c]；**写 obj10[+0x28]** | 主计算：以 Rec20 记录重排/填充 Item21 端点 | docs/25,26 |
| NChBiSta | +0x38 | 0x10002770 | **EA61** | 读 obj8[+0x1c] + obj10[+0x30] | 结构展开器：out = Item21.value 缩放(×1/×2/×10) + 段C 唯一 ±3 | docs/26 |
| NChBiSta2 | +0x3c | 0x10002900 | **EA61** | 读 obj8[+0x1c/+0x28] + obj10[+0x30/+0x3c] | 兄弟展开器，含真实 x87 比较（fcom/fcomp 多条） | docs/26 |
| NChBiZj | +0x44 | 0x10002ea0 | **EA61** | 读 obj10[+0x30/+0x3c]（**不读 obj8**） | 散射：`out[Item21.barIdx] = (double)value`（bit2 门） | docs/27 |
| **NChBiZj3** | +0x48 | **0x10002fc0** | **EA62** | 读 obj8[+0x1c/+0x28] + obj10[+0x30/+0x3c]（**只读**） | 散射：`out[Rec20[recIdx].endBar+1] = (double)value`（bit2 门） | **docs/29（本批）** |
| NChBiZjOrder | +0x4c | 0x10003180 | **EA61** | 读 obj8+obj10；临时 vector | 先 ZjNum 灌 vec，再 `bit0∧¬bit3∧|vec[barIdx]|≥thr` 过滤 → `out[Rec20[recIdx+1].startBar]=value` | docs/27 |
| NChBiFxNum | +0x58 | 0x10003680 | **EA62** | 读 obj10[+0x30/+0x3c]（**不读 obj8**） | 计数器→out[]（4 路展开，含 -0x1d 偏移常量）；细节本轮未展开 [B] | docs/29 |
| **NChBiZjNum** | +0x5c | 0x100038b0 | **EA62** | 读 obj10[+0x30/+0x3c]（**不读 obj8**） | 计数器：见 §WIP-B（单位=Item21 条目） | **docs/29（本批）** |
| NChBiSpeed | +0x60 | 0x10003a90 | **EA62** | 读 obj8[+0x1c/+0x28] + obj10[+0x30/+0x3c] | `out[..] = |value|`（fabs + 额外门 `[obj8+0x28]!=0`） | docs/29 |

**授权码分组**（本批新证据，此前只知 NChBi=EA62 / Sta=EA61）：
- **EA61**: Sta, Sta2, **Zj**, **ZjOrder**
- **EA62**: NChBi, **Zj3**, **ZjNum**, **FxNum**, **Speed**
⇒ 授权码在本族内**按"子功能分组"而非全族统一**；Zj/ZjOrder（EA61）与 Zj3/ZjNum（EA62）跨组，说明二者不是同一许可单元。

**容器契约**：全部 9 支的输入来源只有两处 —— obj8（Rec20，stride 0x20，[+0x1c]=base/ [+0x28]=cnt）与 obj10（Item21，stride 0x21，[+0x30]=base /[+0x3c]=cnt）。
其中 **Zj / ZjNum / FxNum 只吃 obj10**（对 obj8 无依赖）⇒ 这三支可仅依赖 `NCHBI` 一步即可运行。

### C2 docs/26 §九 微修（第三方评审指出）[A]
- 原文（docs/26 行416）：`> 已写入看板 \`docs/19\` 的 \`NCHBI.next\`。`
- 看板实际格式（docs/19）：每个目标条目下用 `> 下一步: <文本>`，**并无 `NCHBI.next` 字段名**。
- 改为：`> 已写入看板 \`docs/19\` 的「NChBi」条目「下一步」。` —— 与看板实际表述一致（1 行）。

### WIP-END-C
