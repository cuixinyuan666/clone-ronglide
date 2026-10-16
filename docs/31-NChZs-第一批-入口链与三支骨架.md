# docs/31 — NChZs 族第一批（kickoff）：入口链 + 三支骨架解剖 + 复用度评估

> 派发：监控方 2026-10-17 06:10（NChZs 族第一批）
> 证据目录：`tools/re-inventory/nchzs/`；伪码：`pseudocode/nchzs.c`
> 口径：**frida 动态验证本轮不运行**（无人值守）；主攻静态骨架与链路确权。

---

## 〇、摘要

| # | 结论 | 置信 |
|---|---|---|
| S1 | **「+0x78 共享槽」之谜破**：`family_slots.txt` 把 5 支导出记作共享 `+0x78` 是**工具误映射**；实测只有 **NChZs 与 NChZs_L2** 真共享 `0x100045f0` | **[A]** |
| S2 | 误映射根因：`map_family_slots.py` 用**固定 0x220 字节窗口**反汇编，短包装（NChDuanKh/Kl/Kd）窗口**越界侵入相邻 NChZs 包装**，撞到 `[edx+0x78]` | **[A]** |
| S3 | NChDuanKh/Kl/Kd 真实槽 = **+0x6c/+0x70/+0x74** → chlib **0x100042f0/0x100043e0/0x100044d0**（K 线三兄弟，与本族无关） | **[A]** |
| S4 | **T1** NChZs 主入口 = chlib **0x100045f0**（161 B，`ret 0x10`，4 参）；容器 = `this[+0x18]`；**授权码在外层包装**（EA61 首层 / EA63 后续，`this[+0xb8]` 层计数器自增） | **[A]** |
| S5 | **T2** NChZsG/D/Bs12/Bs3 均为**极薄包装**（9 行）→ 共享 worker **0x10006800 / 0x10006860 / 0x100068c0** | **[A]** |
| S6 | 0x10006800(G) 与 0x10006860(D) **仅一处偏移不同**（`fld [ptr-0x3c]` vs `[ptr-0x30]`）⇒ **G=ZG(中枢上沿) / D=ZD(中枢下沿)** 价带逐 bar 展开 | **[A]** 结构 / **[B]** 命名 |
| S7 | Bs12/Bs3 = 同一 worker 0x100068c0 的**模式开关**（字面 12 vs 3，选取逻辑不同） | **[A]** |
| S8 | **T3** 族 17 支全表（槽/地址/授权码/元素依赖）落 `family_recon.txt`；授权码四组：EA61 / EA62 / EA63+EA61 / 分层 | **[A]** |
| S9 | **复用度**：Fetch6Buffers 0x10006cc0、memset 0x1001494c、Authorize 0x10014e60、包装模板**全部复用**；但**元素结构不复用**（段 stride 0x5d / 分类 stride 0x18 ≠ Item21 0x21） | **[A]** |

---

## 一、T1 —— NChZs 入口链 + 「+0x78 共享槽」之谜

### 1.1 共享关系实测（决定性证据）[A]

对 TAFLib 包装层逐支重解（`taf_10013*.txt`），并读 chlib 虚表（`tools/re-inventory/nchzs/dump_vt_nchzs.py` → `vt_nchzs.txt`）：

| 导出包装 VA | 真实 vt 槽 | chlib 实现 | family_slots 原记 |
|---|---|---|---|
| 0x100130c0 NChDuanKh | **+0x6c** | 0x100042f0 | ~~+0x78~~ |
| 0x10013140 NChDuanKl | **+0x70** | 0x100043e0 | ~~+0x78~~ |
| 0x100131c0 NChDuanKd | **+0x74** | 0x100044d0 | ~~+0x78~~ |
| 0x10013240 **NChZs** | **+0x78** | **0x100045f0** | +0x78 ✓ |
| 0x100132d0 **NChZs_L2** | **+0x78** | **0x100045f0** | +0x78 ✓ |
| 0x10013370 NChZsG | +0x7c | 0x100046a0 | +0x7c ✓ |
| 0x100133e0 NChZsD | +0x80 | 0x100046c0 | +0x80 ✓ |

**⇒ 真共享只有 2 支（NChZs / NChZs_L2），不是 5 支。** 假设「同一实现按参数分支」对本族不成立。

### 1.2 误映射根因 [A]

`tools/re-inventory/nchbi/map_family_slots.py`：
- `find_slot()` 只认 `mov <reg>,[esi+0xbc]` → 其后 **5 条**内 `mov edx,[edx+0xNN]`；
- `main()` 对每个导出固定反汇编 **0x220 字节**（`disasm_range(..., va, 0x220)`）。

三支 NChDuanK* 包装把 vtable 载入 **eax**（`mov eax,[ecx]; mov eax,[eax+0x6c]`）⇒ 本函数内**无 edx 形态**；
但 0x220 窗口（如 0x100130c0+0x220 = **0x100132e0**）**越界覆盖到相邻 NChZs 包装 0x10013240**，
而后者恰有 `mov edx,[edx+0x78]` ⇒ 三支全部被回填成 **+0x78**。
（0x10013140/0x100131c0 同理：窗口 +0x220 均 ≥ 0x10013360 > 0x10013240。）

> 佐证：`family_slots.txt` 中这 3 支与 NChZs 挤在同一行（该文件 line 87），是同一误值的复制。

### 1.3 NChZs 签名 / 门表 / 授权 [A]

**chlib 0x100045f0**（区间 `0x100045f0–0x10004691`，161 B，`ret 0x10` = **4 参**，x87 条件 **0**）
证据：`chlib_100045f0.txt`、`cond_chlib_100045f0.txt`。

| 顺序 | 地址 | 判据 |
|---|---|---|
| G1 | 0x10004605 | `edi = this`（ecx） |
| G2 | 0x1000461d | `memset(a3[+4], 0, n*8)`（`call 0x1001494c`；n=a1, 8=sizeof(double)） |
| G3 | 0x10004629 | `if (!a3[0]) → -1` |
| G4 | 0x1000462d | `if (!a3[8]) → -1` |
| G5 | 0x10004631 | `this->[+0x18]->vt[+4]()`（**无参**虚调用；非 `push code` 形态）|
| G6 | 0x10004650 | `this->[+0x18]->vt[+0xc](a1, ?, a3[0], a3[8], a4)`（5 参「真工作」虚调用）|
| G7 | 0x1000465d | `call 0x1000e990(a1, *(?))`（2 参）|
| G8 | 0x1000466a | `this->[+0x18]->vt[+8]()` 判空 → -1 |
| G9 | 0x1000467c | `call 0x10006700(this)` |

**⇒ 0x100045f0 是「参数 → this[+0x18] 引擎」的转发器**，授权不在 chlib 内（G5 为无参虚调用）。

**TAFLib 包装授权（0x10013240 NChZs / 0x100132d0 NChZs_L2）[A]**
```
NChZs:
  auth = (this[+0xb8] <= 0) ? Authorize(0xEA61) : Authorize(0xEA63);   // 0x10014e60
  if (!auth) { memset(out,0,n*8); return 0; }                          // 0x1006bd22
  buf = Fetch6Buffers(0x10006cc0);
  this[+0xb8] += 1;                                                    // ★ 层计数器
  return vt[+0x78](arg1, arg2, &buf, arg3);                            // 4 参

NChZs_L2 (同一 vt[+0x78]):
  c = this[+0xb8]
  c<=0 -> Authorize(0xEA61)
  c==1 -> Authorize(0xEA62)
  c>=2 -> Authorize(0xEA63) ∧ Authorize(0xEA62)
  ...（成功路径同上）
```
⇒ **`this[+0xb8]` = 层计数器**，授权码随层递进；NChZs_L2 = 「第二级」变体（额外要 EA62）。

---

## 二、T2 —— NChZsG / NChZsBs12 骨架（含 NChZsD / NChZsBs3 对照）

### 2.1 四支薄包装 [A]
证据：`chlib_100046a0.txt` / `chlib_100046c0.txt` / `chlib_100046e0.txt` / `chlib_10004700.txt`（各 9 行）。

```
NChZsG  (0x100046a0): eax=arg1; esi=this[+0x18]; edi=arg2; call 0x10006800
NChZsD  (0x100046c0): eax=arg1; esi=this[+0x18]; edi=arg2; call 0x10006860
NChZsBs12(0x100046e0): eax=arg1; edi=arg2; push 0xc; push eax; eax=this[+0x18]; call 0x100068c0
NChZsBs3 (0x10004700): 同上, push 3
```
⇒ **G/D 仅 worker 地址不同；Bs12/Bs3 仅字面量不同（12 vs 3）**。四支皆 `ret 0x10`。

### 2.2 worker 0x10006800(G) / 0x10006860(D) —— 中枢价带展开 [A]
证据：`chlib_worker_10006800.txt` / `chlib_worker_10006860.txt`（各 31 行，`ret`）。

```
memset(out, 0, n*8)                         // 0x1001494c
base = obj[+0x30]; cnt = obj[+0x3c]         // 与 NChBi obj10 同偏移
if (!base || !cnt) return -1
ptr = base + 0x55                           // i=0 的循环指针
do {
  if (byte[ptr-0x41] & 1) {                 // 段 flags.bit0 = 有效
     A = [ptr]; B = [ptr+4]                 // 段覆盖的 bar 区间
     do { out[A] = (double)<价>; A++ } while (A <= B)
  }
  ptr += 0x5d                               // ★ stride 0x5d
} while (--cnt)
```

| worker | 价字段（相对 ptr） | 判定 |
|---|---|---|
| 0x10006800 (G) | `fld qword [ptr-0x3c]` | **ZG 中枢上沿** |
| 0x10006860 (D) | `fld qword [ptr-0x30]` | **ZD 中枢下沿** |

> **两支 worker 逐句同构、唯一区别 = 上述一处偏移** —— 这是最干净的「同族孪生」证据。

**段记录布局（stride 0x5d = 93 B）**

| 相对 ptr | 绝对(rec_i = base+i*0x5d, ptr=rec+0x55) | 类型 | 语义 |
|---|---|---|---|
| ptr-0x41 | +0x14 | u8 | flags（bit0 有效）|
| ptr-0x3c | +0x19 | f64 | **ZG**（G 用）|
| ptr-0x30 | +0x25 | f64 | **ZD**（D 用）|
| ptr-0x14 | +0x41 | i32 | barIdx（Bs worker 用）|
| ptr     | +0x55 | i32 | A（区间起）|
| ptr+4   | +0x59 | i32 | B（区间止）|

> A@+0x55、B@+0x59（+0x59+4 = 0x5d 恰为 stride 尾）**强支持**绝对偏移假设；
> rec+0x00..0x13 的 20 B 头部（疑嵌套子结构）语义 **[C]**。

### 2.3 worker 0x100068c0 —— Bs12/Bs3 模式化标志展开 [A]
证据：`chlib_worker_100068c0.txt`（81 行，`ret 8` = **2 参**：`(arg1=n, arg2=mode)`）。

```
memset(out, 0, n*8)
base = obj[+0x40]; cnt = obj[+0x2c]          // ★ 另一组容器偏移, 元素 stride 0x18
if (!base || !cnt) return -1
ptr = base + 0x14
do {
  if (mode == 12) {                          // Bs12: 3 选 1
     v = s8[ptr+1] ? s8[ptr+1] : (s8[ptr] ? s8[ptr] : s8[ptr+3]);
  } else {                                   // Bs3: 按 span 缩放
     dl = s8[ptr+2]; p = [ptr-8];
     if (dl != 0 && p != 0) {
        span = [p+0xc] - [p+8] + 1;
        v = dl * (span > 3 ? 1 : 10);        // 0xfffffff7 位技巧 => 1 或 10
     }
  }
  idx = [ptr-0x14];
  if (0 <= idx < n) out[idx] = (double)v;
  ptr += 0x18
} while (--cnt)
```
⇒ Bs12/Bs3 = **分类标志的逐 bar 散射器**；12/3 为**模式开关**（不同选取/缩放逻辑）。
「Bs」命名 **[C]**（字面 3 与 12，疑「笔数」分类）。

---

## 三、T3 —— 族侦察表 + 复用度评估

**全表 → `tools/re-inventory/nchzs/family_recon.txt`**（17 支：16 槽 + NChZs/NChZs_L2 共享）。

### 3.1 授权码分组（`push 0xeaNN` 直证）[A]

| 组 | 成员 |
|---|---|
| **EA61** | NChZsG / NChZsD / NChZsBs12 / NChZsBs3 / NChZsBreach / NChZsL2M / NChFjZsNum（+ NChZs 首层） |
| **EA63 + EA61** | NChZsFj / NChZsDg / NChZsHLTurn |
| **EA61(层0) / EA63(层>0)** | NChZs |
| **EA61/EA62/EA63 分层** | NChZs_L2 |
| **EA62** | NChZsSel / NChZsSelPri / NChZsSelSlPri / NChZsSelSpPri |

### 3.2 复用度评估 [A]

| 设施 | 复用 | 证据 |
|---|---|---|
| Fetch6Buffers `0x10006cc0` | ✓ | NChZs/NChZs_L2 包装（同 NChBi 包装层）|
| `memset` thunk `0x1001494c` | ✓ | 0x100045f0 / 三个 worker / Breach / NChFjZsNum |
| TAFLib `Authorize` `0x10014e60` | ✓ | 授权形态 `push code; call 0x10014e60` 与 NChBi 族一致 |
| TAFLib 包装模板 | ✓ | `this[+0xbc]`=ch_api*；`this[+0xb8]`=层计数；失败 `memset+ret 0` |
| 容器访问器偏移 | ~ | `[+0x30]`=base/`[+0x3c]`=count 与 NChBi obj10 **同偏移**（作者约定）|
| **元素结构** | **✗** | NChZs 段 stride **0x5d**、分类 stride **0x18** ≠ Item21 **0x21** |
| 配对器 `0x1000b000`/`0x1000a250` | ? 未见 | 本批函数未引用 **[C]** |
| 新 helper | ? | `0x1000e990`（转发器用）、`0x1000eb80`（Sel 用）**[C]** |

> **判定：方法学与工具链复用成立、数据结构需新解。** NChZs 引擎对象 `this[+0x18]` 是**独立类**（多数组容器：段 stride 0x5d + 分类 stride 0x18）。
> ⇒ 中枢族「中枢 = 笔段再聚合」的结构假设方向正确，但**不能直接照搬 obj8/obj10 的 stride**。

---

## 四、勘误与待仲裁

### 4.1 勘误 [A]
1. **`nchbi/family_slots.txt` 槽号错误**：NChDuanKh/Kl/Kd 记 +0x78，实为 +0x6c/+0x70/+0x74（§1.2 根因）。
   —— 未修改原文件（属 NChBi 批次证据）；权威修正见本批 `family_recon.txt` + `dump_vt_nchzs.py`。
2. **「5 支共享 +0x78」为假象**：真共享 = NChZs/NChZs_L2 两支。
3. **NChZs 授权码分层**：非单一码；EA61(首)/EA63(后续)，由 `this[+0xb8]` 层计数决定（docs/19 记「EA63」为概括值，成立）。

### 4.2 待仲裁 [B]/[C]
- **[B]** 段记录绝对偏移（`rec = base + i*0x5d`，ptr=rec+0x55）——凭「B 收尾恰为 stride 尾」推断，需生产者复核。
- **[C]** 段 rec+0x00..0x13 的 20 B 头部（疑似内嵌子结构）语义。
- **[C]** `this[+0x18]` 引擎对象类型与构造点（本批未查 ctor）。
- **[C]** 「G/D」= ZG/ZD、「Bs」命名（字面 3/12）——几何/名称推断，无字符串证据。
- **[C]** `this[+0xb8]` 层计数器语义（调用次数？级别？）。
- **[C]** 本批未做动态验证（frida 预备包待用户在场）。

---

## 五、可复现命令

```bash
D=ronglide-app/chlib.dll ; T=ronglide-app/TAFLib.dll
PY=C:/Users/Administrator/Documents/a_conda/python.exe
cd tools/re-inventory/nchzs

# 1) 三支主角（chlib）
$PY ../disasm_func.py 0x100045f0 --max 0x500 --dll ../../$D -o chlib_100045f0.txt
$PY ../disasm_func.py 0x100046a0 --max 0x500 --dll ../../$D -o chlib_100046a0.txt
$PY ../disasm_func.py 0x100046e0 --max 0x500 --dll ../../$D -o chlib_100046e0.txt
# 2) 共享 worker
$PY ../disasm_func.py 0x10006800 --max 0x400 --dll ../../$D -o chlib_worker_10006800.txt
$PY ../disasm_func.py 0x10006860 --max 0x400 --dll ../../$D -o chlib_worker_10006860.txt
$PY ../disasm_func.py 0x100068c0 --max 0x400 --dll ../../$D -o chlib_worker_100068c0.txt
# 3) x87 条件
$PY ../x87_sim.py chlib_100045f0.txt -o cond_chlib_100045f0.txt   # => 0 条件
# 4) TAFLib 包装（槽 + 授权码）
$PY ../disasm_func.py 0x10013240 --max 0x140 --dll ../../$T -o taf_10013240.txt   # NChZs
$PY ../disasm_func.py 0x100132d0 --max 0x140 --dll ../../$T -o taf_100132d0.txt   # NChZs_L2
# 5) 权威虚表槽（本批新工具）
$PY dump_vt_nchzs.py -o vt_nchzs.txt
# 6) 看板刷新
$PY ../verify_status.py --write
```

---

## 六、下一步建议

**NChZs 族第一批 = 骨架确权完成**（入口链 + 三支 + 全表 + 复用度）。建议第二批三选一：

1. **（首选）NChZs 核心体完整逐条**：`0x100045f0` 的 G5/G6 两个虚调用落到 `this[+0x18]` 的
   `vt[+4]` / `vt[+0xc]` 实现（即引擎类真身），并解 `this[+0x18]` 的**构造点与容器填充生产者**
   —— 这决定「中枢段 stride 0x5d」的字段全貌，是后续所有 Zs 输出的地基。
2. **（次选）NChZsBs3 / Breach 逐条**：Bs3 worker 已见雏形（span>3 缩放），Breach(122 行)/SelPri 三兄弟(129 行×3) 体量小、产出快。
3. **（第三）NChZsL2M(695 行)** 单支深挖：族内最大实现，疑含多级别递归（配合 `this[+0xb8]` 层计数）。

> 若用户在场，**优先跑 frida 预备包**：挂 `0x100045f0` 出入口 dump `this[+0x18]` 的容器 base/count，
> 可一次性把 §4.2 的 [B]/[C]（段偏移、头部语义、层计数）升为 [A]。
