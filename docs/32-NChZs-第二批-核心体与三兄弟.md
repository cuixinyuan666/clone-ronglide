# NChZs 族第二批 —— 核心体引擎与三兄弟

> 批次：NChZs 族第二批（2026-10-17 06:28 派发）
> 上批：`docs/31-NChZs-第一批-入口链与三支骨架.md`（commits `51001bb` + `220c6df`）
> 口径：**frida 动态验证本轮未运行**（无人值守）；本批为静态确权。
> 结论置信标注：[A] 直证 / [B] 强推 / [C] 待仲裁

---

## 一、背景与目标

第一批已确权：`NChZs` / `NChZs_L2` 共享 chlib `0x100045f0`（161 B、`ret 0x10`、容器 `this[+0x18]`、
授权在外层包装 EA61 首层 / EA63 后续、`this[+0xb8]` 层计数器）。本批深挖三件事：

1. **T1（核心体）**：`this[+0x18]` 引擎真身（虚表 5 槽实现）、容器生产者、`0x100045f0` 主循环逐条展开 + 失败出口。
2. **T2（三兄弟）**：`NChZsBs3`(0x10004700) / `NChZsBreach`(0x10004720) / `NChZsSelPri`(0x10005a50) 骨架。
3. **T3（可选）**：`NChZsL2M`(0x100048a0) 递归结构侦察。

---

## 二、摘要表

| 项 | 结论 | 置信 |
|---|---|---|
| 引擎对象 | `this[+0x18]`，`new(0x68)`，ctor `0x1000e7c0`，**虚表 0x1001549c** | [A] |
| 引擎构造点 | `ch_api` ctor `0x100010d0`（同时构造 obj8 vt=0x100153ec 等 7 个子对象） | [A] |
| 引擎 vt[+4] | `0x1000e900` = reset（清字段 + 四容器 init） | [A] |
| 引擎 vt[+0xc] | `0x1000e0b0` = setter（`ret 0x14`，存 5 dword 输入描述符） | [A] |
| 引擎 vt[+8] | `0x1000ebe0` = **build**（分配 C1/C2/C3 + 主循环 + 后处理） | [A] |
| 引擎 vt[+0x10] | `0x1000ed20` = mode 分派（1 / 2 / 0x65） | [A] |
| C0 容器 | `engine[+0x20]` base / `[+0x2c]` count，**stride 0x31**，生产者 `0x1000e990` | [A] |
| C1 容器 | `engine[+0x30]` base / `[+0x3c]` count / `[+0x38]` cap，**stride 0x5d**，生产者 `0x1000f680` | [A] |
| C1 关键字段 | `+0x08` startBar / `+0x0c` endBar / `+0x10` dir / `+0x14` flags / **`+0x19` ZG / `+0x25` ZD** | [A] |
| C1 有效判据 | flags.bit0 ∧ **span ≥ 3**（Breach 另加严 span ≥ 4） | [A] |
| C2/C3 | `engine[+0x40]`（0x18）/ `engine[+0x4c]`（0x1d）；另有 `engine[+0x5c]/[+0x60]` 的 **0x74** 向量 = 4×0x1d | [A]/[B] |
| NChZsBreach | 中枢上/下沿越界**计数**；2 个 x87 条件（price vs ZG/ZD） | [A 结构/B 语义] |
| NChZsSelPri | 0x74 向量 → 4 子记录 `out[barIdx] = 价`；**0 个 x87** | [A] |
| SelPri/SelSlPri/SelSpPri | **三支逐字节同构**（仅跳转地址位移） | [A] |
| NChZsL2M | **无自调用/无递归**（695 行仅 2 个直接调用）⇒ 递归假设**证伪** | [A] |

---

## 三、T1 核心体 `0x100045f0` 与引擎

### 3.1 引擎身份锁定 [A]

定位路径：`ch_api` 虚表 = `0x10015214`（第一批已确权）。用**本批新工具**
`tools/re-inventory/nchzs/scan_engine.py`（全量 .text 扫 `[reg+0x18]` dword 写）命中 ctor 区
`0x10001117` / `0x10001203`；反汇编 `0x100010d0` 确认即 **`ch_api` 构造函数**：

```
ch_api::ch_api(this /*ecx*/, a1)             // 0x100010d0, ret 8
  this[0x00] = &vt_ch_api (0x10015214)
  this[0x04] = a1                                  ; 外部上下文
  this[0x08] = new(0x2c) + vt 0x100153ec           ; ★ obj8（NChBi 已确权同类, vt 完全一致）
  this[0x0c] = new(0x38) + vt 0x10015474
  this[0x10] = new(0x60) + ctor 0x10009850
  this[0x14] = new(0x68) + ctor 0x1000be70
  this[0x18] = new(0x68) + ctor 0x1000e7c0         ; ★★ 引擎
  this[0x1c] = new(0x3c) + vt 0x10015488 (+0x1c=0xc, +0x20=0x1a, +0x24=9)
  this[0x20] = new(0x50) 全零
```

引擎 ctor `0x1000e7c0`（`ret 4`）：写 **虚表 `0x1001549c`**、`[+0x1c]=9`、其余清零。

### 3.2 引擎虚表 `0x1001549c`（5 槽）[A]

| 槽 | 地址 | 语义 |
|---|---|---|
| +0x00 | `0x1000e850` | dtor（调 `0x1000e870` + 可选 free） |
| +0x04 | **`0x1000e900`** | **reset**：清 `[+4..+0x18]`，四容器 init（`0x1000dee0`/`0x10011930`/`0x100119b0`/`0x10006b60`） |
| +0x08 | **`0x1000ebe0`** | **build**：返 int；≠0 ⇒ 核心体返回 -1 |
| +0x0c | **`0x1000e0b0`** | **setter**（`ret 0x14`，5 参）：纯字段写，把输入描述符 5 dword 存进 `[+4]/[+8]/[+0xc]/[+0x10]/[+0x14]` |
| +0x10 | `0x1000ed20` | mode 分派：`arg==1→0x10011500` / `==2→0x10011660` / `==0x65→0x100117b0` / 否则 -1 |

> ★ `0x1000e0b0` 即第一批备注中的「通用 setter 0x1000e0b0」——**确证它属于本引擎类**（引擎 vt[+3]）。

### 3.3 核心体 `0x100045f0` 主路径逐条（铁律 +4 修正后自洽）[A]

```
int NChZs_core(ch_api* this, int n, double* out, TDesc* a3, TArg* a4)   // ret 0x10
 1. memset(out, 0, n*8);                                  ; 0x1001494c
 2. if (a3[0]==0 || a3[8]==0) return -1;                  ; 两指针非空门（0x1000462b/0x1000462f）
 3. engine = this[+0x18]; engine->vt[+4]();               ; reset
 4. engine->vt[+0xc](n, a3[0], a3[8], a3[4], a3);         ; setter（5 参，callee 清栈）
 5. sub_1000e990(n, a4[0]);                               ; ★ 生产 C0（分型/笔序列）
 6. if (engine->vt[+8]() != 0) return -1;                 ; build C1/C2/C3
 7. if (this[+0x18] == 0) return -1;
 8. sub_10006700(this); return 0;
失败出口：0x10004689（或 -1 后 pop edi/esi/ebp/ebx/ecx → ret 0x10）
成功出口：0x10004686（ret 0x10）
```
- 8 个栈槽在 +4 修正后全部自洽（`[esp+0x14]`=a3[4] 局部、`[esp+0x20]`=a3、`[esp+0x24]`=a4、`[esp+0x1c]`=a3[4]）。

### 3.4 容器与记录布局（详表见 `tools/re-inventory/nchzs/chzs_container_layout.txt`）[A]

引擎 `0x68` 字节：`C0@+0x20/0x2c (0x31)`、`C1@+0x30/0x3c (0x5d, cap@+0x38)`、
`C2@+0x40 (0x18)`、`C3@+0x4c (0x1d)`、`V@+0x5c/0x60 (0x74 = 4×0x1d)`。

**C1 中枢段记录（stride 0x5d）**：
`+0x00` 模式 / `+0x04` 自身下标 / `+0x08` startBar / `+0x0c` endBar / `+0x10` 方向 ±1 /
`+0x14` flags(bit0 有效) / **`+0x19` ZG 上沿** / **`+0x25` ZD 下沿** / `+0x41` barIdx / `+0x55` A / `+0x59` B。

**C0 分型/笔记录（stride 0x31）**：`+0x00` 方向 / `+0x04` 子区间起 / `+0x08` 子区间止 /
`+0x0c` 分型标记 / `+0x11` 索引A / `+0x15` 索引B / `+0x19` 价1 / `+0x21` 价2 / `+0x29` 价3。

### 3.5 build（`0x1000ebe0` = vt[+8]）逐条 [A]

```
if (C0.count==0 || C0.base==0 || engine[+0x28]==0) return -1;
n = C0.count;
resize(&C1, n*2); memset(C1.base, 0, n*0xba);  C1.count = 0;   // n*2 元素 × 0x5d = n*0xba
resize(&C2, n);   memset(C2.base, 0, n*0x18);
resize(&C3, n);   memset(C3.base, 0, n*0x1d);
reset(&engine[+0x58]);
for (i = 0; i < n; ) { r = buildSegment(engine, i, n, 0); i = (r>0 ? r : i) + 1; }   // 0x1000f680
for (k = 0; k < C1.count; k++) {                 // 后处理：C1 有效段 → C3
   rec = C1.base + k*0x5d;
   if (!(rec[+0x14] & 1)) continue;
   idx = rec[+0x08] + 1;
   if (idx < 0 || idx >= n) break;
   dst = C3.base + idx*0x1d;  src = C0.base + idx*0x31;
   *(u8*)(dst+4)=1; *(u32*)(dst+5)=idx;
   *(u32*)dst      = (*src == -1) ? +1 : -1;
   *(u32*)(dst+9)  = (*src == -1) ? *(u32*)(src+0x11) : *(u32*)(src+0x15);
   *(f64*)(dst+0x0d)= *(f64*)(src+0x19);
   *(f64*)(dst+0x15)= *(f64*)(src+0x21);
}
```

### 3.6 段生产者 `0x1000f680`（`ret 0xc`，3 参）[A]

```
int buildSegment(engine /*ecx*/, int i /*a1*/, int n /*a2*/, int mode /*a3*/)
  if (C1.count >= C1.cap) return -1;                       // 容量门（cap @ engine[+0x38]）
  rec = C1.base + C1.count*0x5d;  memset(rec, 0, 0x5d);
  rec[+0x00] = mode;  rec[+0x04] = C1.count;               // 自身下标
  r = sub_1000f8c0(i, n) ; if (r < 0) return -1;
  sub_10011170(engine, rec);
  ... 后继在 sub_1000fa40 / 1000fc60 / 10010ee0 / 10010f80 判据下推进/收尾，写
      rec[+0x08]/[+0x0c]（bar 区间）、rec[+0x10]（方向）、rec[+0x14] |= 1（有效）
  有效性: span = endBar − startBar + 1 >= 3 且 dir ∈ {±1}
```

---

## 四、T2 三兄弟

### 4.1 NChZsBs3（`0x10004700`）[A]
9 行极薄包装：`push 3; push a1; eax = this[+0x18]; call 0x100068c0`。
与 `NChZsBs12` **唯一差别 = 字面量 3 vs 12**（模式开关）。0 个 x87 条件。

### 4.2 NChZsBreach（`0x10004720`，`ret 0x10`，4 参，**2 个 x87 条件**）[A 结构 / B 语义]

对每个有效 C1 段（span ≥ 4，严于 buildSegment 的 ≥ 3），在 bar 区间 `[start+4, end+1]` 内，
对 C0 方向与段方向一致的记录，统计其子区间内价格越过中枢边界的次数，写入 `out[idx]`。

x87 直证（`cond_chlib_10004720.txt`，edx = C1.base+0xc）：
- `fcomp [eax+ecx*8] vs mem:[edx+0xd]` ⇒ price vs **rec+0x19（ZG）** —— 条件 `<|=|U` 时跳（即 `!(p ≤ ZG)`）
- `fcomp [eax+ecx*8] vs mem:[edx+0x19]` ⇒ price vs **rec+0x25（ZD）** —— `>|=|U` 时跳（即 `p ≥ ZD`）

⇒ **反向确证 C1 `+0x19` = ZG、`+0x25` = ZD**（与 G/D worker 完全一致）。

### 4.3 NChZsSelPri（`0x10005a50`，`ret 0x10`，**0 个 x87 条件**）[A]

读 `engine[+0x5c]`/`[+0x60]` 的向量，`cnt = (end − beg) / 0x74`（魔数 `0x8d3dcb09` ⇒ **除 116**）。
每元素 = **4 个 0x1d 子记录**（4×0x1d = 0x74），逐子记录 `out[barIdx] = 价`（带 `0 ≤ idx ≤ n` 门）。
子记录字段：`{i32 barIdx @+0x00, f64 价 @+0x04}`，实测偏移 `{0,0x1d,0x3a,0x57}+{1,5}`。

### 4.4 ★ Sel* 同构关系（本批派生发现）[A]

| 函数 | 地址 | 与 SelPri 关系 |
|---|---|---|
| NChZsSel | 0x100058f0 | 不同（有前置 setup 帧、读 `[esp+0x18]`） |
| NChZsSelPri | 0x10005a50 | 基准 |
| NChZsSelSlPri | 0x10005bb0 | **逐字节同构**（仅跳转地址位移） |
| NChZsSelSpPri | 0x10005d10 | **逐字节同构**（同上） |

⇒ 三支是**同一算法的三份克隆**；差异必然来自上游喂入的输入描述符 / 引擎状态，而非函数体。[A 同构 / C 差异来源]

---

## 五、T3 NChZsL2M（`0x100048a0`）递归假设**证伪** [A]

- 695 行，`ret 0x10`（4 参），`sub esp,0x14` 帧。
- **全部直接调用仅 2 处**：`0x100148a0`（`_ftol2`，double→int）、`0x1001494c`（memset）。
  ⇒ **无自调用、无互递归** —— 第一批「多级别递归结构」假设**证伪**；实为**单次全内联**大函数。
- 双数组遍历（`imul … 0x31` + `add … 0x5d`，读 C0/C1），**24 处 x87 比较**（189 基本块 / 10 conflicts，
  `cond_chlib_100048a0.txt`）：(a) `fcomp price vs mem:[edx]`；(b) `fcom 0.0 vs mem:[ecx±k*0x31]`（符号/零判定）。
- **收口建议**：第三批按支配树把 189 个基本块切成 ~6 段 + x87 条件表逐段复核；无需追递归栈。

---

## 六、勘误与待仲裁

**勘误（相对第一批）**
1. 第一批 WIP-C 把「C1 `+0x21` f64」记为段价 —— 实为 **C0 记录**字段（`0x1000ebe0` 后处理中
   `src = C0.base + idx*0x31`）。**C1 在 `+0x19`(ZG) 与 `+0x25`(ZD) 之间无第二个价字段**。
2. 第一批「NChZs 引擎读 `obj[+0x30]/[+0x3c]`（与 NChBi obj10 同偏移）」—— 现确证该偏移**就是引擎自身字段**
   （引擎即该 obj），非「另设容器对象」；且 `C1` 元素 stride **0x5d ≠ Item21 0x21** ⇒ 独立类（第一批判断维持）。
3. 第一批「NChZs 核心体 `vt[+4]` 疑似"已授权?"谓词」—— 证伪：`0x1000e900` = **reset**（引擎内无授权逻辑，
   授权在外层包装层已确权）。

**待仲裁 [B]/[C]**
- [B] `engine[+0x58]` 语义（C3 count 或 vector 辅助字段）；`engine[+0x4c]` 与 `+0x5c/0x60` 向量二者的关系（是否同一容器的两种视图）。
- [B] C0 `+0x0c`「分型标记（值 ∈ {−2,+2}）」的准确语义。
- [C] `engine[+0x1c] = 9`（ctor 常量）的用途。
- [C] `0x1000dee0` / `0x10011930` / `0x100119b0` / `0x10006b60` / `0x10011170` / `0x1000f8c0` / `0x1000fa40` /
  `0x1000fc60` / `0x1000ff80` / `0x10010ee0` / `0x10010f80` / `0x10011360` 未逐一展开（构建链中段）。
- [C] SelPri/SelSlPri/SelSpPri 同构但功能有别 —— 差异来源（上游描述符）未定位。
- [C] `0x1000e990` 的 arg2（C0 生产者输入）与 a4 的语义绑定。
- **本批未做动态验证**（frida 预备包待用户在场运行）。

---

## 七、可复现命令

```bash
PY=C:/Users/Administrator/Documents/a_conda/python.exe
D=ronglide-app/chlib.dll

# T1 引擎身份：扫描 [reg+0x18] 写 + 候选虚表
$PY tools/re-inventory/nchzs/scan_engine.py -o tools/re-inventory/nchzs/scan_engine.txt
# → ch_api ctor 0x100010d0；引擎 vt 候选 0x1001549c

# T1 逐函数反汇编
for a in 100010d0 1000e7c0 1000e900 1000e0b0 1000ebe0 1000ed20 1000e850 1000e990 1000f680; do
  $PY tools/re-inventory/disasm_func.py 0x$a --max 0x700 --dll $D -o tools/re-inventory/nchzs/chlib_$a.txt
done

# T2/T3 x87 条件表
for f in 100045f0 10004720 10005a50 100048a0; do
  $PY tools/re-inventory/x87_sim.py tools/re-inventory/nchzs/chlib_$f.txt \
      -o tools/re-inventory/nchzs/cond_chlib_$f.txt
done
```

---

## 八、下一步（建议）

1. **（首选）NChZs 第三批**：构建链中段空白补完 —— `0x1000f8c0`/`0x1000fa40`/`0x1000fc60`/`0x1000ff80`/
   `0x10010ee0`/`0x10010f80`/`0x10011170`/`0x10011360` 这 8 支（C1 段记录三字段 bar 区间/方向/ZG/ZD 的真正赋值点）
   ⇒ 可把 C1 语义从「[A 偏移]」升到「[A 语义]」。
2. **次选**：`NChZsFj`(0x10005020, 384 行) / `NChZsDg`(0x10005160, 260) / `NChZsHLTurn`(0x10005480, 318)
   三支（EA63+EA61 组）—— 分型/顶底/高低转折。
3. **第三**：`NChZsL2M` 分块收口（§五的建议路径）。
4. **可选**：用户在场时跑 frida 预备包，把引擎容器与 C0/C1 字段由运行时 dump 直证（把 [B] 升 [A]）。
