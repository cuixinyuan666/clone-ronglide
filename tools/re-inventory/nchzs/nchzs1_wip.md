# NChZs 族 第一批 WIP —— 边做边落盘

> 批次：NChZs 族第一批（kickoff），2026-10-17 06:10 派发
> 主文档：`docs/31-NChZs-第一批-入口链与三支骨架.md`
> 任务：T1 入口链 + 「+0x78 共享槽」之谜 / T2 NChZsG+NChZsBs12 骨架 / T3 族侦察表 + 复用度评估

---

## WIP-A — T1: 0x100045f0 共享分发器（首批发现）

**族槽位（family_slots.txt，+0x78..+0xb4）**：
| 槽 | chlib 地址 | 导出 |
|---|---|---|
| +0x78 | **0x100045f0** | NChDuanKh / NChDuanKl / NChDuanKd / **NChZs** / **NChZs_L2**（5 支共享！） |
| +0x7c | **0x100046a0** | NChZsG |
| +0x80 | 0x100046c0 | NChZsD |
| +0x84 | **0x100046e0** | NChZsBs12 |
| +0x88 | 0x10004700 | NChZsBs3 |
| +0x8c | 0x10004720 | NChZsBreach |
| +0x90 | 0x100048a0 | NChZsL2M |
| +0x94 | 0x10005020 | NChZsFj |
| +0x98 | 0x10005160 | NChZsDg |
| +0x9c | 0x10005480 | NChZsHLTurn |
| +0xa0 | 0x10005810 | NChFjZsNum |
| +0xa4 | 0x100058f0 | NChZsSel |
| +0xa8 | 0x10005a50 | NChZsSelPri |
| +0xac | 0x10005bb0 | NChZsSelSlPri |
| +0xb0 | 0x10005d10 | NChZsSelSpPri |
| +0xb4 | 0x10005e70 | (待定名) |

**★ 0x100045f0 = 极短分发器**：区间 `0x100045f0–0x10004691`（仅 **161 字节**，71 行反汇编），`ret 0x10`（**4 参**）。
- 证据：`chlib_100045f0.txt`
- 形态识别：
  - `push ecx` 开头（4B scratch 局部槽 L0 = [esp+0]）、`pop ebx/esi/ebp/edi` 收尾 —— MSVC 标准帧。
  - **无 `push <立即数>` 授权码**（与 NChBi 族 `push 0xEA62` 形态**不同**）！
    `mov ecx,[edi+0x18]; mov edx,[ecx]; mov eax,[edx+4]; call eax` ⇒ `this->[+0x18]->vt[+4]()`（**无参虚调用**）。
    ⇒ `this[+0x18]` 是 auth/holder 对象，`vt[+4]` 疑似「已授权?」谓词（待与 NChBi 的 `vt[+4](code)` 形态仲裁）。
  - `mov [esp+0x14], ecx`（L0 = `a3[+4]`）+ `push a1*8; push 0; push L0` → `call 0x1001494c` = **memset(a3[+4], 0, a1*8)**（a1=n, 8=sizeof(double)）。
  - `ch_auth->vt[+0xc](a1, X, a3[0], a3[8], a4)` —— 5 参「真工作」虚调用（0x1000464f）。
  - 后置：`call 0x1000e990`（2 参）、`ch_auth->vt[+8]()` 判 null、`call 0x10006700(edi)`。
- 待办：确认 `this[+0x18]` 与 NChBi 的 `this[+0xBC]`(ch_api*) 关系；确认 5 导出共享是否靠**参数**区分（查 TAFLib 包装 0x100130c0..0x10013370 的 vt[+0x78] 调用实参）。

---

## WIP-B — T1 关键勘误：「+0x78 共享槽」之谜 = **family_slots.txt 工具误映射**

**实测重解 TAFLib 包装层（rglib 与安装目录 TAFLib.dll 逐字节同源，md5=3a5268a1…）**：

| 导出包装 VA | 真实 vt 槽 | chlib 实现 | 备注 |
|---|---|---|---|
| 0x100130c0 NChDuanKh | **+0x6c** | 0x100042f0 | family_slots **误记为 +0x78** |
| 0x10013140 NChDuanKl | **+0x70** | 0x100043e0 | 误记 +0x78 |
| 0x100131c0 NChDuanKd | **+0x74** | 0x100044d0 | 误记 +0x78 |
| 0x10013240 **NChZs** | **+0x78** | **0x100045f0** | ✓ |
| 0x100132d0 **NChZs_L2** | **+0x78** | **0x100045f0** | ✓ |
| 0x10013370 NChZsG | +0x7c | 0x100046a0 | ✓ |
| 0x100133e0 NChZsD | +0x80 | 0x100046c0 | ✓ |

**根因**：`map_family_slots.py` 的 `find_slot` 只认 `mov edx,[ecx]; mov edx,[edx+SLOT]` 形态；
而 NChDuanKh/Kl/Kd 三支把 vtable 载入 **eax**（`mov eax,[ecx]; mov eax,[eax+0x6c]`）⇒ 未命中，
工具**回退/串用**了相邻包装的值 → 错记为 +0x78。**实证依据**：chlib 虚表 dump（`vtable_dump.txt`）
`+0x6c=0x100042f0 / +0x70=0x100043e0 / +0x74=0x100044d0 / +0x78=0x100045f0`。

**⇒ 「+0x78 共享」真相：只有 NChZs 与 NChZs_L2 两支共享 0x100045f0**（5 支共享是假象）。
（NChDuanKh/Kl/Kd 是 NChDuan 族的 K 线三兄弟，slot +0x6c/+0x70/+0x74，与本族无关。）

### T1 包装体授权分层机制 [A]
**NChZs (0x10013240, ret 0xc)**：
```
if (this[+0xb8] <= 0) auth = Authorize(0xEA61);   // 首层 EA61
else                  auth = Authorize(0xEA63);   // 后续层 EA63
if (!auth) { memset(out,0,n*8); return 0; }       // 0x1006bd22
buf[6] = Fetch6Buffers(0x10006cc0);
this[+0xb8] += 1;                                  // ★ 计数器自增
return vt[+0x78](arg1, arg2, &buf, arg3);          // 4 参
```
**NChZs_L2 (0x100132d0, ret 0xc)** —— 同一 0x100045f0，但授权**按计数器分层**：
```
cnt = this[+0xb8]
cnt<=0 -> Authorize(0xEA61)
cnt==1 -> Authorize(0xEA62)
cnt>=2 -> Authorize(0xEA63) ∧ Authorize(0xEA62)
（失败 -> memset+return 0；成功 -> 同 NChZs：Fetch6 + counter++ + vt[+0x78](4参)）
```
⇒ **`this[+0xb8]` = 层计数器**（每次调用 +1），授权码随层递进 EA61→EA62→EA63。
⇒ TAFLib 侧授权函数 = `0x10014e60`（与 NChBi 族同址，`Authorize(code)`）；**授权码只在外层包装，chlib 0x100045f0 内无 `push code`**。

---

## WIP-C — T2: 三支骨架 = 极薄包装 + 两个「中枢价带展开」worker

### NChZsG (0x100046a0) / NChZsD (0x100046c0) —— 薄包装 [A]
```
NChZsG: eax=arg1; esi=this[+0x18]; edi=arg2; call 0x10006800
NChZsD: eax=arg1; esi=this[+0x18]; edi=arg2; call 0x10006860
```
两者**逐字节同构**，仅 worker 目标不同（0x10006800 vs 0x10006860）。`ret 0x10`（4 参，实为 3 实参 + this）。

### worker 0x10006800 (G) / 0x10006860 (D) —— **仅一处偏移不同** ★ [A]
```
memset(out, 0, n*8);                       // 0x1001494c
base = obj[+0x30]; cnt = obj[+0x3c];       // 与 NChBi obj10 同偏移!
if (!base || !cnt) return -1;
ptr = base + 0x55;                          // i=0 的循环指针
do {
  if (byte[ptr-0x41] & 1) {                 // 段 flags.bit0 = 有效
     A = [ptr]; B = [ptr+4];                // 段 bar 区间
     for (k=A; k<=B; k++) out[k] = <价>;    // 展开到逐 bar
  }
  ptr += 0x5d;                             // ★ stride 0x5d (93 B)
} while (--cnt);
```
| worker | 价字段 | 含义 |
|---|---|---|
| **0x10006800** (G) | `fld qword [ptr-0x3c]` = 段+0x19 | **ZG 中枢上沿** |
| **0x10006860** (D) | `fld qword [ptr-0x30]` = 段+0x25 | **ZD 中枢下沿** |

⇒ **NChZsG/NChZsD = 中枢 ZG/ZD 价带逐 bar 展开器**（输出 = 每个中枢段在其 [A..B] bar 区间上的上/下沿价）。G=Gao/ZG、D=Di/ZD [B]。

### 段记录布局（相对 ptr，stride 0x5d）[A 相对 / B 绝对]
| 相对 ptr | 绝对(设 ptr=rec+0x55) | 类型 | 语义 |
|---|---|---|---|
| ptr-0x41 | +0x14 | u8 | flags（bit0 有效）|
| ptr-0x3c | +0x19 | f64 | **ZG**（G 用）|
| ptr-0x30 | +0x25 | f64 | **ZD**（D 用）|
| ptr-0x14 | +0x41 | i32 | barIdx（Bs worker 用）|
| ptr     | +0x55 | i32 | A（区间起）|
| ptr+4   | +0x59 | i32 | B（区间止；+0x59+4 = 0x5d 恰为 stride 尾）|
> 绝对偏移基于「rec_i = base + i*0x5d」假设（A@+0x55、B@+0x59 恰好收尾，强支持）；rec+0x00..0x13 为 20B 头部（疑嵌套子结构），语义 [C]。
> ⚠ 该容器 base/count 在 `obj[+0x30]/[+0x3c]`（与 NChBi obj10 **同偏移**），但元素 stride = **0x5d ≠ 0x21** ⇒ **不是同一个 obj10 类**（NChZs 的引擎对象 `this[+0x18]` 自有容器）。

### NChZsBs12 (0x100046e0) / NChZsBs3 (0x10004700) —— 薄包装 [A]
```
NChZsBs12: eax=arg1; edi=arg2; push 0xc; push eax; eax=this[+0x18]; call 0x100068c0
NChZsBs3 : 同上, 但 push 3   （唯一差别 = 字面量 12 vs 3）
```
### worker 0x100068c0 —— 模式化标志展开器（`ret 8`，2 参）[A]
```
memset(out,0,n*8);
base = obj[+0x40]; cnt = obj[+0x2c];       // ★ 另一组容器偏移(+0x40/+0x2c), 元素 stride 0x18
if (!base||!cnt) return -1;
ptr = base + 0x14;
do {
  if (mode == 12) {                        // ★ Bs12 分支: 3 选 1
     v = signed8[ptr+1] ?: signed8[ptr] ?: signed8[ptr+3];
  } else {                                 // ★ Bs3 分支: 按 span 缩放
     dl = signed8[ptr+2]; p = [ptr-8];     // +0x0c 指针
     if (dl && p) { span = p[0xc]-p[8]+1; v = dl * (span>3 ? 1 : 10); }
  }
  idx = [ptr-0x14];                        // +0x00 barIdx
  if (idx >= 0 && idx < n) out[idx] = (double)v;
  ptr += 0x18;
} while (--cnt);
```
⇒ Bs12/Bs3 = **NChZs 分类标志展开器**（把段的分类字节写入 out[barIdx]）；12/3 = **模式开关**（不同选取逻辑）。
「Bs」命名待定 [C]（疑"笔数"或"本级别"；字面 3 与 12）。
