# NChZs 族 第二批 WIP —— 边做边落盘

> 批次：NChZs 族第二批，2026-10-17 06:28 派发
> 主文档：`docs/32-NChZs-第二批-核心体与三兄弟.md`
> 任务：T1 核心体 0x100045f0 引擎真身 + 容器生产者 / T2 Bs3·Breach·SelPri 三兄弟 / T3(可选) L2M 递归侦察

---

## WIP-A — T1: 引擎对象 `this[+0x18]` 身份锁定 ★（本批最高价值）

### 定位路径
`ch_api` 虚表 = **0x10015214**（第一批已确权）。`this[+0x18]` 是 ch_api 的内嵌成员子对象。
**搜索工具 `scan_engine.py`**（本批新建）：全量 .text 扫 `[reg+0x18]` dword 写 → 命中 ctor 区 `0x10001117/0x10001203`。

### ch_api 构造函数 `0x100010d0`（`ret 8`，2 参）[A]
```
this[0x00] = &vt_ch_api (0x10015214)
this[0x04] = a1                      ; 外部上下文/owner
this[0x08] = new(0x2c) + vt 0x100153ec   ; ★ obj8（NChBi Rec20+价数组类, vt 与 docs/30 一致）
this[0x0c] = new(0x38) + vt 0x10015474
this[0x10] = new(0x60) + ctor 0x10009850
this[0x14] = new(0x68) + ctor 0x1000be70
this[0x18] = new(0x68) + ctor 0x1000e7c0  ; ★★ 引擎对象（0x100045f0 内 this[+0x18]）
this[0x1c] = new(0x3c) + vt 0x10015488, +0x1c=0xc, +0x20=0x1a, +0x24=9
this[0x20] = new(0x50) 全零（无虚表, 纯结构）
```
- 证据：`chlib_100010d0.txt`（159 行）+ 该 ctor 亦证实 obj8 vt=0x100153ec（与 NChBi docs/30 T3 生产者 obj8 同一类）。

### 引擎构造函数 `0x1000e7c0`（`ret 4`）[A]
```
engine[0x00] = &vt_engine (0x1001549c)
engine[0x04..0x17] = 0
engine[0x18] = 0 (byte)
engine[0x1c] = 9        ; ★ 初始化常量 9
engine[0x20..0x64] = 0
```
⇒ 引擎对象大小 ≥ 0x68（与 `new(0x68)` 吻合）；证据 `chlib_1000e7c0.txt`。

### ★ 引擎虚表 `0x1001549c`（5 槽）[A]
| 槽 | chlib 地址 | 由核心体调用 | 语义初判 |
|---|---|---|---|
| +0x00 | 0x1000e850 | — | dtor / 清空 |
| +0x04 | **0x1000e900** | `vt[+4]()` 无参 | reset / 预处理 |
| +0x08 | **0x1000ebe0** | `vt[+8]()` → 返 int（≠0 ⇒ 核心体返回 -1） | 构建 / 校验 |
| +0x0c | **0x1000e0b0** | `vt[+0xc](5 参)` | ★ **通用 setter**（NChBi 族同址！） |
| +0x10 | 0x1000ed20 | — | ? |

**⇒ 核心体 0x100045f0 的三次虚调用 = 引擎 vt[+4]/vt[+0xc]/vt[+8]，全部落在 0x1000e8xx–0x1000edxx 段。**

### 引擎字段（自 ctor + 薄包装 worker 交叉确证）[A 偏移 / B 语义]
| 偏移 | 类型 | 谁读 | 语义 |
|---|---|---|---|
| +0x1c | i32 | — | 初值 9（疑级别/模式阈值）[C] |
| +0x2c | i32 | Bs worker `[esi+0x2c]` | 分类容器 count |
| +0x30 | ptr | G/D worker `[esi+0x30]` | 中枢段容器 base |
| +0x3c | i32 | G/D worker `[esi+0x3c]` | 中枢段容器 count |
| +0x40 | ptr | Bs worker `[esi+0x40]` | 分类容器 base |

---

## WIP-B — T1: 容器生产者与三容器布局 ★ [A]

### 核心体 0x100045f0 调用序列（逐条展开，铁律 +4 修正后自洽）
```
this = ecx (ch_api*),  ret 0x10 (4 参: a1=n, a2=out, a3=desc*, a4=?)
 1. memset(a2, 0, a1*8)                       ; 0x1001494c, a2=out, a1=n
 2. if (a3[0]==0 || a3[8]==0) return -1       ; ebx=a3[0], esi=a3[8]  (两指针非空门)
 3. engine = this[+0x18]; engine->vt[+4]()    ; 0x1000e900 = reset
 4. engine->vt[+0xc](a1, a3[0], a3[8], a3[4], a3)  ; 0x1000e0b0 = setter(存 5 dword)
 5. sub_1000e990(a1, a4[0])                   ; ★ 生产 container0 (分型/笔序列)
 6. if (engine->vt[+8]() != 0) return -1      ; 0x1000ebe0 = build containers 1/2/3
 7. if (this[+0x18]==0) return -1
 8. sub_10006700(this); return 0
失败口: 0x10004689 (or eax,-1; pop...; ret 0x10)
```

### 引擎三容器（`engine = this[+0x18]`, 大小 0x68）[A 结构 / B 语义]
| 容器 | base | count | 元素 stride | 内容 | 生产者 |
|---|---|---|---|---|---|
| C0 | engine[+0x20] | engine[+0x2c] | **0x31** (49B) | 分型 / 笔序列 | **0x1000e990**（核心体 helper） |
| C1 | engine[+0x30] | engine[+0x3c] | **0x5d** (93B) | 中枢段候选 | **0x1000f680**（经 vt[+8] 调） |
| C2 | engine[+0x40] | (n=engine[+0x2c]) | **0x18** (24B) | 分类/标志（Bs 用） | vt[+8] memset n*0x18 |
| C3 | engine[+0x4c] | engine[+0x58] | **0x1d** (29B) | 段点输出（dir/barIdx/价） | vt[+8] memset n*0x1d |

- 容量字段：C1 容量 @ `engine[+0x38]`（0x1000f680 首行 `count>=cap ⇒ 溢出返 -1`）。
- 另有 `engine[+0x5c]/[+0x60]` = 一个 vector 的 size/cap（reset/vt[+0x10] 中经 `0x10012550` 收缩）。
- 设值器 **0x1000e0b0**（`ret 0x14` 5 参）= 纯字段写：`engine[+4]←a2, [+8]←a3, [+0xc]←a4, [+0x10]←a5, [+0x14]←a1`。
- **0x1000e900**（vt[+4]）= reset：清 [+4..+0x18] + 四容器 init（0x1000dee0/0x10011930/0x100119b0/0x10006b60）。

### C1 中枢段记录（stride 0x5d，`0x1000f680` 中 `memset(rec,0,0x5d)` 后逐字段写）[A 偏移]
| 偏移 | 类型 | 语义 | 赋值点 |
|---|---|---|---|
| +0x00 | i32 | 模式/标志（buildSegment arg3） | 1000f6bf |
| +0x04 | i32 | 自身下标（= 写前的 engine[+0x3c]） | 1000f6c8 |
| +0x08 | i32 | startBar（段起） | 1000f6xx 子调用 |
| +0x0c | i32 | endBar（段止） | 同上 |
| +0x10 | i32 | 方向 ±1 | 1000fc60/ff80 路径 |
| +0x14 | u8 | flags.bit0=有效 | 1000f800/f853/f8a5 `or byte [edi+0x14],1` |
| +0x19 | f64 | **ZG 中枢上沿**（G worker 用; ptr-0x3c） | — |
| +0x21 | f64 | （另一价，转写进 C3[+0x15]） | — |
| +0x25 | f64 | **ZD 中枢下沿**（D worker 用; ptr-0x30） | — |
| +0x41 | i32 | barIdx（Bs worker 用; ptr-0x14） | — |
| +0x55 | i32 | A 输出区间起（G/D worker [ptr]） | — |
| +0x59 | i32 | B 输出区间止（[ptr+4]; 0x59+4=0x5d 收尾） | — |

**C1 有效性判据（0x1000f680 尾部）**：`span = endBar − startBar + 1 >= 3` 且 `dir ∈ {±1}` 门 ⇒ **中枢需覆盖 ≥3 根 K 线** [A]。
**C0 记录（stride 0x31）**：`+0x19 f64 / +0x21 f64 / +0x29 f64` 三价；`+0x0c = 1` 当值 ∈ {−2, +2}（0x100eb33）⇒ 分型点标记 [B]。

### vt[+8] = 0x1000ebe0（构建器）逐条 [A]
```
if (C0.count==0 || C0.base==0 || engine[+0x28]==0) return -1;
n = C0.count;
resize(&C1, n*2);  memset(C1.base, 0, n*0xba);   // n*2 元素 × 0x5d = n*0xba；容量 2n
C1.count = 0;
resize(&C2, n);    memset(C2.base, 0, n*0x18);
resize(&C3, n);    memset(C3.base, 0, n*0x1d);
reset(&engine[+0x58]);                     // 0x10011b10
for (i=0; i<n; ) { r = buildSegment(engine, i, n, 0);  i = (r>0? r : i) + 1; }   // 0x1000f680
// 后处理: 把 C1 有效段映射到 C3
for (k=0; k<C1.count; k++) {
   rec = C1.base + k*0x5d;
   if (!(rec[+0x14] & 1)) continue;
   idx = rec[+0x08] + 1;                    // startBar+1
   if (idx<0 || idx>=n) break;
   dst = C3.base + idx*0x1d;  src = C0.base + idx*0x31;
   dst[+4]=1; *(u32*)(dst+5)=idx;
   dst[+0]  = (*src==-1) ? +1 : -1;
   dst[+9]  = (*src==-1) ? src[+0x11] : src[+0x15];
   *(f64*)(dst+0x0d) = *(f64*)(src+0x19);
   *(f64*)(dst+0x15) = *(f64*)(src+0x21);
}
```

---

## WIP-C — T2: 三兄弟（Bs3 / Breach / SelPri）+ 派生发现

### NChZsBs3（0x10004700，`ret 0x10`）[A] —— 第零批已解，本批确证
9 行极薄包装：`push 3; push arg1; eax = this[+0x18]; call 0x100068c0`。
**与 NChZsBs12 唯一差别 = 字面量 3 vs 12**（模式开关）。无 x87。

### ★ NChZsBreach（0x10004720，`ret 0x10`，4 参，**2 个 x87 条件**）[A 结构 / B 语义]
```
memset(a2=out, 0, a1*8);
engine = this[+0x18];
C0base=engine[+0x20], C0cnt=engine[+0x2c], C1base=engine[+0x30], C1cnt=engine[+0x3c];
if (!C0cnt||!C0base||!C0cnt||!C1base||!C1cnt) return -1;      // 5 道非空门
for (s = 0; s < C1cnt; s++)  {                               // edx = C1base+0xc, 步进 0x5d
  rec = C1base + s*0x5d;
  if (!(rec[+0x14] & 1)) continue;                           // 段有效
  span = rec[+0x0c] - rec[+0x08] + 1;
  if (span <= 3) continue;                                   // ★ 需 span ≥ 4（严于 buildSegment 的 ≥3）
  for (idx = rec[+0x08]+4; idx <= rec[+0x0c]+1; idx++) {
     c0 = C0base + idx*0x31;
     if (c0[+0x00] != rec[+0x10]) continue;                  // C0 方向必须与段方向一致
     up = dn = 0;
     for (k = c0[+0x04]; k <= c0[+0x08]; k++) {              // C0 子区间
        p = price[k];                                        // [eax+ecx*8]
        if (rec[+0x10] != -1) { if (!(p <= rec[+0x19])) {up++; ...} }   // fcomp ZG
        else                  { if (!(p >= rec[+0x25])) {dn++; ...} }   // fcomp ZD
        out[idx] = (double) 计数;
     }
  }
}
```
- x87 直证（`cond_chlib_10004720.txt`）：`fcomp [eax+ecx*8] vs mem:[edx+0xd]` = price vs **rec+0x19**；
  `fcomp ... vs mem:[edx+0x19]` = price vs **rec+0x25**（edx = C1base+0xc ⇒ +0xd→+0x19、+0x19→+0x25）。
  **⇒ rec+0x19 = ZG（上沿）、rec+0x25 = ZD（下沿）**（与 G/D worker 完全对上）。
- 语义初判 [B]：**中枢突破（Breach）计数** —— 对每根 bar 统计其价格越过中枢上/下沿的次数。

### ★ NChZsSelPri（0x10005a50，`ret 0x10`，4 参，**0 个 x87 条件**）[A]
```
memset(out, 0, a1*8);
engine = this[+0x18];
vec.beg = engine[+0x5c]; vec.end = engine[+0x60];
cnt = (vec.end - vec.beg) / 0x74;    // ★ magic 0x8d3dcb09 ⇒ 整除 116 = 0x74
if (!cnt) return 0;
for (e = 0; e < cnt; e++) {
   elem = vec.beg + e*0x74;           // ★ 元素 = 4 个 0x1d 子记录 (4*0x1d = 0x74)
   子记录 i ∈ {0,1,2,3} @ elem + i*0x1d:
       idx = *(i32*)(sub+0x00);  val = *(f64*)(sub+0x04);
       if (0 <= idx <= a1 && idx <= limit) out[idx] = val;
}
```
- 子记录偏移实测（两处循环体交叉确证 A）：`+0x01/0x05`、`+0x1e/0x22`、`+0x3b/0x3f`、`+0x58/0x5c`
  = `{0, 0x1d, 0x3a, 0x57} + {1, 5}` ⇒ 每子记录 `{i32 barIdx@+0x00, f64 价@+0x04, ...}`，步长 **0x1d**。
- 语义初判 [B]：**中枢/段点的"优先点"展开器**（4 组 barIdx+价 同时写 out[]）。

### ★★ Sel* 四兄弟同构关系 [A]
| 函数 | 地址 | 与 SelPri 关系 |
|---|---|---|
| NChZsSel | 0x100058f0 | **不同**（多一段前置 setup、读 [esp+0x18]，形态为 `push ecx` 帧） |
| **NChZsSelPri** | 0x10005a50 | 基准 |
| **NChZsSelSlPri** | 0x10005bb0 | **逐字节同构**（diff 仅跳转地址位移） |
| **NChZsSelSpPri** | 0x10005d10 | **逐字节同构**（同上） |

⇒ SelPri / SelSlPri / SelSpPri 是**同一算法的三份克隆**（差异必然来自上游喂入的 5-dword 输入描述符 / 引擎状态，而非函数体）[A 同构 / C 差异来源]。

---

## WIP-D — T3: NChZsL2M（0x100048a0）递归假设 **证伪** [A]

- 体量 695 行、`ret 0x10`（4 参）、`sub esp,0x14` 帧。
- **全部直接调用仅 2 处**：`0x100148a0`(_ftol2，double→int) 与 `0x1001494c`(memset)。
  ⇒ **无自调用、无互递归** —— 「多级别递归」假设**证伪**；此函数是**单次全内联**的大计算体。
- 结构：读 `engine[+0x20]/[+0x2c]`(C0) 与 `engine[+0x30]/[+0x3c]`(C1)，以 `imul 0x31` + `add 0x5d` 双数组遍历，
  做 **24 处 x87 比较**（189 基本块 / 10 conflicts，见 `cond_chlib_100048a0.txt`）：
  两类模式 —— (a) `fcomp price vs mem:[edx]`（价 vs 某个基准）；(b) `fcom 0.0 vs mem:[ecx±k*0x31]`（符号/零判定，判定 C0 记录三价的关系）。
- **收口建议**：L2M 可在第三批用**分块函数切分**（按 189 基本块的支配树切成 ~6 段）+ x87 条件表逐段复核；
  无需追踪递归栈。
