# NChZs 第三批 WIP — 构建链中段 8 支 + C1 语义升级

证据目录：`tools/re-inventory/nchzs/`（chlib_1000f8c0/1000fa40/1000fc60/1000ff80/10010ee0/10010f80/10011170/10011360.txt）

---

## WIP-A — 调用约定与两支已解（`0x1000f8c0` 段初始化 / `0x1000fa40` 段延展判定）

### 全局调用约定（本批 8 支实测统一）[A]
- **C1 段记录指针走寄存器 `edi`**（`0x1000fa40`/`0x1000fc60`/`0x1000ff80`/`0x10011170` 内 `mov [edi+X]` 写段字段）。
- `0x1000f8c0` 另类：**`ecx` = 段记录（输出参数），`eax` = engine**，栈参 = (i, n)。
- 引擎指针 = 栈 arg0（`mov edx,[esp+8]`），bar 下标 = 栈 arg1。
- 全部 **栈槽 +4 修正** 后自洽（`push ebx` / `push ebp` / `push esi` 后逐点换算）。

### ★ C1 段记录新增 4 组「(下标, 价)」对 [A]（docs/32 布局升级）
`0x1000f8c0` 一次性写 8 个字段 ⇒ 段记录含 **4 组极值对**：

| 下标字段 | 价字段 | 语义（初判） | 写点 |
|---|---|---|---|
| `+0x15` | `+0x19` | **ZG（中枢上沿）** + 其 bar 下标 | 1000f93b/1000f960 → 1000f967 |
| `+0x21` | `+0x25` | **ZD（中枢下沿）** + 其 bar 下标 | 1000f97d/1000f988 → 1000f98f |
| `+0x2d` | `+0x31` | **GG（段内最高）** + 其 bar 下标 | 1000f992/1000f9b4 → 1000f997/1000f9b1 |
| `+0x39` | `+0x3d` | **DD（段内最低）** + 其 bar 下标 | 1000f9b7/1000f9d9 → 1000f9bc/1000f9d6 |

> 与缠论「中枢四值」ZG/ZD/GG/DD 完全对齐。docs/32 只标到 `+0x19/+0x25`，本批补全 `+0x2d/+0x31/+0x39/+0x3d/ +0x15/+0x21` 六字段。

### 0x1000f8c0 — 段初始化（seg_init）[A]  `ret 8`，`ecx`=rec / `eax`=engine / 栈参=(i, n)
```c
int seg_init(Rec5D* rec /*ecx*/, Engine* eng /*eax*/, int i /*arg0*/, int n /*arg1*/)
{
    if (rec == NULL)                return -1;          // test ecx,ecx  (1000f8c0)
    if (i < 0)                      return -1;          // test ebp,ebp  (1000f8d4)
    if (i + 3 > n)                  return -1;          // lea eax,[ebp+3]; cmp n (1000f8da)
    C0 = eng[+0x20];                                     // 1000f8e3
    /* 门 G1: C0[i].dir 与 C0[i+2].p1/p2 的相对关系 —— 只对 dir==-1 走 A 支，否则 B 支 */
    if (C0[i].dir == -1) {                               // cmp [C0+i*0x31], -1
        if (!(C0[i].p2 > C0[i+2].p1))  return -1;        // fld [..+0x21]; fcomp [eax+0x19]; ah&0x41==0 → fail
        // ---- A 支 ----
        rec->endBar = i + 2;                             // [ecx+0xc] = esi = i+2
        rec->startBar = i;                               // [ecx+8]  = ebp = i
        rec->dir = C0[i].dir;                            // [ecx+0x10] = [C0+i*0x31]
        /* ZG 取 C0[i].p1 与 C0[i+2].p1 的较大者 + 记录其下标 */
        if (C0[i].p1 < C0[i+2].p1) { rec->zgIdx = i+2; load C0[i+2].p1; }
        else                       { rec->zgIdx = i;   load C0[i].p1;   }   // [ecx+0x15], fld [eax]
        rec->ZG = ST;                                    // [ecx+0x19]
        ...
    } else {
        if (C0[i].p2 < C0[i+2].p1) ...                   // B 支: fcomp [eax+0x21]; ah&5; jp
    }
    /* ZD / GG / DD 同理，各取相邻两 C0 记录 (+0x19/+0x21) 的极值并记下标 */
    ...
    /* 尾部: 调 0x1000f180(?) 选下一个候选 bar，再按 dir 分派到 0x10010ee0 / 0x10010f80 */
    esi = (rec->dir == -1) ? +1 : -1;                    // 1000f9dc-1000f9eb
    k = sub_1000f180(...);                               // 1000f9ed
    if (k < 0 || k >= eng[+0x3c]) return rec->endBar;    // 1000f9f4/f9f6/f9f9
    if (rec->dir == -1)  sub_10010ee0(rec / *C1base+k*0x5d*/, ...);   // 1000fa0c
    else                 sub_10010f80(...);                            // 1000fa24
    return rec->endBar;
}
```
**失败口**：`0x1000f94e`（pop esi/ebx/edi; or eax,-1; pop ebp; ret 8）。

### 0x1000fa40 — 段延展判定（seg_extend）[A]  `ret 8`，`edi`=rec / 栈参=(engine, i)
```c
int seg_extend(Rec5D* rec /*edi*/, Engine* eng /*arg0*/, int i /*arg1*/)
{
    if (i < 0 || i >= eng[+0x2c]) return -1;             // C0 越界门
    if (C0[i].dir == rec->dir)    return -1;             // 方向相同 → 不是新端点
    if (eng[+0x00] == 0) { /* 首段特殊路径 */ }
    else {
       k = sub_1000f200(eng[+0x3c], rec->dir);           // 1000fa7e 找前段
       if (k < 0) goto common;
       prev = C1base + k*0x5d;
       if (prev->dir != rec->dir) goto common;
       if (rec->dir == -1) { if (prev->GG < C0[i].p2) goto ret_alt; }   // fcomp [eax+0x31] vs [ebx+0x21]
       else                { if (prev->DD > C0[i].p1) goto ret_alt; }   // fcomp [eax+0x3d] vs [ebx+0x19]
    }
common:
    span = rec->endBar - rec->startBar + 1;
    if (span > 3) {   // ★ setg → span >= 4
        // dir==-1: 要求 ZG <= C0[i].p2 且 ZD <= C0[i].p1（不成立则判定段结束）
        // dir!=-1: 要求 DD <= C0[i].p1 且 ZG <= C0[i].p2
        // 满足 → rec->endBar = i (endBar 前推); 调 0x1000edb0 / 0x1000edd0 记录极值; return i
    } else {
        // span <= 3: 用 rec 起点附近 C0[startBar] 的价与 C0[i] 比较，更新 rec->ZG/ZD/GG/DD 与下标
        rec->endBar = i;
        ... 调 0x1000edb0 / 0x1000edd0
        return i;
    }
}
// 失败/拒收口: 0x1000fa6b / 0x1000fac1 / 0x1000fb04 / 0x1000fb5f / 0x1000fc08 (全为 or eax,-1; ret 8)
```
**新增调用**：`0x1000f200`（找前段）、`0x1000edb0` / `0x1000edd0`（极值记录器，本批未展开 [C]）。

---

## WIP-A 勘误（本批自查）— ZG/ZD 是 min/max 对偶，前表推导已修正

WIP-A 初稿对 x87 分支目标判读有误。逐条重核 `fnstsw ax` + `test ah,K` + `jp/jnp/jne/je` 的**跳转目标**后：

| 字段 | 指令 | 判据（ST vs src） | 取值 | 结论 |
|---|---|---|---|---|
| `+0x19` | `1000f930 test ah,1 / jne 0x1000f958` | jne ⇒ C0=1 ⇒ ST<src ⇒ 跳**取 ST(小)**；不跳 ⇒ C0=0 ⇒ ST≥src ⇒ **取 src(小)** | **min** | **ZG = min(相邻两高点)** |
| `+0x25` | `1000f979 jp 0x1000f982` | jp ⇒ (ah&0x41)∈{0,0x41} ⇒ ST>src 或 unordered ⇒ 跳**取 ST(大)**；不跳 ⇒ ST≤src ⇒ **取 src(大)** | **max** | **ZD = max(相邻两低点)** |
| `+0x31` | `1000f9a5 test ah,5 / jp 0x1000f9b7` | jp ⇒ ST>src（跳过更新，保留 src）⇒ 大；不跳 ⇒ ST<src ⇒ 取 ST ⇒ 大 | **max** | **GG = max(高点)** |
| `+0x3d` | `1000f9ca test ah,0x41 / jne 0x1000f9dc` | jne ⇒ ST≤src ⇒ 保留 src(小)；不跳 ⇒ ST>src ⇒ 取 C0[i+2](小) | **min** | **DD = min(低点)** |

⇒ 修正后与缠论定义**完全一致**：`ZG = min(高点集)`、`ZD = max(低点集)`、`GG = max(高点)`、`DD = min(低点)`。
（初稿误把 `+0x25` 写成 min —— 实际 `jp` 落在 0x1000f982 的 `fld [ebx]`(C0[i+2].p2) 支，是取大者。）
额外佐证：`0x1000fa40` 的**中枢重叠门** `dir==-1 ⇒ rec.ZG >= C0[i].p2(=low) ∧ rec.ZD <= C0[i].p1(=high)` ⟺ 区间 `[ZD,ZG]` 与 bar 的 `[low,high]` 相交 ⇒ **ZG 必为上沿、ZD 必为下沿** [A]。
且 `0x1000fa40` 扩展支把 `+0x19` 取 min / `+0x25` 取 max（同样判据），与 init 支一致（前表疑「矛盾」**消解**）。

### C0 记录 p1/p2/p3 语义 [A]（本批由重叠门反证）
- `C0[t].p1 (+0x19) = 高(high)`、`C0[t].p2 (+0x21) = 低(low)` ⇒ ZG/ZD/GG/DD 的取极值对象自洽。
- `C0[t].p3 (+0x29)`：`0x10011170` 中要求 `p3[endBar] < p3[startBar]`（dir==-1 支）而 `p1[endBar] > p1[startBar]` ⇒ p3 与 high 反向变动 ⇒ 疑 `收盘/中间价` [B]。

---

## WIP-B — T1: 8 支逐支定位与调用关系（★ 全部上游 = `0x1000f680` buildSegment）

| # | 地址 | 签名 | 角色（本批定名） | 下游调用 | 关键写点 |
|---|---|---|---|---|---|
| 1 | `0x1000f8c0` | `ret 8`；`ecx`=rec，`eax`=engine，栈(i,n) | **seg_init**（段初始化 + 4 极值对抽样 + 尾部派发） | `0x1000f180`、`0x10010ee0`、`0x10010f80` | 写 rec `+8/+0xc/+0x10/+0x15/+0x19/+0x21/+0x25/+0x2d/+0x31/+0x39/+0x3d` |
| 2 | `0x1000fa40` | `ret 8`；`edi`=rec，栈(engine,i) | **seg_extend**（候选 bar 归属判定 + 极值更新） | `0x1000f200`、`0x1000edb0`、`0x1000edd0` | 写 rec `+0xc/+0x15/+0x19/+0x21/+0x25/+0x2d/+0x31/+0x39/+0x3d` |
| 3 | `0x1000fc60` | `ret 0xc`；`eax`=rec，栈(engine,i,*flag) | **seg_endcheck**（收尾判定，`*flag`=1/2） | `0x1000fc10`、`0x1000f180`、`0x1000f1c0` | `*flag`；读 rec `+0/+8/+0xc/+0x10/+0x2d/+0x39` |
| 4 | `0x1000ff80` | `ret 8`；`eax`=engine，栈(rec,mode) | **seg_wrapup**（收尾主流程 + 递归再建段） | `0x1000fdf0`、`0x10010070`、`0x100100d0`、`0x100101c0`、`0x100102c0`、`0x10010d60`、`0x1000fe50`、`0x1000f0e0`、`0x1000f070`、`0x1000f010`、**`0x1000f680`×2（递归）**、`0x1000f200`、`0x100104e0` | rec `flags = (flags&~1)\|2`（`0x10010014`）、rec `+0xc` |
| 5 | `0x10010ee0` | `ret 4`；`ecx`=engine，`eax`=rec，`esi`=barIdx，栈(rec2) | **c2_reg_up**（C2 登记，dir==+1 支） | `0x1000edf0` | C2[esi] `+0/+4+slot*4/+0x14+slot`；rec2 `+0x45+slot*4`；rec2 `flags\|=4` |
| 6 | `0x10010f80` | 无栈参；`ecx`=engine，`ebx`=rec，`esi`=barIdx | **c2_reg_down**（C2 登记，dir==-1 支） | `0x1000edf0` | 同上；读取 `C0[esi][+0x11]`（vs 0x10010ee0 取 `+0x15`） |
| 7 | `0x10011170` | `ret 4`；`eax`=engine，栈(rec) | **seg_finalize**（段输出/C3 写入 + 插值） | `0x1000f200`、`0x1000f260`/`0x1000f370`、`0x100110a0`×2、`0x1000ee30`、`0x1000f0b0` | 读 rec `+8/+0xc/+0x10`；调 `0x1000ee30(engine, rec, slotByte)`；返回 rec[+0xc] |
| 8 | `0x10011360` | `ret 8`；`eax`=engine，栈(engine?,rec) | **seg_advance**（逐 bar 推进 + 端点重评） | `0x1000f200`、`0x1000f1c0`、`0x10011010`、`0x1000f0b0`、`0x100110a0`、`0x1000ee30`×3 | 读 rec `+8/+0xc/+0x10/+0x31/+0x3d`；调 `0x1000ee30` 带 slot 字节 `{5,6,0xfa,0xfb,0xfd,0xfc}` |

### 派发实现（`0x1000f680` = buildSegment 中央派发器，220 行）[A]
```c
int buildSegment(Engine* eng /*ecx*/, int i /*[ebp+8]*/, int n /*[ebp+0xc]*/, int mode /*[ebp+0x10]*/)
{
  if (C1.count >= C1.cap) return -1;                        // 0x1000f691
  rec = &C1[C1.count];  memset(rec, 0, 0x5d);               // 0x1000f6ac
  rec->mode = mode; rec->self = C1.count;                   // 0x1000f6bf / f6c8
  r = seg_init(rec, eng, i, n);                             // 0x1000f8c0  ★#1
  if (r < 0) return -1;
  seg_finalize(eng, rec);                                   // 0x10011170  ★#7
  for (k = r + 1; k < n; ) {
     e = seg_extend(rec, eng, k);                           // 0x1000fa40  ★#2
     if (e > 0) {                                            // 该 bar 是转折点
        seg_advance(eng, rec);                              // 0x10011360  ★#8
        if (seg_endcheck(eng, rec, &flag) > 0)              // 0x1000fc60  ★#3
            return seg_wrapup(eng, rec, flag);              // 0x1000ff80  ★#4
        break;
     }
     seg_advance(eng, rec);                                 // 0x1000f73a
     if (c2_reg_up(eng, rec, k) > 0) goto L_up;             // 0x10010ee0  ★#5
     if (c2_reg_down(eng, rec, k) > 0) goto L_down;         // 0x10010f80  ★#6
     if (C0[k].dir != rec->dir) break;
     k++;
  }
L_up:   ... if (rec->dir==+1) return seg_wrapup(eng,rec,1);      // 0x1000f7ed-7fd
L_down: ... if (rec->dir==-1) return seg_wrapup(eng,rec,1);      // 0x1000f842-850
L_tail: rec->flags |= 1;  return ...;                            // 0x1000f800 / f853 / f8a5
}
```

---

## WIP-C — 关键下游补解（4 支）⇒ C1 语义升级的**直证链**

### `0x1000edb0` / `0x1000edd0` = GG/DD 更新器 ★★ 独立复核 WIP-A 勘误 [A]
```c
// 0x1000edb0(esi = C0 下标, eax = engine, edx = rec)
if (C0[esi].p1 >  rec->GG) { rec->ggIdx(+0x2d) = esi; rec->GG(+0x31) = C0[esi].p1; }   // 取大
// 0x1000edd0
if (C0[esi].p2 <= rec->DD) { rec->ddIdx(+0x39) = esi; rec->DD(+0x3d) = C0[esi].p2; }   // 取小
```
- 判据直读：`fcomp [edx+0x31]; test ah,0x41; jne → skip` ⇒ 仅当 `C0.p1 > rec.GG` 才更新 ⇒ **`+0x31` = GG = max(high)**；`fcomp [edx+0x3d]; test ah,5; jp → skip` ⇒ 仅当 `C0.p2 <= rec.DD` 才更新 ⇒ **`+0x3d` = DD = min(low)**。
- 与 WIP-A 勘误**完全一致**（GG/DD），并给出 `+0x2d`/`+0x39` = 对应 bar 下标 [A]。

### `0x1000f0e0` = 段入册器（segment committer）★★★ [A]  `ret 4`，`esi`=rec，arg0=engine
```c
int commit_segment(Rec5D* rec /*esi*/, Engine* eng /*arg0*/)
{
   if (!rec) return -1;
   span = rec->endBar - rec->startBar + 1;  if (span > 3) eax = span; else eax = span;
   if (eax < 3) return -1;                                  // 段长门
   if (C1.count >= C1.cap) return -1;
   // A = C0[startBar+1] 的 idx（按 dir 取 +0x15 或 +0x11）
   t = &C0[rec->startBar + 1];
   rec->A (+0x55) = (t->dir == -1) ? t->idxA(+0x15) : t->idxB(+0x11);
   // B = C0[endBar 或 endBar-1] 的 idx（同规则）
   u = &C0[(span > 3) ? rec->endBar : rec->endBar - 1];
   rec->B (+0x59) = (u->dir == -1) ? u->idxB(+0x15) : u->idxA(+0x11);
   C1.count += 1;                                            // ★ 段正式入册
   return rec->endBar;
}
```
> ⇒ **`rec+0x55`(A) / `rec+0x59`(B) 是「输出 bar 区间」**，值取自 **C0 记录的 `idx` 字段**（`+0x11`/`+0x15`，即分型点所在 bar），**不是** startBar/endBar 原值 —— G/D worker 读 `[ptr]`/`[ptr+4]` 即此二值 [A]（docs/32 的 [B] 升级）。
> 且此函数**唯一**执行 `C1.count++` ⇒ 它是「段」从缓冲区转为**有效产出**的唯一闸口。

### `0x1000f200` = 前段查找器 [A]  `ret 4`，`esi`=engine，`eax`=起扫下标(内部 -1)，arg0=dir 过滤(0=任意)
从 `C1[eax-1]` 向前扫，返回**首个** `flags.bit0=1 ∧ span>3 ∧ (dir==arg0 ∨ arg0==0)` 的段下标；无则 -1。

### `0x1000edf0` = slot 归一化（jump-table 恒等映射 0..3）[B]
`jmp [eax*4 + 0x1000ee0c]`；表项指向 4 个 `ret` 常量桩（返回 0/1/2/3）。调用点处 `cmp eax,8; ja skip` 作为使用前界检 ⇒ 该函数实为「slot 合法性归一」。

---

## WIP-D — 语义汇总（供 T2 落表）

| 结论 | 证据 | 置信 |
|---|---|---|
| `C1+0x19` = **ZG = min(high)** | 1000f930/933 + 1000fa40 重叠门 + 与 GG 对偶 | A |
| `C1+0x25` = **ZD = max(low)** | 1000f979 + 重叠门 `ZD <= high` | A |
| `C1+0x31` = **GG = max(high)** | `0x1000edb0` 判据直读 | A |
| `C1+0x3d` = **DD = min(low)** | `0x1000edd0` 判据直读 | A |
| `C1+0x15/+0x21/+0x2d/+0x39` = ZG/ZD/GG/DD 的 bar 下标 | 1000f93b/f960、1000f97d/f988、1000edb0、1000edd0 | A |
| `C1+0x08/+0x0c` = startBar/endBar（endBar 随扫描前推） | 1000f917、1000fad?/fb2d/fb7a、0x1000f680 多处 | A |
| `C1+0x10` = dir(±1)，源自 `C0[startBar].dir` | 1000f91a/91d | A |
| `C1+0x14` flags：bit0=有效(`0x1000f680` 三处 `or ..,1`)、bit1=2「已收尾」(`0x10010014`)、bit2=4「端点确认」(`0x10010f5f`/`0x10010ff7`) | 直读 | A(bit0/1/2) |
| `C1+0x45+slot*4` = 该 slot 的 bar 下标；slot 字节 ∈ {3,4,5,6,0xfa,0xfb,0xfc,0xfd} | 10010f55 / 10010fed / 0x1000ee30 调用点的 `al` | B |
| `C1+0x55/+0x59` = A/B 输出 bar 区间（取 C0 的 idx） | `0x1000f0e0` | A |
| `C2[esi]`（stride 0x18）：`+0x00`=C0 idx、`+4+slot*4`=段指针、`+0x14+slot`=标志字节 | 10010f3e-f50 / 10010fd6-fe8 | A |
