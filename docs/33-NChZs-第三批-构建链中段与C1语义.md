# NChZs 族第三批 —— 构建链中段 8 支与 C1 段记录语义升级

- **批次**：NChZs 族第三批（监控方派发 2026-10-17 06:47）
- **目标**：① 逐支展开构建链中段 8 支；② 把 C1 段记录的 bar 区间/方向/极值字段由「[A 偏移]」升到「[A 语义]」；③ 画出构建链全图
- **批前基线**：docs/31（入口链与三支骨架）、docs/32（核心体引擎 + 引擎五容器与 C0/C1 布局、stride 0x5d）
- **口径**：frida 动态验证**本轮不运行**（无人值守）；本批为**纯静态**，全部结论以反汇编指令直证 + 交叉印证分级标注
- **产物**：本文件 + `tools/re-inventory/nchzs/{build_chain_mid.txt, chzs_c1_semantics.txt, nchzs_build_graph.txt, nchzs3_wip.md}` + 24 份新反汇编/条件表 + `pseudocode/nchzs.c` §8–§10

---

## 一、背景与目标

docs/32 定位了「引擎」（`this[+0x18]`，ctor `0x1000e7c0`，虚表 `0x1001549c`）与其五容器，并把中枢段记录（C1，stride 0x5d）的字段标到 `[A 偏移]` 层级——即「哪里是 0x19 / 0x25」已知，但「它到底等于什么、哪个指令写、取值从哪来」未闭合。

本批沿 `build`（`0x1000ebe0`）→ `buildSegment`（`0x1000f680`）这条主干，把中段 8 支全部展开，并用**下游直证**（`0x1000edb0`/`0x1000edd0` 的判据、`0x1000f0e0` 的入册赋值）把 C1 语义钉死。

---

## 二、摘要表

| # | 地址 | 签名 | 角色（本批定名） | x87 条件 | 关键写点 |
|---|---|---|---|---|---|
| 1 | `0x1000f8c0` | `ret 8`；`ecx`=rec，`eax`=engine，栈(i,n) | **seg_init** | 6 | rec `+8/+0xc/+0x10/+0x15/+0x19/+0x21/+0x25/+0x2d/+0x31/+0x39/+0x3d` |
| 2 | `0x1000fa40` | `ret 8`；`edi`=rec，栈(engine,i) | **seg_extend** | 10 | rec `+0xc/+0x15/+0x19/+0x21/+0x25/+0x2d/+0x31/+0x39/+0x3d` |
| 3 | `0x1000fc60` | `ret 0xc`；`eax`=rec，栈(engine,i,\*flag) | **seg_endcheck** | 4 | `*flag` ∈ {1,2} |
| 4 | `0x1000ff80` | `ret 8`；`eax`=engine，栈(rec,mode) | **seg_wrapup**（含递归） | 0 | rec `flags = (flags&~1)\|2` |
| 5 | `0x10010ee0` | `ret 4`；`ecx`=eng，`eax`=rec，`esi`=idx，栈(rec2) | **c2_reg_up**（dir=+1 登记） | 1 | C2[esi] `+0/+4+slot*4/+0x14+slot`；rec2 `+0x45+slot*4`；`flags\|=4` |
| 6 | `0x10010f80` | 无栈参；`ecx`=eng，`ebx`=rec，`esi`=idx | **c2_reg_down**（dir=−1 登记） | 1 | 同上（取 C0 `+0x11` vs `+0x15`） |
| 7 | `0x10011170` | `ret 4`；`eax`=engine，栈(rec) | **seg_finalize**（段输出/插值） | 9 | 经 `0x1000ee30` 写 C3 |
| 8 | `0x10011360` | `ret 8`；`eax`=engine，栈(engine?,rec) | **seg_advance**（推进 + 端点重评） | 5 | 经 `0x1000ee30` 写 C3（slot ∈ {5,6,0xfa,0xfb,0xfd,0xfc}） |

> ★ 8 支的**唯一上游**都是 `0x1000f680`（buildSegment 中央派发器）——用 `grep call` 交叉验证，无例外。

**C1 段记录语义升级要点（T2 结论）**：

| 字段 | 语义（升级后） | 判据 |
|---|---|---|
| `+0x19` | **ZG = min(相邻高点)** | `1000f933`（min 判据）+ extend 支同判据 |
| `+0x25` | **ZD = max(相邻低点)** | `1000f979` + `0x1000fa40` 重叠门 `ZD <= high` |
| `+0x31` | **GG = max(高点)** | `0x1000edb0` 判据直读：`C0.p1 > rec.GG` 才更新 |
| `+0x3d` | **DD = min(低点)** | `0x1000edd0` 判据直读：`C0.p2 <= rec.DD` 才更新 |
| `+0x15/+0x21/+0x2d/+0x39` | 上述四值各自的 **bar 下标** | `1000f93b/…/1000edc8/1000ede8` |
| `+0x55 / +0x59` | **A / B = 输出 bar 区间（取 C0 的 idx 字段）** | `0x1000f0e0`（段入册器，唯一 `C1.count++`） |

---

## 三、T1 构建链中段 8 支逐支展开

> 完整汇总表见 `tools/re-inventory/nchzs/build_chain_mid.txt`。栈槽一律按「callee 内读 `[esp+X]` 前有 push 时 +4 修正」逐代码点换算。

### 3.1 `0x1000f8c0` — seg_init（段初始化 + 4 极值对抽样）[A]

`ret 8`；`ecx` = 段记录（输出），`eax` = engine，栈 arg0 = i，arg1 = n。

```c
int seg_init(Rec5D* rec /*ecx*/, Engine* eng /*eax*/, int i, int n)
{
    if (!rec)           return -1;                       // 1000f8c0 test ecx,ecx
    if (i < 0)          return -1;                       // 1000f8d4
    if (i + 3 > n)      return -1;                       // 1000f8da lea eax,[ebp+3]; cmp [esp+0x18]
    C0 = eng[+0x20];
    // ── 入口门（按 dir 分两支）
    if (C0[i].dir == -1) { if (!(C0[i].p2 > C0[i+2].p1)) return -1; }   // 1000f903
    else                 { if (!(C0[i].p1 > C0[i+2].p2)) return -1; }   // 1000f944
    // ── 共享体（0x1000f90d .. 0x1000f9dc）
    rec->endBar   = i + 2;                               // 1000f914 [ecx+0xc]
    rec->startBar = i;                                   // 1000f917 [ecx+8]
    rec->dir      = C0[i].dir;                           // 1000f91a/91d [ecx+0x10]
    rec->ZG  = min(C0[i].p1, C0[i+2].p1); rec->zgIdx = <取者>;   // 1000f924-f967 → +0x15/+0x19
    rec->ZD  = max(C0[i].p2, C0[i+2].p2); rec->zdIdx = <取者>;   // 1000f96a-f98f → +0x21/+0x25
    rec->GG  = max(C0[i].p1, C0[i+2].p1); rec->ggIdx = <取者>;   // 1000f995-f9b4 → +0x2d/+0x31
    rec->DD  = min(C0[i].p2, C0[i+2].p2); rec->ddIdx = <取者>;   // 1000f9ba-f9d9 → +0x39/+0x3d
    // ── 尾部派发
    k = sub_1000f180(...);                               // 1000f9ed
    if (k < 0 || k >= eng[+0x3c]) return rec->endBar;    // 1000f9f4/f9f6/f9f9
    if (rec->dir == -1) sub_10010ee0(*(C1base + k*0x5d));   // 1000fa0c  → c2_down 侧
    else                sub_10010f80(...);                  // 1000fa24
    return rec->endBar;
}
```

**★ 本批最大收获**：段记录不是「只有 ZG/ZD 两值」，而是 **4 组「(bar 下标, 价)」对**：ZG/ZD 是中枢上/下沿，GG/DD 是段内最高/最低 —— 恰好对应缠论「中枢四值」。

### 3.2 `0x1000fa40` — seg_extend（候选 bar 归属判定 + 极值更新）[A]

`ret 8`；`edi` = rec，栈 arg0 = engine，arg1 = i。

```c
int seg_extend(Rec5D* rec /*edi*/, Engine* eng /*arg0*/, int i)
{
    if (i < 0 || i >= eng[+0x2c]) return -1;             // C0 越界门
    if (C0[i].dir == rec->dir)    return -1;             // 方向相同 ⇒ 非转折点
    if (eng[+0x00] != 0) {                               // 非首段
        k = sub_1000f200(eng[+0x3c], rec->dir);          // 1000fa7e 查前段
        if (k >= 0) {
            prev = &C1[k];
            if (prev->dir == rec->dir) {
                if (rec->dir == -1) { if (prev->GG <  C0[i].p2) goto alt; }   // 1000fa99
                else                { if (prev->DD >  C0[i].p1) goto alt; }   // 1000faae
            }
        }
    }
common:
    span = rec->endBar - rec->startBar + 1;
    if (span > 3) {                                      // 1000fad5 setg
        // ★ 中枢重叠门
        if (rec->dir == -1) { if (!(rec->ZG >= C0[i].p2 && rec->ZD <= C0[i].p1)) return -1; }
        else                { if (!(rec->ZD <= C0[i].p1 && rec->ZG >= C0[i].p2)) return -1; }
        // 通过 ⇒ rec->endBar = i ; sub_1000edb0(engine,rec,i) ; sub_1000edd0(engine,rec,i) ; return i
    } else {
        // 短段支: 与 C0[startBar] / C0[startBar+1] 比对, 重写 ZG/ZD/GG/DD 与其下标
        rec->endBar = i;
        // 1000fb7d-fbfb: 0x1000edb0 / 0x1000edd0 记录 GG/DD; +0x19/+0x25/+0x15/+0x21/+0x2d/+0x39 重写
        return i;
    }
}
```

**洞见**：`0x1000fa40` 是**段是否继续的判据中心**。判据不是一个阈值，而是「**当前 bar 的 [low,high] 是否与中枢区间 [ZD,ZG] 相交**」（`[ZD,ZG] ∩ [low,high] ≠ ∅`）——这也反过来证实 ZG 必为上沿、ZD 必为下沿。

### 3.3 `0x1000fc60` — seg_endcheck（收尾判定，`*flag` = 1/2）[A]

`ret 0xc`；`eax` = rec，栈 arg0 = engine，arg1 = i，arg2 = `int* flag`。

```c
int seg_endcheck(Rec5D* rec /*eax*/, Engine* eng, int i, int* flag)
{
    *flag = 1;
    eax = (rec && span > 3) ? span : (rec ? span : 0);
    if (eax >= eng[+0x1c]) return i;                     // = 9, ctor 常量 → 「够长了, 直接结束」
    if (rec->mode == 0) {                                // 1000fc93
        if (sub_1000fc10(eng) & 1) *flag = 2;            // 「密集」收尾标记
        return i;                                        // 1000fcaa
    }
    // mode != 0: 取候选段 k = sub_1000f180(...) ; 逐门校验:
    //   段存在 ∧ dir 相同 ∧ 其 span <= 3 (1000fcdb-cde1) ∧
    //   endBar 一端对齐 (rec 的 +0x2d/+0x39 与 k 段的 endBar 相等关系)
    //   ∧ 极值单调 (fcomp C0.p2 / C0.p1 比较)
    // 全通过 ⇒ return i ; 否则 return -1 (0x1000fd40)
}
```

### 3.4 `0x1000ff80` — seg_wrapup（收尾主流程 + **递归再建段**）[A]

`ret 8`；`eax` = engine（`edi`），栈 arg0 = rec，arg1 = mode。

```c
int seg_wrapup(Engine* eng /*eax*/, Rec5D* rec /*ebp*/, int mode /*[esp+0x1c]*/)
{
    if (!rec) return -1;
    s = sub_1000fdf0(eng, rec);
    if (mode == 2) {                                     // 「密集」模式: 四次候选扫描
        if (sub_10010070(eng)        > 0) return mode;
        if (sub_100100d0(eng)        > 0) return mode;
        if (sub_100101c0(eng)        > 0) return mode;
        if (sub_100102c0(eng, rec)   > 0) return mode;
        s = rec->startBar;
    }
    if (sub_10010d60(eng, rec) > 0) return mode;
    k = sub_1000fe50(rec, s, rec->endBar, eng);          // 收尾评估
    if (k < 0) return -1;
    rec->flags = (rec->flags & 0xfe) | 2;                // ★ 10010014: bit1 = 已收尾
    sub_1000f0e0(eng);
    sub_1000f070(rec->endBar, rec->startBar);
    if (sub_1000f680(eng, rec->startBar, k + 1, rec) > k) return ...;   // ★★ 递归
    sub_1000f010(eng, k);
    if (sub_1000f680(eng, <cursor>, eng[+0x2c], rec) > ...) return ...; // ★★ 递归
    return ...;
}
```

**⇒ 构建链是「迭代 + 递归」双层**：外层 `build` 线性推进 `i`，内层 `buildSegment` → `seg_wrapup` 递归回调 `buildSegment` —— 与 docs/32「`0x1000f680` 只被 build 调用」的认知**修正**：`0x1000ff80` 内亦调用它 2 次。

### 3.5 `0x10010ee0` / `0x10010f80` — C2 端点登记器（dir=+1 / dir=−1）[A]

```c
int c2_reg_up(Engine* eng /*ecx*/, Rec5D* rec /*eax*/, int idx /*esi*/, Rec5D* newRec /*arg0*/)
{
    if (!newRec) return -1;
    if (idx < 0 || idx >= eng[+0x2c]) return -1;
    c0 = &C0[idx];
    if (c0->dir != +1)                return -1;         // 1000f01 cmp [eax+edx],1
    if (!(newRec->ZG > c0->p2))       return -1;         // 1000f0b-f16
    slot = 2;  slot = sub_1000edf0(slot);
    if (slot < 0 || slot > 8)         goto L_flag;       // 1000f25-f28
    if (c0->flags(+0x0c) & 1)         goto L_flag;       // 1000f33
    if (c0->dir != +1)                goto L_flag;
    C2base = eng[+0x40] + idx*0x18;                      // ★ stride 0x18
    C2base[+0x00]            = c0->idxB;                 // c0[+0x15]
    *(Rec5D**)(C2base+4+slot*4) = newRec;                // 段指针
    *(u8*)(C2base + 0x14 + slot) = 0xfd;                 // 标志字节
    newRec->slotBar[slot](+0x45+slot*4) = idx;           // bar 下标
L_flag:
    if (newRec->dir == +1) newRec->flags |= 4;           // 1000f5f
    return idx - 1;
}
```
`0x10010f80` 为对称支（`dir == -1`，取 `c0->idxA(+0x11)`，标志字节 `3`，`rec2->flags |= 4` 条件为 `dir == -1`）。

### 3.6 `0x10011170` — seg_finalize（段输出/插值）[A]

`ret 4`；`eax` = engine，栈 arg0 = rec。

```c
int seg_finalize(Engine* eng /*eax*/, Rec5D* rec /*edi*/)
{
    if (!rec) return -1;
    if (!(span > 3)) return -1;                           // 1000f19b setg / jne fail
    dir = rec->dir;
    if (dir == -1) {                                      // 1000f1ae
        if (!(C0[endBar].p1 > C0[startBar].p1)) return -1;   // 1000f1b6-c3 (jnp fail)
        if (!(C0[endBar].p3 < C0[startBar].p3)) return -1;   // 1000f1c8-d5
        slotByte = 4;                                      // 1000f1d7
    } else {
        if (!(C0[endBar].p2 < C0[startBar].p2)) return -1;   // 1000f1de-eb
        if (!(C0[endBar].p3 < C0[startBar].p3)) return -1;   // 1000f1f0-fd
        slotByte = 0xfc;                                   // 1000f1ff
    }
    k = sub_1000f200(eng[+0x3c], dir);                    // 1000f207
    if (k >= 0) prev = &C1[k];
    // ... 价格单调性复核 (1000f223-f5b) ...
    slot = (k >= 0) ? (dir == -1 ? 5 : 0xfb) : (dir == -1 ? 5 : 0xf9);   // 1000f32e-f4f
    sub_1000ee30(eng, slotByte/slot, rec, ...);           // ★ 写 C3
    return rec->endBar;
}
```
**注**：`p3` 与 `p1` 反向单调（`p1` 递增而 `p3` 递减）⇒ `p3` 非 high ⇒ 疑「收盘/中间价」[B]。

### 3.7 `0x10011360` — seg_advance（逐 bar 推进 + 端点重评）[A]

`ret 8`；`eax` = engine，arg0 = engine（`ebp`），arg1 = rec（`esi`）。

```c
int seg_advance(Engine* eng /*eax,ebp*/, Rec5D* rec /*esi*/)
{
    if (!rec) return -1;
    span = rec->endBar - rec->startBar + 1;
    if (!(span > 3))            return -1;               // 1000f383
    if (span >= eng[+0x1c](=9)) return -1;               // 1000f38a  ★「不再推进」上限
    i = rec->endBar + 1;
    if (i >= eng[+0x2c]) return -1;
    c0 = &C0[i];
    if (rec->dir == -1) { if (!(c0->p1 > rec->GG)) return -1; }   // 1000f3b3-bb
    else                { if (!(c0->p2 < rec->DD)) return -1; }   // 1000f3cd-d8
    k = sub_1000f200(eng[+0x3c], dir);
    sub_1000f1c0(eng, k);
    // ... 与 C0[startBar/+/-1] 的 p3 单调性 复核 ...
    slot = <按 ebx(=k) 与 dir 组合出的字节：5 / 6 / 0xfa / 0xfb>;
    sub_1000ee30(eng, slot, ...);                        // ★ 写 C3
    return rec;
}
```
**⇒ `engine[+0x1c] = 9` 的真实用途确认**：`seg_advance` 用它作「段长上限」（`span >= 9` 即停止推进）——docs/32 的「用途不明」[C] **撤销**，升级 [A]。

---

## 四、T2 C1 段记录语义升级（[A 偏移] → [A 语义]）

> 完整表见 `tools/re-inventory/nchzs/chzs_c1_semantics.txt`。以下为核心。

### 4.1 四组「(下标, 价)」对的赋值链 [A]

| 字段 | 语义 | 判据（本批直证） |
|---|---|---|
| `+0x19` **ZG** | 中枢**上沿** = `min(高点)` | `1000f930 test ah,1; jne 1000f958` ⇒ 跳转支取 ST（小） |
| `+0x25` **ZD** | 中枢**下沿** = `max(低点)` | `1000f979 jp 1000f982` ⇒ 跳转支取 C0[i+2].p2（大） |
| `+0x31` **GG** | 段内**最高** = `max(高点)` | `0x1000edb0`：`if (C0[esi].p1 > rec->GG) rec->GG = C0[esi].p1` |
| `+0x3d` **DD** | 段内**最低** = `min(低点)` | `0x1000edd0`：`if (C0[esi].p2 <= rec->DD) rec->DD = C0[esi].p2` |
| `+0x15/+0x21/+0x2d/+0x39` | 四值各自的 **bar 下标** | `1000f93b/f960`、`1000f97d/f988`、`1000edc8`、`1000ede8` |

→ 与缠论定义 `ZG = min(gn)`、`ZD = max(dn)`、`GG/DD = 段内极值` **完全一致** [A]。

### 4.2 bar 区间与方向 [A]

| 字段 | 语义 | 赋值点 |
|---|---|---|
| `+0x08` startBar | 段起始 bar | `1000f917 mov [ecx+8], ebp`（= i） |
| `+0x0c` endBar | 段当前终止 bar（**随扫描前推**） | `1000f914`(=i+2)、`1000fb2d`、`1000fb7a`；`0x1000f680` 多处 |
| `+0x10` dir | 方向 ±1，源自 `C0[startBar].dir` | `1000f91a/91d` |
| `+0x00` mode / `+0x04` self | 建段模式 / 自身下标 | `1000f6bf` / `1000f6c8` |

### 4.3 flags（`+0x14`）位台账 [A(bit0..2)]

| bit | 值 | 语义 | 置位点 |
|---|---|---|---|
| 0 | 1 | **段有效**（可被 find/输出/消费） | `0x1000f680` 三处 `or byte [edi+0x14], 1`（`1000f800`/`f853`/`f8a5`） |
| 1 | 2 | **已收尾**（wrapup 完成） | `0x1000ff80`：`10010008-fb0e` `cl = (flags & 0xfe) \| 2` |
| 2 | 4 | **端点已登记**（C2 层面确认） | `0x10010ee0` `1000f5f`（dir=+1）/ `0x10010f80` `10010ff7`（dir=−1） |
| 3..7 | — | 未定性 | — [C] |

### 4.4 ★ A / B 输出区间（`+0x55` / `+0x59`）[A] —— docs/32 的 [B] 升级

`0x1000f0e0`（**段入册器**，全链**唯一**执行 `C1.count++` 的闸口）：
```c
rec->A (+0x55) = C0[rec->startBar + 1].idx     // dir==-1 取 +0x15, 否则取 +0x11
rec->B (+0x59) = C0[(span>3 ? endBar : endBar-1)].idx   // 同规则
C1.count += 1;
```
⇒ G/D worker 读的 `[ptr]` / `[ptr+4]` 就是这两个 **bar 区间端点**，且其值取自 `C0` 记录的 `idx` 字段（分型点所在 bar），**不是** startBar/endBar 原值。

### 4.5 跨字段不变式（本批验证）

1. **区间嵌套**：`DD <= ZD <= ZG <= GG` [A]
2. **中枢重叠门**：当前 bar 的 `[low,high]` 必与 `[ZD,ZG]` 相交 [A]
3. **段方向门**：`C0[startBar].dir == rec->dir` [A]
4. **段长门**：建段初检需 `span > 3`（即 `i+3 <= n`）；`commit` 需 `span >= 3`；`find` 过滤 `span > 3`；`advance` 上限 `span < 9` [A]
5. **A/B 门**：A、B 取自分型点 bar 的 `idx` 字段 [A]

### 4.6 无法静态定性者（[B] + 最小实验）

| 点 | 内容 | 最小实验 |
|---|---|---|
| 1 | slot 字节 `{3,4,5,6,0xfa,0xfb,0xfc,0xfd}` 的语义（疑「段端点角色码」） | frida hook `0x1000ee30` 打印 `(rec->self, al, arg0, arg1, C3 目标下标)` |
| 2 | `+0x41` barIdx 的写点（8 支内未直证，疑由 `0x1000ee30` 写） | hook 后 dump C1 全部 rec，对照 Bs worker 读 `[ptr-0x14]` |
| 3 | `+0x45..0x54` 未定性（疑 slot 计数/角色位图） | 断点 `0x10010f55` 打印 `rec+0x45..0x54` |
| 4 | extend 短段支「与 `C0[startBar]` 比却取 `C0[startBar+1]` 值」是否原程序特性 | 构造 `span<=3 ∧ C0[i].p1 >= C0[startBar].p1` 输入，观察 `rec.ZG` 落点 |

---

## 五、T3 构建链全图

> 完整图见 `tools/re-inventory/nchzs/nchzs_build_graph.txt`（含 ASCII 图）。精简版：

```
TAFLib CalcProc_NChZs 0x10013240
   Authorize(EA61 | EA63 by this[+0xb8]) → Fetch6Buffers(0x10006cc0) → this[+0xb8]++ → vt[+0x78]
        │
chlib 核心体 0x100045f0  (ret 0x10)
   memset(out) → 门 → engine=this[+0x18]
   vt[+4] reset(0x1000e900) → vt[+0xc] setter(0x1000e0b0) → 0x1000e990(C0 生产)
   → vt[+8] build(0x1000ebe0) → 0x10006700
        │
   build 0x1000ebe0
     resize C1(n*2×0x5d) / C2(n×0x18) / C3(n×0x1d) → for(i<n) buildSegment(engine,i,n,0)
        │                                                                  ▲
        ▼                                                                  ║(递归 ×2)
   ┌── 0x1000f680 buildSegment(engine, i, n, mode) ─────────────────────────┘
   │  ① 0x1000f8c0 seg_init ── 写 startBar/endBar/dir + ZG/ZD/GG/DD(+下标)
   │         └─ 尾部派发 → 0x10010ee0 / 0x10010f80  (C2 端点登记)
   │  ② 0x10011170 seg_finalize ── 0x1000f200 → 插值 0x100110a0 → 0x1000ee30 写 C3
   │  ③ loop k:
   │       0x1000fa40 seg_extend (中枢重叠门) ─┐ >0 转折点
   │       0x10011360 seg_advance (span<9 上限)│
   │       0x1000fc60 seg_endcheck (*flag=1/2) ┤
   │       0x1000ff80 seg_wrapup ══▶ 递归 buildSegment  (flags: (f&~1)|2)
   │       0x10010ee0 / 0x10010f80 (C2 登记, flags |= 4)
   │  L_tail: rec->flags |= 1   ← 段有效
   │
   └─ 数据: price[] → C0(0x31/bar) → C1(0x5d 段) → C2(0x18) / C3(0x1d) → V(0x74) → out[]
```

**层责任速记**：
| 层 | 责任 |
|---|---|
| `0x1000ebe0` build | 容器装配 + 主循环 + C1→C3 后处理 |
| `0x1000f680` buildSegment | **单段**生命周期调度（8 支的顺序编排） |
| `0x1000f8c0` / `0x1000fa40` | 段的**起点锚定** / **终点推进与收束** |
| `0x1000fc60` / `0x1000ff80` | **收尾判定** / **收尾执行（含递归再建段）** |
| `0x10010ee0` / `0x10010f80` | 端点 → **C2 登记**（供 Bs worker 消费） |
| `0x10011170` / `0x10011360` | 段 → **C3 输出**（供 SelPri / L2M 消费） |
| `0x1000f0e0` | **段入册**（唯一 `C1.count++`） |
| `0x1000edb0` / `0x1000edd0` | GG / DD **极值更新器**（判据直证 C1 语义） |

---

## 六、勘误与待仲裁

1. **★ ZG/ZD 推导勘误（本批自查纠正）**：初稿把 `0x1000f979 test ah,0x41; jp 0x1000f982` 的跳转目标读反，误判 `+0x25` 为 min。逐条重核后：`jp` 落在 `1000f982`（`fld [ebx]` = `C0[i+2].p2`）支 ⇒ 取**大**者 ⇒ `+0x25` = **max(low)** = ZD。修正后与 `0x1000edb0/edd0` 的判据直证、与 `0x1000fa40` 的重叠门**三方自洽**。
2. **docs/32 §3.6「段生产者 0x1000f680」表述修正**：`0x1000f680` 不只被 `build` 调用 —— `0x1000ff80`（seg_wrapup）内**递归调用它 2 次**。构建链是「外层迭代 + 内层递归」双层结构。
3. **docs/32 §3.4 容器表补充**：C1 记录除 `+0x19/+0x25` 外还有 `+0x31/+0x3d`（GG/DD）与四个下标字段；原表「+0x21 属 C0 的勘误」在本批进一步明确 —— C1 的 `+0x21` 是 **zdIdx（下标，非价）**，与 C0 的 `+0x21`（low）是**同偏移不同容器**，两处解读均成立。
4. **docs/32「engine[+0x1c] = 9 用途不明 [C]」撤销**：`0x10011360 seg_advance` 用它作段长上限（`span >= 9` 停止推进）⇒ 升级 **[A]**。
5. **待仲裁 [B]/[C]**：见 §4.6 表（slot 字节语义、`+0x41` barIdx 写点、`+0x45..0x54`、extend 短段支的取指特性）。**本批未做动态验证**（frida 待用户在场）。

---

## 七、可复现命令

```bash
PY=C:/Users/Administrator/Documents/a_conda/python.exe
D=ronglide-app/chlib.dll

# T1 8 支反汇编（本批核心）
for a in 1000f8c0 1000fa40 1000fc60 1000ff80 10010ee0 10010f80 10011170 10011360; do
  $PY tools/re-inventory/disasm_func.py 0x$a --max 0x700 --dll $D \
      -o tools/re-inventory/nchzs/chlib_$a.txt
done

# T2 语义直证链（4 个关键下游）
for a in 1000edb0 1000edd0 1000edf0 1000ee30 1000f0e0 1000f200; do
  $PY tools/re-inventory/disasm_func.py 0x$a --max 0x300 --dll $D \
      -o tools/re-inventory/nchzs/chlib_$a.txt
done

# x87 条件表（8 支）
for a in 1000f8c0 1000fa40 1000fc60 1000ff80 10010ee0 10010f80 10011170 10011360; do
  $PY tools/re-inventory/x87_sim.py tools/re-inventory/nchzs/chlib_$a.txt \
      -o tools/re-inventory/nchzs/cond_chlib_$a.txt
done

# 上游/下游交叉验证（8 支唯一上游 = 0x1000f680）
cd tools/re-inventory/nchzs
for t in 1000f8c0 1000fa40 1000fc60 1000ff80 10010ee0 10010f80 10011170 10011360; do
  printf "%-10s <- " $t; grep -lE "call +0x$t" *.txt | tr '\n' ' '; echo
done
```

---

## 八、下一步（建议）

**首选**：**NChZs 第四批 —— 消费侧闭环 + 剩余基元**
- 展开 `0x1000ee30`（C3 写入器，138 行）：把「段 → C3/V」的映射与 slot 字节语义钉死（统一解决 §4.6 点 1/2/3）。
- 展开 `0x100110a0`（插值）/ `0x10011010`（价查询）：解释 SelPri 消费的 `V(0x74)` 四子记录从何而来。
- 展开 `0x1000fc10` / `0x1000fdf0` / `0x1000fe50` / `0x10010d60` 四支收尾辅助。

**次选**：**NChZsFj / NChZsDg / NChZsHLTurn**（EA63+EA61，族内尚未触碰的三支）。

**第三**：`NChZsL2M`(0x100048a0) 分块收口（按支配树切 ~6 段 + x87 条件表逐段复核；本批已证无递归，故无需追栈）。

**可选（需用户在场）**：frida 挂 `0x1000f680` / `0x1000ee30`，dump C1 段记录与 C3 输出，把本批全部 [B] 升 [A]。
