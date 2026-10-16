# NChZs 族第四批 —— 消费侧闭环 + 剩余基元

- **批次**：NChZs 族第四批（监控方派发 2026-10-17 06:56）
- **目标**：① 钉死 `0x1000ee30`（C3/C2 写入器）的 slot 字节语义；② 解释 SelPri 消费的 V(0x74) 四子记录的产线（`0x100110a0`/`0x10011010`）；③ 补完四支收尾辅助
- **批前基线**：docs/31（入口链 + 三支骨架）、docs/32（核心体引擎 + 容器布局）、docs/33（构建链中段 8 支 + C1 段记录语义）
- **口径**：frida 动态验证**本轮不运行**（无人值守）；本批为**纯静态**，结论以反汇编指令直证 + 交叉印证分级标注
- **产物**：本文件 + `tools/re-inventory/nchzs/{c3_slot_semantics.txt, v_pipeline.txt, build_chain_tail.txt, nchzs4_wip.md}` + 11 份新反汇编 / 7 份 x87 条件表 + `pseudocode/nchzs.c` §12–§14

---

## 一、背景与目标

docs/33 把 C1 段记录语义钉到了 ZG/ZD/GG/DD 四值 + 四下标 + A/B 输出区间，但留下三个洞：

1. **slot 字节语义未定**——`0x1000ee30` 的入参 `al`（∈ {3,4,5,6,8,0xfa,0xf8,0xfb,0xfc,0xfd}）究竟落到 C2 的哪个槽、符号干什么用；
2. **消费侧产线未闭环**——SelPri 读的 V（`engine[+0x5c]/[+0x60]`，元素 0x74 = 4 × 0x1d）是谁写进去的；
3. **构建链尾部四支未展开**——`0x1000fc10 / 0x1000fdf0 / 0x1000fe50 / 0x10010d60`（收尾 / 分裂 / 递归再建）。

本批即针对这三点，把「构建 → 段 → C2 并发槽 → V 子记录 → SelPri 输出」这条消费侧链路闭合。

---

## 二、摘要表

| # | 地址 | 签名 | 角色（本批定名） | x87 | 关键结论 |
|---|---|---|---|---|---|
| T1 | `0x1000ee30` | `ret 8`；`ebp`=engine，`[esp+8]`=rec，`ecx`=i，`al`=slot(s8) | **seg_register**（C3/C2 写入器） | 2 | C2[i] 4 并发槽登记；slot 归一化 + 方向门 + 镜像分支 |
| T1b | `0x1000edf0` | `jmp [eax*4+0x1000ee0c]` | **slot 归一化跳转表** | 0 | 9 项表 → 4 槽（只取决于 \|slot\|） |
| T2a | `0x10011010` | `ret 4`；`eax`=a，`ebx`=b，arg0=engine | **sum_p3** 区间 p3 求和 | 6 | `Σ_{i∈[a,b]} C0[i].p3` |
| T2b | `0x100110a0` | `ret 8`；`edx`=a，arg1=b，arg0=engine，`edi`=dir | **sum_p3_dir** 同向 p3 求和 | 6 | `Σ C0[i].p3` 且 `C0[i].dir == edi` |
| T2c | `0x1000ed20` | `ret 4`；`ecx`=engine，arg=mode | **engine vt[+0x10] dispatch** | 0 | mode 1→`0x10011500` / 2→`0x10011660` / 0x65→`0x100117b0` |
| T2d | `0x10011500` / `0x10011660` / `0x100117b0` | 见 §4.3 | ★ **V 生产者**（三 mode） | 0 | 组装 0x1d 子记录 → `0x10011a70` push |
| T2e | `0x10011a70` | `eax`=elem，`esi`=&V | ★ **V.push_back**（单 0x1d） | 0 | 容量按 0x74 组计量；不足时 `0x10011c40` |
| T2f | `0x10012550` | `eax`=first，`ebx`=last，arg=dest | **V 紧致化原语** | 0 | `0x1d` 块搬移，长度按 `0x74` 计量 |
| T3-1 | `0x1000fc10` | `ret`；`eax`=engine，`ebx`=rec | **seg_overlap_check** | 2 | 前一同向段 `[DD,GG]` 相交谓词 → bool |
| T3-2 | `0x1000fdf0` | `ret`；`ebx`=rec，`edi`=engine | **find_prev_valid** | 0 | 向前找首个同向有效段 |
| T3-3 | `0x1000fe50` | `ret 0xc` | **scan_candidate** | 2 | 局部 vector(stride 0xc) + 相邻 C0 区间相交门 |
| T3-4 | `0x10010d60` | `ret 4`；`ecx`=engine，`ebx`=rec | ★ **split_rebuild** | 8 | `flags\|=2` + 入册 + 递归 `0x1000f680` ×2 |

---

## 三、T1 —— `0x1000ee30`：C3/C2 写入器与 slot 字节语义

### 3.1 签名（栈槽逐点换算，4 处调用点直证）[A]

```
进入 esp=P；序言 push ebx/ebp/esi/edi ⇒ 体内 esp = P-0x10
sub_1000ee30(engine /*arg0, ebp*/, rec /*arg1, 压栈*/, i /*ecx*/, slot /*al*/)
   arg0=engine : [ebp+0x2c]=C0.count, [ebp+0x20]=C0.base, [ebp+0x40]=C2.base
   arg1=rec    : 段记录（写 rec[+0x45+s*4] = i）
   ecx = i     : bar 下标
   al  = slot  : signed char（符号 = 方向档）
```

调用点（4 处，全部在构建链内）：`0x1001126a`(seg_finalize)、`0x1001146b` / `0x10011484` / `0x100114e7`(seg_advance)。调用点直证形态：

```asm
10011459  cmp   dword ptr [eax + 0x10], -1     ; rec->dir
10011466  mov   al, 6                          ; slot = 6   (dir==-1 支)
1001147f  mov   al, 0xfa                       ; slot = 0xfa(dir!=-1 支)
10011469  mov   ecx, esi                       ; i
10011468  push  ebp                            ; engine (arg0)
10011465  push  ecx                            ; rec    (arg1)
1001146b  call  0x1000ee30
```

### 3.2 主体流程 [A 结构]

```c
void sub_1000ee30(Engine* eng, Rec* rec, int i, signed char slot)
{
  if (rec == 0) return;                                     // 1000ee30
  if (i < 0 || i >= eng->count /*[+0x2c]*/) return;          // 1000ee46 / ee4e
  if (abs(slot) - 1 > 8) return;                             // 1000ee57..ee65  (slot ∈ ±1..±9)
  s = 0x1000edf0(abs(slot) - 1);                             // 1000ee6b  ★ 归一到 0..3
  if (s < 0) return;
  Rec31* c0 = &C0[i];                                        // [+0x20] + i*0x31
  if (c0->mark /*[+0xc]*/ & 1) return;                        // 1000ee82  该 bar 已登记
  if (slot < 0 && c0->dir /*[+0x00]*/ != +1) return;          // ★ 方向门
  if (slot > 0 && c0->dir                != -1) return;       // ★ 方向门
  /* ---- 主写 (C2[i], stride 0x18) ---- */
  C2[i].id       (+0x00)     = (c0->dir == -1) ? c0->idxA(+0x11) : c0->idxB(+0x15);
  C2[i].ptr      (+4 + s*4)  = rec;
  C2[i].slotB    (+0x14 + s) = slot;
  rec[+0x45 + s*4]           = i;
  /* ---- 镜像分支（仅 slot ∈ {6, 8, 0xfa, 0xf8}）---- */
  if (slot == 0xfa || slot == 0xf8) goto MIRROR_A;
  if (slot == 6    || slot == 8)    goto MIRROR_B;
  return;
MIRROR_B:                          // 0x1000eeeb
  j = i + 2;  if (j >= eng->count) return;
  if (!(C0[j].p1(+0x19) < C0[i].p1)) return;                 // fld/fcomp + test ah,5 + jp
  if (C0[j].mark & 1) return;
  newSlotRaw = (slot == 6) ? 9 : 2;                          // (slot!=6)-1 & 7 + 2
  goto EMIT2;
MIRROR_A:                          // 0x1000ef4a
  j = i + 2;  if (j >= eng->count) return;
  if (!(C0[j].p2(+0x21) > C0[i].p2)) return;                 // fld/fcomp + test ah,0x41 + jne
  if (C0[j].mark & 1) return;
  newSlotRaw = (slot == 0xfa) ? 0xF7 : 0xFE;                 // (slot!=0xfa)-1 & 0xF9 + 0xFE
EMIT2:
  s2 = 0x1000edf0(abs((signed char)newSlotRaw) - 1);         // ★ 两条路径均 → 槽 1
  C2[j].id = (C0[j].dir == -1) ? C0[j].idxA : C0[j].idxB;
  C2[j].ptr[+4 + s2*4]  = rec;
  C2[j].slotB[+0x14+s2] = newSlotRaw;                        // 存「原始字节」（9 / 2 / 0xF7 / 0xFE）
  rec[+0x45 + s2*4]     = j;
}
```

### 3.3 ★ `0x1000edf0` = slot 归一化跳转表（9 项 → 4 槽）[A]

```
形态: jmp dword ptr [eax*4 + 0x1000ee0c]
表体: 0x1000ee0c .. 0x1000ee2f = 9 × 4 = 0x24 字节（末尾恰接函数体 0x1000ee30）
目标桩: 0x1000edf7(ret 0) / 0x1000edfa(ret 1) / 0x1000ee00(ret 2) / 0x1000ee06(ret 3)
```

| idx = \|slot\|−1 | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
|---|---|---|---|---|---|---|---|---|---|---|
| **返回槽** | 0 | 1 | 2 | 3 | 3 | 3 | 3 | 0 | 1 |

映射回 slot 字节（**只取决于 \|slot\|；符号仅决定方向门**）：

| raw slot | 有符号 | \|slot\|−1 | 归一槽 |
|---|---|---|---|
| `3` | +3 | 2 | **2** |
| `4` | +4 | 3 | **3** |
| `5` | +5 | 4 | **3** |
| `6` | +6 | 5 | **3** |
| `8` | +8 | 7 | **0** |
| `0xfd` | −3 | 2 | **2** |
| `0xfc` | −4 | 3 | **3** |
| `0xfb` | −5 | 4 | **3** |
| `0xfa` | −6 | 5 | **3** |
| `0xf8` | −8 | 7 | **0** |

> ⇒ C2 的 **4 个并发槽**：槽 2 = 「±3」档；槽 3 = 「±4/±5/±6」档；槽 0 = 「±8」档；槽 1 仅由镜像分支写入。
> 第一批列出的 `{3,4,5,6,0xfa,0xfb,0xfc,0xfd}` 本批**补齐 `+{8, 0xf8}`**（同落槽 0）。[A]

### 3.4 C2 记录布局（stride 0x18）[A]

| 偏移 | 类型 | 语义 | 写点 |
|---|---|---|---|
| +0x00 | i32 | C0 分型 id（dir==−1 取 `+0x11`(idxA)，否则 `+0x15`(idxB)） | 1000eec4 / 1000efb9 |
| +0x04 + s*4 | ptr | 段记录指针 `rec`（按归一槽 s = 0..3） | 1000eeca / 1000efbf |
| +0x14 + s | i8 | 该槽的 **slot 原始字节**（不归一） | 1000eece / 1000efc3 |

> ⇒ `0x1000ee30` 是**唯一**把「C1 段记录」登记进 **C2 并发槽** 的写入器。段侧 `rec[+0x45+s*4]` 回存 bar 下标；`0x10011500` 系列即以 `C2[i].slotB[0]/[3]` 的符号挑选 `ptr[0]/ptr[3]` 作为 V 生产入口（见 §4）。

---

## 四、T2 —— 消费侧产线闭环（V 向量的 0x74 组四子记录从何而来）

### 4.1 结论速览

- ✅ SelPri 消费的 V(0x74) 四子记录 **由 `engine vt[+0x10]`（`0x1000ed20`）dispatch 的三个 mode 生产者**（`0x10011500` / `0x10011660` / `0x100117b0`）组装、经 **`0x10011a70`（V.push_back）** 写入。
- ❌ 任务书设想的「`0x100110a0`/`0x10011010` 是 V 生产者」**不成立**：两支是 **C0[i].p3 的区间求和器**，用于**段评分 / 区间对比**（§4.2）。
- ⚠️ 第三批对子记录偏移的记录（`+0x00` / `+0x04`）**错位 1 字节**，本批校正（§4.4）。

### 4.2 `0x10011010` / `0x100110a0` —— 区间 p3 求和（段评分）[A 结构 / B 语义]

```c
double sum_p3     (Engine* eng /*arg0*/, int b /*ebx*/, int a /*eax*/)      // 0x10011010, ret 4
{ ST0 = Σ_{i=a..b} C0[i].p3 /*+0x29*/; }                                   // 无方向过滤，4 路展开 + 尾循环
double sum_p3_dir (Engine* eng /*arg0*/, int b /*arg1*/, int a /*edx*/, int dir /*edi*/)  // 0x100110a0, ret 8
{ ST0 = Σ_{i=a..b, C0[i].dir /*+0x00*/ == dir} C0[i].p3; }
```

- 结果留在 **ST(0)**（f64 返回值）；循环单位是 **C0 下标 = bar 下标**（C0 每 bar 一条记录）。
- **直证用途**：`0x10011360` @10011442 先 `call sum_p3` 再 `fcomp [edi+0x29]`（当前 C0 记录的 p3）；
  `0x10011170` @100112ff / @10011314 **连调 `sum_p3_dir` 两次再 `fcompp`**（两候选区间同向累计量对比）。
- ⇒ **p3 是「可加的每 bar 标量」，Σ = 区间累计量（面积/量）** [B]；两支服务于**段择取评分**。

### 4.3 ★ V 产线：dispatch 三 mode 生产者

```
engine vt[+0x10] = 0x1000ed20 (dispatch, ret 4, arg = mode)
   mode == 0          → 返 -1
   mode == 1          → 0x10011500   (dir +1 族, 严 span 门 ≥8)
   mode == 2          → 0x10011660   (dir +1 族, 宽 span 门 ≥6)
   mode == 0x65 (101) → 0x100117b0   (dir -1 族, span 门 ≥6)
   进入前: 对 V 做一次紧致化（0x10012550，回写 engine[+0x60]）
```

三支**结构同构**（以 `0x10011500` 为例）：

```c
for (i = 1; i < C0.count; i++) {                     // 循环 offset: C2 += 0x18, C0 += 0x31
   c2 = C2[i];
   if ((s8)c2.slotB[0](+0x14) < 0)      ptr = c2.ptr[0](+4);
   else if ((s8)c2.slotB[3](+0x17) < 0) ptr = c2.ptr[3](+0x10);
   else continue;
   if (!ptr || ptr->dir(+0x10) != DIR)  continue;     // mode1/2: +1; 0x65: -1
   span = ptr->endBar(+0xc) - ptr->startBar(+8) + 1;
   if (!(span >= SPAN_MIN))             continue;     // mode1: 8; mode2/0x65: 6
   if (i - ptr->startBar + 1 != 8)      continue;     // ★ 定位到段首 +7/+8 邻域
   if (C0[i].dir != DIR)                continue;
   if (C0[startBar..i-1].p2 关系门)      continue;     // 逐 bar fcomp
   idx = ptr->idxB(+0x15);  if (idx > limit) continue; // limit = engine[+0x14]-1（或 C0[i].? [+0x42]）
   for (; idx <= limit; idx++) if (price[idx] 满足 fcomp) break;   // price = engine[+8]
   if (未满足) continue;
   Rec1D sub = { .tag = ?, .idx = idx, .v1 = <C0 字段>, .v2 = <C0 字段>, .v3 = 0.0 };
   V.push_back(0x10011a70, &sub);                     // 10011627
}
```

| mode | 目标函数 | dir | span 门 | C2 入口 | 末端 idx | v1 来源 |
|---|---|---|---|---|---|---|
| 1 | `0x10011500` | +1 | ≥8 | slotB[0]<0 → ptr[0] | `idxB(+0x15)` | `C0[k-1].p2` |
| 2 | `0x10011660` | +1 | ≥6 | slotB[0]<0 → ptr[0] | `idxB(+0x15)` | `C0[i].p2` |
| 0x65 | `0x100117b0` | −1 | ≥6 | slotB[0]**≥0** → ptr[0] | `idxA(+0x11)` | `C0[..].p1` |

### 4.4 ★★ 0x1d 子记录布局（生产者写点 + SelPri 读点**双向确证**）[A]

| 偏移 | 类型 | 语义 | 生产者写点 | SelPri 读点 |
|---|---|---|---|---|
| +0x00 | u8 | 标签（生产者未显式写） | — | — |
| **+0x01** | i32 | **barIdx** | `10011619 mov [esp+0x19], ecx` | `10005b20 [eax-0x1d]` / `10005b86 [eax]` |
| **+0x05** | f64 | **v1** | `1001160e fstp [esp+0x1d]` | `10005b2f fld [eax-0x19]` / `10005b92 [eax+4]` |
| +0x0d | f64 | v2 | `1001161d fstp [esp+0x25]` | （SelPri 不读） |
| +0x15 | f64 | v3 = 0.0 | `10011627 fstp [esp+0x2d]` | （SelPri 不读） |

- 每 **0x74 组 = 4 × 0x1d 子记录**；组内 4 个子记录 = `base + {0,1,2,3}*0x1d`。
- `0x10011a70`（V.push_back）：`eax` = 子记录地址，`esi` = &V；容量检查 `(end−beg)/0x74 < (cap−beg)/0x74`，命中则 `0x10012770` 拷贝 + `end += 0x1d`，否则 `0x10011c40` 扩容。
- `0x10012550`（V 紧致化）：`n = (last−first)/0x74` → `dst = arg + n*0x1d`，按 `0x1d` 步长 `rep movsd(7)+movsb` 搬移。

### 4.5 SelPri 消费路径（校正后精确版）

```c
int SelPri(this, int n, double* out, ...)      // 0x10005a50, ret 0x10
{
   memset(out, 0, n*8);
   V = engine[+0x5c] .. engine[+0x60];  cnt = (end − beg) / 0x74;
   for (e = 0; e < cnt; e++)
     for (j = 0; j < 4; j++) {
        sub = V.beg + e*0x74 + j*0x1d;
        idx = *(i32*)(sub + 0x01);
        val = *(f64*)(sub + 0x05);
        if (0 <= idx && idx <= n) out[idx] = val;   // 上界 = arg0 = n
     }
   return 0;
}
```

> **闭环**：`构建链(0x1000f680) → C1 段 → C2 并发槽(0x1000ee30) → engine vt[+0x10] dispatch(mode 1/2/0x65) → 0x10011500/60/b0 → 0x10011a70 push → V(engine[+0x5c]/[+0x60]) → SelPri/SelSlPri/SelSpPri → out[barIdx] = 价`。

---

## 五、T3 —— 四支收尾辅助

| # | 地址 | 签名 | 角色 | 关键点 |
|---|---|---|---|---|
| 1 | `0x1000fc10` | `ret`；`eax`=engine，`ebx`=rec | **seg_overlap_check** | 调 `0x1000f200` 取前段；要求同向；`dir==−1` ⇒ `prev.GG(+0x31) >= rec.DD(+0x3d)`；`dir==+1` ⇒ `prev.DD(+0x3d) <= rec.GG(+0x31)`（区间相交）→ 返回 `al` |
| 2 | `0x1000fdf0` | `ret`；`ebx`=rec，`edi`=engine | **find_prev_valid** | 向前扫 C1 找首个「同向 ∧ `flags.bit0`」的段；命中返 `startBar`，未命中返 `startBar + 2` |
| 3 | `0x1000fe50` | `ret 0xc` | **scan_candidate** | 含 SEH 帧 + 局部 vector（元素 stride **0xc**）；调 `0x1000f490`/`0x1000f5b0`（按 dir 生成候选）；门 = **相邻 C0 价格区间相交**（`C0[k+1].dir==−1 ? p2<=C0[k+2].p1 : p1>=C0[k+2].p2`）；命中返 bar 下标 |
| 4 | `0x10010d60` | `ret 4`；`ecx`=engine，`ebx`=rec | ★ **split_rebuild** | `e < engine[+0x1c]`(=9 段长上限) ⇒ −1；`find_prev_valid` → `scan_candidate`×2 → 价格门(dir 分派 8 条 x87) → `rec->flags = (flags & 0xFE) \| 2`（**置 bit1「已收尾」**）→ `0x1000f0e0`（**段入册 C1.count++**）→ `0x1000f070(startBar,endBar)` → **`0x1000f680` 递归 ×2** → 返 `max(a,b)` |

> ⇒ 四支共同构成 `seg_wrapup`(0x1000ff80) 的收尾子层：**谓词 + 查找 + 候选扫描 + 分裂递归**。
> ★ (4) 是 `0x1000f680` **内层递归的真实发起者**（docs/33 §3.4 所述「递归再建段」在此落地）[A]。

---

## 六、勘误与待仲裁

| # | 内容 | 级别 | 处置 |
|---|---|---|---|
| 1 | **docs/32 V 子记录偏移错位 1 字节**：原文记 `{i32 barIdx@+0x00, f64 价@+0x04}`，实为 `{u8 tag@+0, i32 barIdx@+0x01, f64 v1@+0x05}` | [A] 勘误 | 本批校正（§4.4，生产者/消费者双向对齐） |
| 2 | **docs/33「slot 字节 ∈ {3,4,5,6,0xfa,0xfb,0xfc,0xfd}」不全**：实际还有 `{8, 0xf8}`（同落槽 0） | [A] 补充 | 见 §3.3 |
| 3 | **docs/33 把 `0x100110a0`/`0x10011010` 记为「插值/价查询」**：实为 **C0.p3 区间求和（段评分）**，与 V 生产无直接关系 | [A] 勘误 | 见 §4.2；两文件改在伪码 §13 备注 |
| 4 | **docs/33「段入册器 `0x1000f0e0` 是唯一 C1.count++ 闸口」**：本批确认 `0x10010d60` 经它入册，无第二处 | [A] 加强 | 见 §五(4) |
| 5 | 镜像分支语义动机（slot 6/8 与 0xfa/0xf8 向 i+2 复制时价格门方向相反） | [B] | 待仲裁；疑与「同向相邻中枢段」有关 |
| 6 | `newSlotRaw ∈ {9, 2, 0xF7, 0xFE}` 编码含义（归一后均为槽 1） | [C] | 待仲裁（原始字节存 C2.slotB） |
| 7 | V 子记录 `v2(+0x0d)` 语义（三 mode 各写不同 C0 字段） | [B] | 待逐 mode 定值表 |
| 8 | 子记录 `+0x00` 标签字节实际取值（生产者未显式写） | [C] | 待动态验证 |
| 9 | `0x1000fe50` 的候选生成器 `0x1000f490`/`0x1000f5b0`；`0x1000f070`/`0x1000f010`/`0x1000f0b0`/`0x10013f00` | [C] | 待展开 |

**本批未做动态验证**（frida 待用户在场启动交易软件，无人值守）。

---

## 七、可复现命令

```bash
PY=C:/Users/Administrator/Documents/a_conda/python.exe
D=ronglide-app/chlib.dll
cd /d/a_ronglide/clone-ronglide

# T1 写入器 + 归一化表
$PY tools/re-inventory/disasm_func.py 0x1000ee30 --max 0x700 --dll $D -o tools/re-inventory/nchzs/chlib_1000ee30.txt
$PY tools/re-inventory/disasm_func.py 0x1000edf0 --max 0x300 --dll $D -o tools/re-inventory/nchzs/chlib_1000edf0.txt
$PY tools/re-inventory/x87_sim.py tools/re-inventory/nchzs/chlib_1000ee30.txt -o tools/re-inventory/nchzs/cond_chlib_1000ee30.txt

# T2 求和器 + dispatch + V 生产者 + push + 紧致化
for a in 100110a0 10011010 1000ed20 10011500 10011660 100117b0 10011a70 10012550 10005a50; do
  $PY tools/re-inventory/disasm_func.py 0x$a --max 0x700 --dll $D -o tools/re-inventory/nchzs/chlib_$a.txt
done

# T3 四支收尾辅助
for a in 1000fc10 1000fdf0 1000fe50 10010d60; do
  $PY tools/re-inventory/disasm_func.py 0x$a --max 0x700 --dll $D -o tools/re-inventory/nchzs/chlib_$a.txt
  $PY tools/re-inventory/x87_sim.py tools/re-inventory/nchzs/chlib_$a.txt -o tools/re-inventory/nchzs/cond_chlib_$a.txt
done

# 调用关系交叉验证
grep -lE "call +0x1000ee30" tools/re-inventory/nchzs/*.txt    # → 10011170 / 10011360
grep -lE "call +0x10011a70" tools/re-inventory/nchzs/*.txt    # → 10011500 / 10011660 / 100117b0
grep -lE "call +0x100110a0" tools/re-inventory/nchzs/*.txt    # → 10011170 / 10011360
```

---

## 八、下一步（建议）

1. **（首选）NChZs 第五批 —— 招牌成员消费链收口**：`NChZsFj`(`0x10005020`)/`NChZsDg`(`0x10005160`)/`NChZsHLTurn`(`0x10005480`)（EA63+EA61 组，384/260/318 行）——它们与 `engine[+0x14]/[+0x18]`（V 生产门的 limit 源）直接相关，可一并钉死 mode 1/2/0x65 的**选用者**。
2. **（次选）`NChZsL2M`(`0x100048a0`) 按支配树分块收口**（695 行、189 块；docs/32 §7.3 已给切分路径）。
3. **（第三）补完 T3 遗留**：`0x1000f490`/`0x1000f5b0`（候选生成器）+ `0x1000f070`/`0x1000f010`/`0x1000f0b0`/`0x10013f00`。
4. **（可选）动态验证**：用户在场时以 frida 挂 `0x1000ee30` / `0x10011a70`，dump C2 并发槽与 V 子记录，把本批 [B]/[C] 升 [A]。
