# NChZs 第四批 WIP — 消费侧闭环（0x1000ee30 / 0x100110a0 / 0x10011010 + 四支收尾辅助）

> 铁律：栈槽 +4 修正；x87 链用 x87_sim.py 验证；疑点 [A]/[B]/[C] 不掩盖。
> 本批 frida 动态验证未运行（无人值守）。

---

## WIP-A — T1: `0x1000ee30` = C3/C2 记录写入器（`ret 8`）★ [A 结构]

### 签名（栈槽逐点换算后自洽）
进入 esp=P；序言 `push ebx/ebp/esi/edi` ⇒ 体内 esp=P-0x10。
- `[esp+8]`(序言前)=arg1 → `rec2`（**C1 段记录指针**）
- `[esp+0xc]`(push ebx/ebp 后) = `[P+4]` = **arg0 = engine**
- `ecx` = `i`（bar 下标）；`al` = `slot`（**signed char**）
- `[esp+0x14]`(体内)=P+4=arg0 槽（被复用为局部 `i*0x31`）；`[esp+0x18]`=P+8=arg1 槽

```c
void sub_1000ee30(Engine* eng /*arg0, ebp*/, Rec* rec2 /*arg1*/, int i /*ecx*/, signed char slot /*al*/)
{
  if (rec2 == 0) return;                                  // 1000ee30
  if (i < 0 || i >= eng->count /*[+0x2c]*/) return;       // 1000ee46 / ee4e
  if (abs(slot) - 1 > 8) return;                          // 1000ee57..ee65  (slot ∈ ±1..±9)
  s = sub_1000edf0(abs(slot) - 1);                        // 1000ee6b  归一化 → 0..3
  if (s < 0) return;                                      // 1000ee70
  Rec31* c0 = &C0[i];                                     // [eng+0x20] + i*0x31
  if (c0->mark /*[+0xc]*/ & 1) return;                    // 1000ee82  该 bar 已登记 → 跳过
  if (slot < 0 && c0->dir /*[+0]*/ != +1) return;         // 1000ee90-97  ★方向门
  if (slot > 0 && c0->dir          != -1) return;         // 1000ee9f-a4  ★方向门
  // ---- 主写（C2[i]，stride 0x18）----
  C2[i].id      /*[+0x00]*/         = (c0->dir == -1) ? c0->idxA /*[+0x11]*/ : c0->idxB /*[+0x15]*/;
  C2[i].ptr     /*[+4 + s*4]*/      = rec2;
  C2[i].slotB   /*[+0x14 + s]*/     = slot;
  rec2->bars    /*[+0x45 + s*4]*/   = i;
  // ---- 镜像分支（仅 slot ∈ {6,8,0xfa,0xf8}）----
  if (slot == 0xfa || slot == 0xf8) goto MIRROR_A;        // 1000eed6 / eed8 → 0x1000ef4a
  if (slot == 6 || slot == 8)       goto MIRROR_B;        // 1000eedd / eee2 → 0x1000eeeb
  return;
MIRROR_B:                                                 // slot 6/8
  j = i + 2;  if (j >= eng->count) return;
  if (!(C0[j].p1 < C0[i].p1)) return;                     // fld C0[j]+0x19; fcomp C0[i]+0x19; test ah,5; jp exit
  if (C0[j].mark & 1) return;
  newSlotRaw = (slot == 6) ? 9 : 2;                       // (slot!=6)-1 & 7 + 2
  goto EMIT2;
MIRROR_A:                                                 // slot 0xfa/0xf8
  j = i + 2;  if (j >= eng->count) return;
  if (!(C0[j].p2 > C0[i].p2)) return;                     // fld C0[j]+0x21; fcomp C0[i]+0x21; test ah,0x41; jne exit
  if (C0[j].mark & 1) return;
  newSlotRaw = (slot == 0xfa) ? 0xF7 : 0xFE;              // (slot!=0xfa)-1 & 0xF9 + 0xFE（低字节）
EMIT2:
  s2 = sub_1000edf0(abs((signed char)newSlotRaw) - 1);    // ★ 两条路径均 → 1
  C2[j].id  = (C0[j].dir == -1) ? C0[j].idxA : C0[j].idxB;
  C2[j].ptr[+4 + s2*4]  = rec2;
  C2[j].slotB[+0x14+s2] = newSlotRaw;                     // 存原始字节
  rec2->bars[+0x45 + s2*4] = j;
}
```

### ★ `0x1000edf0` = slot 归一化跳转表（9 项 → 4 槽）[A]
`jmp [eax*4 + 0x1000ee0c]`；表体 0x1000ee0c..0x1000ee2f（**9×4 = 0x24 字节**，末尾恰接函数体 0x1000ee30）。
表项（小端 dword 实测）：`F7 ED 00 10 / FA ED 00 10 / 00 EE 00 10 / 06 EE 00 10 / 06 EE 00 10 / 06 EE 00 10 / 06 EE 00 10 / F7 ED 00 10 / FA ED 00 10`
⇒ 目标桩：`0x1000edf7`(ret 0) / `0x1000edfa`(ret 1) / `0x1000ee00`(ret 2) / `0x1000ee06`(ret 3)。

| idx = \|slot\|−1 | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
|---|---|---|---|---|---|---|---|---|---|---|
| 返回槽 | **0** | **1** | **2** | **3** | **3** | **3** | **3** | **0** | **1** |

映射回 slot 字节（**只取决于 |slot|，符号仅决定方向门**）：

| raw slot | 有符号值 | \|slot\|−1 | 归一槽 |
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

⇒ **C2 的 4 个并发槽**：槽 2 = 「±3」档、槽 3 = 「±4/±5/±6」档、槽 0 = 「±8」档、槽 1 仅由镜像分支写入。
> 第三批列出的 `{3,4,5,6,0xfa,0xfb,0xfc,0xfd}` 之外，本批补齐 `{8, 0xf8}`（同样落槽 0）。符号 = 方向门（负 ⇒ 要求 `C0.dir==+1`；正 ⇒ `C0.dir==−1`）[A]。

### C2 记录布局（stride 0x18，本批直证）[A]
| 偏移 | 类型 | 语义 | 写点 |
|---|---|---|---|
| +0x00 | i32 | C0 分型点 id（dir==−1 取 `+0x11`(idxA)，否则 `+0x15`(idxB)） | 1000eec4 / 1000efb9 |
| +0x04 + s*4 | ptr | 段记录指针 `rec2`（按归一槽 s） | 1000eeca / 1000efbf |
| +0x14 + s | i8 | 该槽的 **slot 原始字节** | 1000eece / 1000efc3 |

### 调用点（4 处，全部在构建链内）
| 调用者 | 地址 | 上下文 |
|---|---|---|
| `seg_finalize` 0x10011170 | 0x1001126a | 1 处 |
| `seg_advance`  0x10011360 | 0x1001146b / 0x10011484 / 0x100114e7 | 3 处（slot 字节 `al` 来自各路径常量） |

> ⇒ `0x1000ee30` 是**唯一**把「C1 段记录」登记进 **C2 并发槽** 的写入器；C2[i].id 存 C0 分型 id，C2[i].ptr[s] 存段指针，段侧 `rec2[+0x45+s*4]` 回存 bar 下标 ⇒ **C2 即「每 bar 的 4 路段指针表」** [A]。
> 遗留：镜像分支的**语义动机**（为何 slot 6/8 与 0xfa/0xf8 需要向 i+2 复制、且价格门方向相反）[B]；`newSlotRaw` 9/2/0xF7/0xFE 的编码含义 [C]。

---

## WIP-B — T2: 消费侧产线闭环（V 向量 0x74 组四子记录从何而来）★ [A]

### B.1 两支求和器（本批新解，是「段评分」而非 V 生产者）
| # | 地址 | 签名 | 行为 | x87 |
|---|---|---|---|---|
| Σ1 | `0x10011010` | `ret 4`；`eax`=a，`ebx`=b，arg0=engine | `Σ_{i=a..b} C0[i].p3(+0x29)`（**不过滤**，4 路展开 + 尾循环） | 6 |
| Σ2 | `0x100110a0` | `ret 8`；`edx`=a，arg1=b，arg0=engine，`edi`=dir 过滤 | `Σ_{i=a..b, C0[i].dir(+0x00)==edi} C0[i].p3(+0x29)` | 6 |

- 两者结果留在 **ST(0)**（f64）。**注意：p3 循环单位是 C0 下标（= bar 下标，C0 每 bar 一条）**，非段下标。
- **★ 用途（直证）**：`0x10011360` @10011442 先 `call Σ1` 再 `fcomp [edi+0x29]`（= **当前 C0 记录的 p3**）⇒ **p3 是「可加的每 bar 标量」，Σ = 区间累计量**（面积/量）[B 语义 / A 结构]。
- `0x10011170` @100112ff 与 @10011314 **连调 Σ2 两次再 `fcompp`** ⇒ **比较两个候选区间的（同向）累计量**，据结果择段 ⇒ 段评分/背驰式比较 [A 结构 / B 语义]。
> ⇒ **`0x100110a0`/`0x10011010` 是「区间加权求和 + 区间对比」，不是 V 元素来源**（修正 T2 任务书中的猜想）。

### B.2 ★ V 向量（`engine[+0x5c]/[+0x60]`）的真实产线
```
engine vt[+0x10] = 0x1000ed20 (dispatch, ret 4, arg=mode)
  mode 1   -> 0x10011500        (dir +1 族, 严门)
  mode 2   -> 0x10011660        (dir +1 族, 宽 span 门)
  mode 0x65-> 0x100117b0        (dir -1 族)
  进入前: 对 V 做一次 0x10012550 紧致化 (beg/end 校正)
```
三支**结构同构**，均：
1. 若 `engine[+0x2c] (C0.count) <= 1/2` 直接返 0；
2. 以 `C2[i]`（stride 0x18）为入口：取 `slotB[0]`（`+0x14`）<0 → `ptr[0]`(`+4`)；否则取 `slotB[3]`（`+0x17`）<0 → `ptr[3]`(`+0x10`)；否则转下一 bar；
3. 门：段 `dir(+0x10)` 匹配 / `span=endBar-startBar+1` 阈值（mode1: **≥8**；mode2 & 0x65: **≥6**）/ `i == startBar + 8` / `C0[i].dir` 匹配 / 价格关系（`C0[i±k].p1/p2` 与 `price[idx]` 比较，逐 idx 推进直到满足）；
4. 组装 **0x1d 子记录**在栈上（`lea eax, [esp+0x18]` / `[esp+0x20]`）并 `call 0x10011a70` push 进 V。

### B.3 ★★ 0x1d 子记录布局（由 `0x10011500` 写点 + SelPri 读点**双向确证**）[A]
| 偏移 | 类型 | 语义 | 生产者写点 | SelPri 读点 |
|---|---|---|---|---|
| +0x00 | u8 | 标签/保留（生产者未显式写） | — | — |
| +0x01 | i32 | **barIdx** | 10011619 `[esp+0x19] = ecx` | 10005b20/10005b86 `[eax-0x1d]/[eax]` = base+1 |
| +0x05 | f64 | **v1**（mode1: `C0[k-1].p2`；mode2: `C0[i].p2`；0x65: `C0[..].p1`） | 1001160e `[esp+0x1d]` | 10005b2f `[eax-0x19]` = base+5 |
| +0x0d | f64 | v2 | 1001161d `[esp+0x25]` | （SelPri 不读）|
| +0x15 | f64 | v3 = 0.0 | 10011627 `[esp+0x2d]` | （SelPri 不读）|

- 每 **0x74 组 = 4 × 0x1d 子记录**；`0x10011a70` 是**单子记录** push_back（容量按 0x74 计量，magic `0x8d3dcb09`）。
- 组内 4 子记录偏移 `base + {0, 1, 2, 3}*0x1d`。
- **★ 勘误（第三批）**：docs/32 记「子记录 `{i32 barIdx@+0x00, f64 价@+0x04}`」为**错位 1 字节**；实测应为 `{u8 tag@+0, i32 barIdx@+0x01, f64 v1@+0x05}`（SelPri 原码 `eax-0x1d`/`eax-0x19`、`eax`/`eax+4` 与生产者 `[esp+0x19]`/`[esp+0x1d]` 完全对齐）。

### B.4 SelPri 消费路径（校正后）
```c
int SelPri(this, n, out, ...) {
   memset(out, 0, n*8);
   V = engine[+0x5c] .. engine[+0x60];   cnt = (end-beg)/0x74;
   for (e = 0; e < cnt; e++)
     for (j = 0; j < 4; j++) {
        sub = V.beg + e*0x74 + j*0x1d;
        idx = *(i32*)(sub+0x01);  val = *(f64*)(sub+0x05);
        if (0 <= idx && idx <= n) out[idx] = val;
     }
   return 0;
}
```
> ⇒ **闭环**：`构建链 → C1 段 → (dispatch mode 1/2/0x65) → V 0x1d 子记录 → SelPri/SelSlPri/SelSpPri → out[barIdx]=价`。
> V 由 `engine vt[+0x10]`（mode ∈ {1,2,0x65}）驱动，**不是**由 `0x100110a0/0x10011010` 产生。

---

## WIP-C — T3: 四支收尾辅助 [A 结构]

| # | 地址 | 签名 | 角色（本批定名） | 关键点 |
|---|---|---|---|---|
| 1 | `0x1000fc10` | `ret`（无栈参）；`eax`=engine，`ebx`=rec | **seg_overlap_check** 与前一有效段的重叠谓词 → `al`=bool | 调 `0x1000f200` 找前段；要求 `prev.dir == rec.dir`；`dir==-1` 支要求 `prev.GG(+0x31) >= rec.DD(+0x3d)`，`dir==+1` 支要求 `prev.DD(+0x3d) <= rec.GG(+0x31)`（区间 `[DD,GG]` 相交）|
| 2 | `0x1000fdf0` | `ret`（无栈参）；`ebx`=rec，`edi`=engine | **find_prev_valid** 向前扫 C1 找首个 `flags.bit0 ∧ dir 匹配 ∧ 有效` 的段 | 命中返回 `rec->startBar(+8)`；未命中返回 `rec->startBar + 2` |
| 3 | `0x1000fe50` | `ret 0xc`；`ecx`=rec?，arg 3 个 | **scan_candidate** 候选段扫描（含 SEH 帧 + 局部 vector，元素 stride **0xc**；调 `0x1000f490`/`0x1000f5b0` 按 dir 生成候选） | 门：`C0[idx+1].dir == -1 ? (C0[idx+1].p2 <= C0[idx+2].p1) : (C0[idx+1].p1 >= C0[idx+2].p2)`（相邻 C0 价格区间相交）；命中返回该 bar 下标；未命中销毁局部 vector（`0x10013f00`）后返回 |
| 4 | `0x10010d60` | `ret 4`；`ecx`=engine，`ebx`=rec | ★ **split_rebuild** 段分裂 + 递归再建 | `span-1 < engine[+0x1c]`(=9 段长上限) → 返 -1；`find_prev_valid` → `scan_candidate`×2 → 价格门（dir 分派，比较 `C0[..].p1/p2`）→ `rec->flags = (flags & ~1) \| 2`（**置 bit1「已收尾」**）→ `call 0x1000f0e0`（**段入册 C1.count++**）→ `call 0x1000f070(startBar,endBar)` → **`call 0x1000f680` 递归 buildSegment ×2** |

> ⇒ 四支共同构成 `seg_wrapup`(0x1000ff80) 的「收尾/分裂」子层：**谓词(1) + 查找(2) + 候选扫描(3) + 分裂递归(4)**。
> 其中 (4) 是 `0x1000f680` 递归调用的**真实源头**（第三批定位的「内层递归」由它发起）[A]。
