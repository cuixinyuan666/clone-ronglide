# NChZs 第五批 WIP — 招牌成员消费链（2026-10-17）

## WIP-A 首轮通读（Fj / Dg / HLTurn 骨架）

### A1 三支公共外壳（同一模板，与 NChBi 族一致）
- 签名一律 `ret 0x10`（4 参）：
  `arg0(n, bar 数)` `arg1(out, double[n])`，ecx = this（ch_api 对象）。
- 首句必为 `memset(out, 0, n*8)`（`call 0x1001494c`）⇒ **三支都是"逐 bar 输出数组"型指标**，
  未命中 bar 恒为 0.0。
- 次句必取 `engine = this[+0x18]`，然后读 3 个容器指针做非空门：
  | 函数 | 门 1 | 门 2 | 门 3 | 失败口 |
  |---|---|---|---|---|
  | Fj 0x10005020 | `engine[+0x20]`(C0.base) | `engine[+0x4c]`(C3.base) | `engine[+0x2c]`(C0.count) | 0x10005156 `or eax,-1` |
  | Dg 0x10005160 | `engine[+0x2c]`(C0.count) | `engine[+0x4c]`(C3.base) | `engine[+0x2c]` (重复) | 0x1000546a |
  | HLTurn 0x10005480 | `engine[+0x20]`(C0.base) | `engine[+0x4c]`(C3.base) | `engine[+0x2c]`(C0.count) | 0x100057f5 |
  失败口返回 **-1**，成功口返回 0（`xor eax,eax`）。
- 价格数组来源（engine setter 槽）：`engine[+8]` → Fj/Dg/HLTurn 的 **[esp+0x30]**；
  `engine[+0xc]` → **[esp+0x34]**（Dg 用 [esp+0x10]）。两支都是 **逐 bar double 数组基址**。

### A2 C3 记录（stride 0x1d）在消费侧的**真实字段布局**（★ 本批首条修正）
三支消费代码一致按下列偏移读取，与 docs/34 的 V(0x74) 子记录布局**不同**：

| C3 偏移 | 类型 | 三支的用法 | 语义 |
|---|---|---|---|
| +0x00 | i32 | Fj `fild [e+0]`→out；Dg/HLTurn 当 dir 比对 | **方向 ±1** |
| +0x04 | u8 | 三支均 `test byte [e+4],1` | **有效标记 bit0** |
| +0x05 | i32 | Dg `[ecx]`=rec+5 当起点 bar | 起点 barIdx |
| +0x09 | i32 | 三支均作 `out[]` 下标（`esi*8`） | 终点 barIdx |
| +0x0d | f64 | 本批三支**未读** | 价 1（C0.p1 镜像） |
| +0x15 | f64 | 本批三支**未读** | 价 2（C0.p2 镜像） |

⇒ 与 `chzs_container_layout.txt` 五节的 `{i32 barIdx@0, f64 价@4, u8=1@0xc}`
**不一致**：实测有效标记在 **+4**、方向在 **+0**、double 在 +0xd/+0x15。
（0x1000ebe0 后处理的写点 `dst[+0]`=±1、`[+4]=1`、`i32+5`、`i32+9` 与实测一致 ⇒ 权威表五节需勘误。）
`[A]` **待仲裁**：V(0x74) 子记录（`{u8 tag@0,i32 bar@1,f64@5}`）与 C3(0x1d) 元素是否**真为同一结构**
——目前证据指向**同一 0x1d 结构、两种读法**，但 tag@0 与 dir@0 冲突，需在 V 生产者
0x10011500 里逐字节复验（本批 T4 一并处理）。

### A3 Fj 0x10005020（384 行）— "C3 端点方向打点器"
```
gate(C0.base, C3.base, C0.count)  else -1
lastHit = -1; i = 0
if (C0.count >= 4) {                        // 4× 展开主循环，指针步进 0x74 = 4×0x1d
  e = C3 + 0x26;                            // = elem[0]+0x26 ⇒ 下面 -0x22 落在 elem[0]+4
  do {
    for (s = 0..3) {                        // 展开 4 次，判定完全相同
      if (C3[i+s].valid && C3[i+s].barIdx9 in [0,n)) {
        out[C3[i+s].barIdx9] = (double)C3[i+s].dir;   // ★ 写的是 ±1
        lastHit = i+s;
      }
    }
    i += 4;
  } while (i < C0.count - 3);
}
for (; i < C0.count; i++) { /* 同一逻辑的尾循环（0x100050f7..0x10005124） */ }
if (lastHit > 0 && lastHit < n-1)
  call 0x100069b0(out, C0.base, C0.count, C3[lastHit].dir, <eax = C3[lastHit].+5 + 3>)
free? 无（Fj 无临时缓冲）
return 0
```
- **迭代上界是 `C0.count`，而元素步进是 C3(0x1d)** ⇒ 明确假设 **C3.count == C0.count**（一一对应）。
- 输出语义：`out[bar] = ±1`，bar 取 C3 记录的 **+0x09**。
- 尾部 `0x100069b0(out, C0, cnt, dir, idx+3)` = 收尾补点器（三支共用，本批 T4 一并 dump）。
`[B]` 疑点：`mov eax,[elem+5]; add eax,3` 计算后**未压栈**（Fj 0x10005144），
只能解释为 0x100069b0 的第 5 参走寄存器约定 / 或编译器保留的 eax 实参——待 dump 0x100069b0 定论。

### A4 Dg 0x10005160（260 行）— "C3 区间极值点位打点器"
```
memset(out); gate
alloc temp[0x1d × C0.count]  (call 0x10006b60(count, &hdr))     // hdr = {ptr@+0, ?, ?}
m = 0; for (i = 0; i < C0.count; i++)                            // 0x100051ef 起
   if (C3[i].valid && C3[i].barIdx9 >= 0) { memcpy(temp+m, C3+i, 0x1d); m++; }  // rep movsd ×7 + movsb = 29B
if (m <= 0) goto cleanup
for (k = 0; k < m; k++) {
   cur = temp + k*0x1d;
   f = (cur.dir == 1) ? arrC[cur.barIdx9] : arrB[cur.barIdx9];    // arrB = engine[+8], arrC = engine[+0xc]
   best = cur.barIdx5; bestVal = f;
   // 前段：与 k-1 记录的 barIdx5 + 3 之后对齐（0x1000526f: temp[k-1].bar9 + 3 ≤ cur.bar5）
   for (j = prevEnd; j <= cur.barIdx5; j++) {                    // C0 逐元素 stride 0x31
       取 C0[j].dir（+0x00），按 dir==-1 分支选 idx 字段；
       if (j > best) 在 dir==1 时取 max(arrC[j] vs arrB[j]),  dir==-1 时取 min(...)
   }
   // 后段：cur.bar5+3 .. temp[k+1].bar9-3 之间同法扫极值（0x10005332..0x100053e6）
   out[bestBar] = (double)cur.dir;                               // 0x100053f9 fild [ecx-5] + fstp
}
if (lastBest > 0 && lastBest < n-1) call 0x100069b0(out, C0.base, C0.count, temp[lastBest].dir, lastBest+3)
cleanup: free(temp)  via [0x100150b0] = operator delete?
return 0
```
- 读 **C0（stride 0x31）逐元素**取 dir 与索引字段（`[edx-0x15]`=C0+0, `[edx-4]`/`[edx]` = C0+0x11/+0x15 双索引），
  `j > best` 时比较 `arrB[j]` 与 `arrC[j]`（用 `arrC - arrB` 的字节差做同下标换算，0x100052bb `sub edi,[esp+0x10]`）。
- 输出同样是 `out[bar] = ±1`，但 **bar 是区间内极值 bar**，不是记录自带的 bar9。

### A5 HLTurn 0x10005480（318 行）— "同向记录配对 + 高低转折打点"
```
memset(out); gate; alloc temp 同上; 过滤复制 valid && bar9>=0 的 C3 记录 → temp, m 条
if (m <= 0) goto free
x87 载入两个常量 [0x100154c8]/[0x100154c0]，再做 fld st(1) ×2 ⇒ 栈顶两组 (值,值) 跑双游标
for (k = 0; k < m; k++) {
   cur = temp + k*0x1d;
   if (k == 0) out[cur.bar9] = (double)cur.dir;                  // 0x10005562 首点直接打
   dir = cur.dir;
   for (j = k+1; j < m && temp[j].dir != dir; j++) ;             // 找**下一个同向**记录
   if (j >= m) { 尾处理 0x10005599 } else { 段扫描 0x100055d4 }
}
段扫描 0x100055d4:
   idx0 = max(cur.bar9, bestSoFarIdx);  if (n - idx0 < 4) 走短路径 0x10005759
   limit = temp[j].bar9;
   // 主扫描：从 idx0+2 起，步长 4（4× 展开，0x10005621 起 4 个块）
   //   dir== 1 → 用 arrC(engine[+0xc]) 取 max；dir==-1 → 用 arrB(engine[+8]) 取 min
   //   命中更新 edi = bar 下标
   // 尾扫描 0x10005759：单步 1 直到 n（无上界 limit）
   if (edi >= 0) { out[edi] = (dir==1) ? +1.0 : -1.0;  bestSoFar = edi; }   // 0x100057c5..0x100057e0
     // 注意：写入值用 setne 由 dir 归一，非直接 fild dir
free(temp); return 0
```
- 与 Dg 的差别：Dg 用 `C0.dir` 与 `C0` 双索引扫极值；HLTurn 用 **C3 记录自身 dir** 且
  只在"同向记录对"之间的 bar 区间扫（`j` 为下一个同向记录），首点/极值点各打一次。

## WIP-B T4 溯源（dispatch / mode / limit 源）

### B1 三支共用的收尾补点器 0x100069b0（ret 0x10，★ eax = 第 5 个隐式实参）
```
int tail(out, C0.base /*arg2*/, end /*arg3*/, dir /*arg4*/)   // eax(隐式) = start
{
  if (dir == 1) {
     max = DBL_MAX(0x100154c0); best = -1;
     for (j = start; j < end; j++)                       // 4× 展开，stride 0x31
        if (C0[j].p2(+0x21) > max) { max = C0[j].p2; best = j; }
     if (best >= 0) out[ C0[best].idxB(+0x15) ] = **-2.0**(0x100154e0);
  } else {                                               // dir == -1（非 1 一律走此支）
     min = -DBL_MAX(0x100154c8); best = -1;
     for (j = start; j < end; j++)
        if (C0[j].p1(+0x19) < min) { min = C0[j].p1; best = j; }
     if (best >= 0) out[ C0[best].idxA(+0x11) ] = **+2.0**(0x100154b8);
  }
}
```
- **eax 实参**：Fj `0x10005144 add eax,3` / Dg `0x10005444 add eax,3` 都在 `push` 之后才 `add`，
  且 eax 不入栈 ⇒ 确证 `eax = start`（非 cdecl 常规，本仓首次遇到，已用两处调用点交叉确认）。
- 常量读音（`_read_consts.py`）：0x100154b8=**2.0**、0x100154c0=**+DBL_MAX**、
  0x100154c8=**−DBL_MAX**、0x100154e0=**−2.0**。
- ⇒ **值域结论**：NChZs 族输出 = `{0, ±1, ±2}`；±1 由成员主体写、**±2 只由收尾器写**，
  与 C0[+0x0c] 的「分型标记 = 1 当值 ∈ {−2,+2}」互为印证（±2 = 段级端点）。

### B2 TAFLib 包装骨架（授权码直证，三支完全同构）
```
NChZsFj   = 0x10013660 / NChZsDg = 0x100136f0 / NChZsHLTurn = 0x10013780   (TAFLib, ret 0xc)
  code = (this[+0xb8] > 1) ? 0xEA63 : 0xEA61;          // ★ 层计数器 +0xb8
  if (!Authorize(0x10014e60, code)) { memset(out,0,n*8); return 0; }   // ★ 未授权 → 清零 + 返回 0
  Fetch6Buffers(0x10006cc0)(this, &buf);
  api = this[+0xbc]; fn = api->vt[+0x94 / +0x98 / +0x9c];
  fn(n, out, &buf, arg3);  return 1;
```
ch_api 虚表 0x10015214 实测映射（权威）：
`+0x94 → 0x10005020 (Fj)` / `+0x98 → 0x10005160 (Dg)` / `+0x9c → 0x10005480 (HLTurn)`；
邻槽 `+0x80..0x90` = 0x100046c0/0x100046e0/0x10004700/0x10004720/0x100048a0，
`+0xa0..0xb0` = 0x10005810/0x100058f0/0x10005a50/0x10005bb0/0x10005d10。
注册表（scan_registry 重跑，274 条）NCHZSFJ seq=1262 / NCHZSDG 1263 / NCHZSHLTURN 1264（连续）⇒ 三支确为同族邻居。
★ **未授权路径语义**：不是返回 -1，而是 **memset 清零 + 返回 0** ⇒ 试用版这些指标输出全 0（不是"算错"）。

### B3 dispatch 0x1000ed20 的三个 mode 值（★ 勘误：0x65 → 0x66）
```
if (mode == 0) return -1;
0x10012550(&V)                     ; 先对 V 做紧致化（去空洞）
movzx eax, byte [ebp+8]
sub eax,1  ; je → 0x10011500       ; mode 1
sub eax,1  ; je → 0x10011660       ; mode 2
sub eax,0x64 ; jne → fail          ; mode = 1+1+0x64 = **0x66**
call 0x100117b0
```
前三批记的 "0x65" 是把 `sub 0x64` 直接当成 mode 常量；累减后实为 **0x66**。

### B4 mode 1 生产者 0x10011500（110 行，`ret 4`，arg0 = engine）
```
if (C0.count <= 1) return 0;
for (i = 0; i + 1 < C0.count; i++) {
  p = C2[i+1] 的解析结果：                       // C2 stride 0x18、整块基址 engine[+0x40]
     if (C2[i+1].i8(+0x14) < 0)      p = C2[i+1].ptr(+0x04);
     else if (C2[i+1].i8(+0x17) >= 0) continue;  // 两标志皆非负 → 跳过
     else                            p = C2[i+1].ptr(+0x10);
  if (!p || p[0x10] != 1) continue;              // 只认「上升」子对象
  span = p[0xc] - p[8] + 1;
  if ((span > 3 ? span - 1 : span) < 7) continue;   // ★ 有效 span ≥ 8
  if (i - p[8] + 1 != 8) continue;                  // ★ 必须恰好第 8 根（i = lo + 7）
  if (C0[i+1].dir != 1) continue;
  for (k = p[8]; k < i; k++)                        // C0[i+1].p2 必须严格大于 C0[lo..i].p2
     if (!(C0[i+1].p2 > C0[k].p2)) goto next;
  limit = (i+2 < C0.count) ? C0[i+2].idxA(+0x11) : **engine[+0x14] - 1**;   // ★ limit 源
  for (b = C0[i+1].idxB(+0x15); b <= limit; b++)
     if (price[b] < C0[i].p2) break;                // price = engine[+8]
  if (b > limit) continue;
  V.push_back({tag:未写, bar:b, v1:C0[i].p2, v2:C0[i+1].p2, v3:0.0});   // call 0x10011a70
}
```
⇒ **mode 1 = 上升穿越点探测器**：v1 = 前一笔高（C0[i].p2）、v2 = 本笔高（C0[i+1].p2），
bar = 首个"价格跌破前笔高"的 bar。

### B5 mode 2 vs mode 0x66：逐条镜像（归一化 diff 结果，仅 12 处差异）
| 项 | mode 2 @0x10011660 | mode 0x66 @0x100117b0 |
|---|---|---|
| 循环起点 | `C0.count <= 2` 退出；i 从 2 起 | 同 |
| C2 分支判据 | `i8(+0x14) jge` / `i8(+0x17) jge` | `jle` / `jle`（符号翻转） |
| 子对象方向 | `p[0x10] == 1` | `p[0x10] == -1` |
| C0 方向门 | `C0[i].dir == 1` | `C0[i].dir == -1` |
| 相邻笔价 | C0[i-1].p2(+0x21) / C0[i].p2(+0x21) | C0[i-1].p1(+0x19) / C0[i].p1(+0x19) |
| 单调判据 | `test ah,1; je skip` ⇒ 需 C0[i-1].p2 < C0[i].p2 | `test ah,0x41; jnp skip` ⇒ 需 C0[i-1].p1 > C0[i].p1 |
| span 门 | `< 5` 跳过 ⇒ 有效 span ≥ 6 | 同 |
| 相位门 | `i - lo == 8` | 同 |
| 右边界 | C0[i+1].idxA(+0x11)，否则 engine[+0x14]-1 | C0[i+1].idxB(+0x15)，否则 engine[+0x14]-1 |
| 起点 | C0[i].idxB(+0x15) | C0[i].idxA(+0x11) |
| 价格数组 | engine[+8] | engine[+0xc] |
| 突破判据 | `test ah,0x41; jnp found` ⇒ 需 C0[i-1].p2 > price | `test ah,1; je found` ⇒ 需 C0[i-1].p1 < price |
| V 记录 | v1=C0[i].p2, v2=C0[i-1].p2 | v1=C0[i].p1, v2=C0[i-1].p1 |

⇒ **mode 2 = 上升笔「前高不破」段的首破点；mode 0x66 = 下降笔镜像（前低不破段的首破点）**。

### B6 V 向量与 push_back（0x10011a70）
- `0x10011a70` 入口 `esi` = **engine+0x58**（`lea esi,[ebp+0x58]`）⇒ 向量三字段：
  `begin = engine[+0x5c]`、`end = engine[+0x60]`、`capEnd = engine[+0x64]`。
- 元素大小由魔数 `0x8d3dcb09`（= 2^36/0x1d 的定点倒数）+ `sar 4` 确证 = **0x1d**（29 B）。
  `[B]` 勘误候选：docs/32/34 的「V 元素 0x74 = 4×0x1d」应改述为 **元素 = 0x1d**（0x74 只出现在 C3 的 4-路展开步进）。
- `0x10011a70` 的 xref 全表 = `0x10011627 / 0x1001177a / 0x100118ca`（恰为三支 mode 生产者）⇒ V 只有这三个生产者。
- 记录 `tag@+0` **三支均未写**（`[esp+0x18]` 无写点）⇒ `[B]` 待仲裁（疑原 C++ 结构体首字节为 padding，或由 0x10012770 拷贝器填入）。

### B7 ★ 可达性判定：dispatch 无静态调用者
| 检查 | 结果 |
|---|---|
| chlib `.text` 线性反汇编覆盖率 | 81920 B / 100.0%（resync 仅 1 B） |
| chlib 内 `call/jmp [reg+0x10]`（capstone） | **0** |
| chlib 内字节级 `FF /2,/4 mod=01 rm=reg disp=0x10` | **0** |
| chlib 内 `call 0x1000ed20` 立即数 | **0**（唯一引用 = .rdata+0x4ac = 虚表槽 0x100154ac） |
| TAFLib `.text`（450560 B, 100%）`call/jmp [reg+0x10]` | **0** |
| TAFLib 全部非索引 mem-call 位移 | 全部指向导入表 `0x1006f0xx/0x1006f1xx…`，无任何小位移虚调用 |
⇒ **engine vt[+0x10] 在 chlib+TAFLib 两个模块内都没有调用点**；三支 mode 生产者
（0x10011500/0x10011660/0x100117b0）与其唯一出口 push_back 构成**不可达子图**（当前构建）。
`[C]` 待 frida 验证（等用户在场）：在 chlib 的 0x10011a70 / 0x1000ed20 / 0x10011500 下钩，
跑一个 NChZs 指标看命中数；若全 0 ⇒ 死代码结论成立。
**旁证**：V 记录 tag@+0 未初始化，也符合"遗留/未接线代码"的画像。

### B8 limit 源结论（T4 第二问）
- **engine[+0x14] = n（bar 数）**（setter 0x1000e0b0 第 5 槽 ← 核心体 0x100045f0 的 a1）：
  三支 producer 均用 `engine[+0x14] - 1` 作**扫描右边界兜底**（当 `i+2 >= C0.count` 无下一笔可借索引时）。
- **engine[+0x18] 在三支 producer 内一次都没有被读**（只有 `[esp+0x18]` 栈槽）⇒
  派单假设「engine[+0x14]/[+0x18] 共同限制 V 生产」需**勘误**：limit 只有 [+0x14] 一个来源。
  （engine[+0x18] 在布局表里是 u8 标志，本批未找到任何读者，登记为遗留项。）

## WIP-C 勘误（WIP-A 两处 + 新增两条实证）

### C1 ★ 栈槽 +4 换算（Dg 的 [esp+0x20] 之谜解开，铁律生效）
Dg 首段 `mov [esp+0x2c],ecx`（ecx=engine[+8]）出现在 `add esp,0xc` **之前**，
后一次 `mov [esp+0x2c],ecx`（ecx=C0.base）在**之后** ⇒ 两者是**不同栈槽**：
- 换算：`sub esp,0x44` 后连推 ebx/esi/edi + 3 个 memset 实参，`add esp,0xc` 使 esp 回抬 ⇒
  **0x10005194 的 [esp+0x2c] = 后续的 [esp+0x20]**（+0xc 差）。
⇒ `[esp+0x20] = engine[+8]`、`[esp+0x10] = engine[+0xc]`、`[esp+0x2c] = C0.base`、`[esp+0x40] = C0.count`。
（WIP-A 的 A4 里把 [esp+0x20] 记作"无写点局部"，**作废**。）

### C2 ★ engine[+8]/[+0xc] = 高/低价数组（本批确权）
- Dg：dir==1 支比较 `[edi+edx]`，edi = engine[+8] − engine[+0xc]（字节差）、edx = engine[+0xc]+idx*8
  ⇒ 实读 **engine[+8][idx]**；dir==-1 支直接 `[edx]` ⇒ 读 **engine[+0xc][idx]**。
- 交叉印证：C0 的 p1(+0x19)/p2(+0x21) 由 GG/DD 更新器（0x1000edb0/edd0）判明
  **p1 = 高（比 GG 取大）、p2 = 低（比 DD 取小）**；mode 1 要求"低点抬高"用 p2、
  mode 0x66 要求"高点降低"用 p1，与"上升段配低点/下降段配高点"完全自洽。
⇒ **engine[+8] = 高价数组、engine[+0xc] = 低价数组**（取代旧记「价格数组 = engine[+8]」的粗略说法）。

### C3 ★ 极值方向勘误（WIP-A 的 A5 写反了）
x87 状态字解码（Intel 四态，C0=AH.b0、C2=AH.b2、C3=AH.b6）：
- `fcom cand` + `test ah,0x41; jne skip` ⇒ **仅当 acc > cand 才替换** ⇒ **min 累加器**
- `fcom cand` + `test ah,0x05; jp  skip` ⇒ **仅当 acc ≤ cand 才替换** ⇒ **max 累加器**
（`test ah,0x05` 结果为 0 时 PF=1，`jp` 跳走 = 跳过 ⇒ 只剩"不大于"才进体）

| 站点（HLTurn） | 掩码/跳转 | 语义 |
|---|---|---|
| 0x1000562e `fcom [低价[idx]]` | `ah,0x41 jne` | dir==1 ⇒ **min(低价)** |
| 0x10005648 `fcom [高价[idx]]`（前有 fxch） | `ah,0x05 jp` | dir==-1 ⇒ **max(高价)** |
| 0x10005675 / 0x10005693 | 同上（块 2） | 同 |
| 0x100056bb / 0x100056d5 | 同上（块 3） | 同 |
| 0x10005702 / 0x1000571e | 同上（块 4） | 同 |
| 0x1000577d / 0x10005797 | 同上（尾块） | 同上（尾块无上界，扫到 n） |
⇒ **HLTurn：上升记录取"段内最低低点"、下降记录取"段内最高高点"** ⇒ 语义 = **段起点/转折点标注**。
（4× 展开块 + 1 个尾块 = 10 个比较站点；Fj 0 个、Dg 4 个，合计 14。）

| 站点（Dg） | 掩码/跳转 | 语义 |
|---|---|---|
| 0x100052cf `fcom [高[idx]]` | `ah,0x05 jp` | dir==1 ⇒ **max(高价)** |
| 0x100052e0 `fcom [低[idx]]` | `ah,0x41 jne` | dir==-1 ⇒ **min(低价)** |
| 0x100053a2 / 0x100053b3 | 同 | 后段块（同一逻辑，区间换成 cur.bar5+3 .. next.bar9-3） |
⇒ **Dg：上升记录取"段内最高高点"、下降记录取"段内最低低点"** ⇒ 语义 = **顶/底极值点标注**。
⇒ Dg 与 HLTurn **方向相反**（Dg=极值、HLTurn=起点），是两支的标志性差异。

**Fj 特殊性**：全文 **0 个 x87 比较站点**（只有 `fild dword` / `fstp qword` 的 int→double 转换），
是纯"查表打点"函数（out[C3.barIdx9] = C3.dir），不参与任何浮点判断。

## 待办（本批剩余）
- [ ] T4 dump `0x100069b0`（三支共用收尾器）确认第 5 参
- [ ] T4 dump `0x10011500/0x10011660/0x100117b0` 复核 V 子记录布局 + limit 源（engine[+0x14]/[+0x18]）
- [ ] T4 全 .text 搜 `call 0x1000ed20` / `[vt+0x10]` 定位 mode 1/2/0x65 的选用者
- [ ] setter 0x1000e0b0 复核 engine[+8]/[+0xc] 是"高/低价数组"
