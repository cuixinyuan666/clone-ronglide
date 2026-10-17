# NChZs 第六批 WIP — NChZsL2M(0x100048a0) 支配树分块收口

来源：看板首选遗留项「NChZsL2M(0x100048a0) 按支配树分块收口（695 行/189 块）」。
工具：`cfg_blocks.py`（本批新建，CFG + 支配树 + 回边，输出 `l2m_cfg.txt`）。

## 0. 函数外壳（[A]）

```
0x100048a0  push ebp / mov ebp,esp / and esp,~7 / sub esp,0x14
            push ebx / push esi / push edi
0x100048b0  ecx = a4[0]; fld qword [ecx]; call _ftol2(0x100148a0)   ; ebx = (int)a4[0]
0x100048c6  ebx = eax                                                ; ★ P 参数（与 NChBi 族同 idiom）
0x100048d6  call memset(0x1001494c, a2 /*out*/, 0, a1*8)             ; out[] 清零，n = a1
0x1000492d  cmp ebx,1 -> mode1 / cmp ebx,2 -> mode2 / cmp ebx,3 -> mode3 / else -> 0x10004d42
0x100049c5  ret 0x10                                                 ; 全函数 5 个返回点
```

- 签名：`int L2M(this /*ecx*/, int n /*a1*/, double* out /*a2*/, ... a3 /*ebp+0x10*/, void* a4 /*ebp+0x14*/)`
  与 Fj/Dg/HLTurn 同为 `ret 0x10`，acc 走 ecx。
- `edi = a3[+0xc]`（0x100048bd）；`ecx = edi` 后续作 **C0.base**（`imul reg,0x31` 索引）⇒
  **a3 是「输出通道包装」，a3[+0xc] = out 的双精度视图基址**（与 Fj/Dg 同构）。
- 非空门（0x100048db..0x10004927，**7 重**，全 [A]）：
  C0.base(+0x20) ∧ C0.count(+0x2c) ∧ C1.base(+0x30) ∧ C1.count(+0x3c) ∧ C2.base(+0x40) ∧
  C0.base(局部槽复判) ∧ C1.count(复判) —— 任一为 0 ⇒ `0x1000500f` 失败口 `or eax,-1`。
  比 Fj/Dg 的 3 重门更严：**L2M 同时依赖 C0/C1/C2 三者**。
- 局部槽映射（★栈槽 +4 换算，基线 `add esp,0xc` 之后）：
  `[B0+0x14]`=C0.base（先由 pre-add 的 `[esp+0x20]` 存入）= 后复用为 C1 计数循环变量；
  `[B0+0x1c]`=C2.base；`[B0+0x10]`=C0.count；`[B0+0x18]`=mode3 标量游标。
- 全文只有 **2 个调用**：`_ftol2` + `memset` ⇒ 无子函数、无递归（与 L2M「无递归」旧结论互证）。

## 1. mode 1（ebx==1，0x10004936–0x100049c5，[A]）

外层 = 遍历 **C1 段记录**（`ecx = C1.base + 8`，步进 0x5d，行程 = C1.count）：

```
for each rec in C1:                                     ; ecx = rec+8
  if (!(rec.flags(+0x14) & 1)) continue                 ; 0x1000494a
  S = rec.startBar(+0x08); E = rec.endBar(+0x0c)
  if (E - S + 1 <= 3) continue                          ; setg
  if (rec.dir(+0x10) != -1) continue                    ; ★只吃下跌段
  if (S + 3 > E) continue
  for (i = S+3; i <= E; i += 2) {                        ; ★步进 2 笔
      c0 = C0.base + i*0x31
      if (c0->mark(+0x0c) & 1) continue                 ; 已登记则跳过
      if (!(rec.ZG(+0x19) > c0->p2(+0x21))) continue     ; test ah,0x41 / jne
      if (!(C0[S].p2 > c0->p2)) continue                 ; test ah,0x05 / jp
      out[c0->idxB(+0x15)] = 1.0                         ; fld1 在阶外只压一次
  }
```

- 语义（[B]）：**下跌段内「低点相对段首低点抬高、且跌破 ZG 上沿」的笔尾 → 标 +1**。
- 对称性：mode2 是它的镜像 —— `dir==+1`、用 `ZD(+0x25)` 比 `c0->p1(+0x19)`（高）、写 `idxA(+0x11)`。
- x87 站点对（0x10004985 / 0x10004997 与 0x10004a20 / 0x10004a32）**方向恰好互换**，是镜像直证。

## 2. mode 2（ebx==2，0x100049d1–0x10004a60，[A]）

```
同 mode1 外壳，差异 3 处：
  rec.dir(+0x10) != +1  -> continue                      ; ★只吃上涨段
  比较对象 = rec.ZD(+0x25) 与 c0->p1(+0x19 /*高*/)        ; test ah,0x05 / jp
  段首比较 = C0[S].p1 < c0->p1                           ; test ah,0x41 / jne
  out[c0->idxA(+0x11)] = 1.0
```

## 3. mode 3（ebx==3，0x10004a63–0x10004d41）— 进行中

结构已见：4 路展开 + 标量尾（`((n-5)>>2)+1` 次展开），游标
`ecx = C0.base+0x83`（= &C0[2].p2，步进 2 笔）、`esi = C2.base+0x46`（=&C2[1]+0x16，步进 1 条）。
判定用 **C2 槽字节**：`C2[i].slotB[2](+0x16) ∈ {0xFD, 3}` 与 `C2[i].slotB[1](+0x15) == 0xFE`
（下一笔同构检查 +0x18 / +0x17），是 C2 上的**模式状态机**。

## 4. mode 3（续）/ mode 4 — C2 槽状态机（结构 [A] / 语义 [B]）

逐元素模板（4 路展开 + 标量尾，pen 下标 k 从 1 到 n-1）：

```
if (C0[k].mark & 1) goto next;                  ; 已登记
al = C2[k].slotB[2] (+0x16);
if (al == -3 || al == +3) {                      ; 0xFD / 0x03
    haveRef = 0;                                 ; ★reset
    if (C2[k].slotB[1] == SEED) { haveRef = 1; refLo = C0[k-1].p2; refHi = C0[k-1].p1; }
    goto next;
}
if (!haveRef) { if (C2[k].slotB[1] == SEED) { haveRef = 1; ref = C0[k-1]; } goto next; }
if (C0[k].dir == DIRGATE && refLo < C0[k].p2 && refHi > C0[k].p1)
    out[C0[k].IDX] = 1.0;
next: if (C2[k].slotB[1] == SEED) { haveRef = 1; ref = C0[k-1]; }   ; 0x10004ad1 公共尾
```

| mode | SEED (slotB[1]) | DIRGATE | IDX | 参考笔 |
|------|-----------------|---------|-----|--------|
| 3 | `-2` (0xFE) | `+1` | idxB (+0x15) | k-1 |
| 4 | `+2`      | `-1` | idxB (+0x15) | k-1 |

- 语义 [B]：**「前一笔完全包含当前笔」+ 方向门 + 槽 −2/+2 作为参考锚点** → 标 1。
- 比较式（[A]，站点 0x10004b9f..0x10004bc5 手工窗口验证）：`fxch st(1)` 后 `fcom C0[k].p2`，
  `fxch st(2)` 后 `fcom C0[k].p1`，写 `st(0)`；净栈效应 = 恒等（三处 fxch 归位）。
- 写入值 = 常驻 `fld1` 的 1.0（[B]；x87 轮转保持 4 深栈，退出时 4 次 `fstp` 清空 —— mode1/2 只 1 次）。

## 5. 尾部与默认分支（[A]）

- `esi(C1.count)==0` → `0x10004fd3` → **return 0**（不是 -1）。
- `ebx ∉ {1,2,3,4}` → `0x10004fd3` → return 0（未知 mode 静默成功）。
- 失败口只有 `0x1000500f`（`or eax,-1`），由 7 重非空门触发。
- 返回点 5 处：0x100049c5 / 0x10004a60 / 0x10004d3f / 0x10004fdb / 0x10005018，全 `ret 0x10`。

## 6. 包装层（[A]，TAFLib 0x100135e0 = vt[+0x90]，code 0xEA61）

```
if (!authorize(0xEA61)) { memset(out, 0, n*8); return 0; }   ; 试用版：清零不报错
Fetch6Buffers(this, &buf6);                                   ; a3 = &buf6
fn = (*(this[+0xbc]))->vt[+0x90];
fn(n, out, &buf6, P);                                         ; P = 第 3 个实参（double 向量）
```
- `P = (int)(*(double**)a4)[0]` → 决定 mode 1..4（`_ftol2` 转换）。
- `a3[+0xc]` 在 L2M 内**只作非空门，从不解引用**（随后 edi 被 C0.base 覆盖）— [B]；
  推测为 6 buffer 结构中的第 4 个缓冲（与 out 同址或无关），需 frida 确认 [C]。

## 7. T3 遗留基元 6 支（本批顺手收口）

| 地址 | 身份 | 证据 |
|------|------|------|
| 0x1000f010 | **C3 单条写入器**：`C3[i] = {(dir==-1?+1:-1), valid=1, c0Index=i, barIdx=(dir==-1?idxA:idxB), hi=p1, lo=p2}` | 0x1000f019..f066，与第五批 C3 布局逐字段吻合 [A] |
| 0x1000f070 | **C3 区间打标器**：`for i in [start..end] (clamp count): C3[i].valid = (valid&0xFE)|2`（bit1 已收尾） | 0x1000f089..f09d [A] |
| 0x1000f0b0 | **C3 反向查有效**：从 i 向 0 扫，返回首个 `valid&1` 的记录，越界/无则 0 | 0x1000f0c0..f0d7 [A] |
| 0x1000f490 | **候选点收集器 A（取 p1=高）**：`for i=start..end step 2` 压 `{f64 C0[i].p1, i32 i}` 到 12B 元素 vector，尾部 `std::reverse` | 0x1000f4ef (fld +0x19) / 0x1000f570 反转对 [A] |
| 0x1000f5b0 | **候选点收集器 B（取 p2=低）**：同上，`fld +0x21` | 0x1000f60f [A] |
| 0x10013f00 | MSVC **局部展开/EH 辅助**（funclet 0x10014870 + 0x10014440），非业务逻辑 | 0x10013f19..f52 [B] |

- 选择者直证：`0x1000fe96 / 0x100107ac / 0x10010974` 三处均为
  `if (rec.dir == -1) f490(...) else f5b0(...)` ⇒ **下跌段取高点序列、非下跌段取低点序列** [A]。
- vector 元素 = **12 字节 {f64 价@+0, i32 笔序@+8}**（0x2aaaaaab 魔数 /12 + 反转步长 0xc 双向确证）。
