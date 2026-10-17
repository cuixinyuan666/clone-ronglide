# NChZs 第六批 — NChZsL2M 支配树收口 + 遗留基元 6 支

- 批次：NChZs 族 · 第六批（2026-10-18）
- 目标成员：`NChZsL2M` @ `0x100048a0`（695 指令 / 189 基本块），包装 `TAFLib 0x100135e0`（slot `+0x90`, 授权码 `0xEA61`）
- 附带收口：第四批遗留 6 支基元 `0x1000f010 / 0x1000f070 / 0x1000f0b0 / 0x1000f490 / 0x1000f5b0 / 0x10013f00`
- 证据目录：`tools/re-inventory/nchzs/`（`chlib_100048a0.txt`、`l2m_cfg.txt`、`l2m_modes.txt`、`l2m_x87sim.txt`、`taf_100135e0.txt`、`chlib_1000f0*.txt`、`chlib_1000f490/5b0.txt`、`chlib_10013f00.txt`、`nchzs6_wip.md`）
- 新增工具：`cfg_blocks.py`（CFG + 支配树 + 回边）、`x87_path.py`（分支路径探索式符号 x87 模拟）
- frida 动态验证本轮不运行（无人值守）

## 一、摘要

| # | 结论 | 等级 |
|---|------|------|
| 1 | L2M 是 **4 模式选择器**：`P = (int)(*(double**)a4)[0]`，1/2/3/4；越界或 `C1.count==0` 时 **return 0**（静默成功，非 -1） | [A] |
| 2 | mode 1/2 = **C1 段 → C0 笔的隔笔扫描**：跌段标 `idxB`、涨段标 `idxA`，写入恒 `1.0` | [A] |
| 3 | mode 3/4 = **C2 槽状态机**：`slotB[2] ∈ {−3,+3}` 重置参考、`slotB[1] ∈ {−2,+2}` 打锚，命中「前一笔完全包含当前笔」则标 `idxB` | 结构 [A] / 语义 [B] |
| 4 | 全函数 **8 个自然环** = 4 模式 × (外层/内层)，环头 `0x1000494a/0x1000497c/0x100049e5/0x10004a17/0x10004ab0/0x10004ccb/0x10004d89/0x10004f90` | [A] |
| 5 | `0x1000f010` 补上了 C3 布局的**生产者侧直证**（且给出 `dir = −C0.dir`、`barIdx = dir==−1 ? idxA : idxB`） | [A] |
| 6 | `0x1000f490` / `0x1000f5b0` = **候选点收集器双胞胎**（取 p1 高 / p2 低），元素 **12 字节 `{f64 价, i32 笔序}`**，尾部 `std::reverse` | [A] |

## 二、支配树骨架

`cfg_blocks.py` 产出 `l2m_cfg.txt`（321 块：以「跳转目标 / 跳转后一条 / 调用后一条」为 leader；`cond_*` 工具的 189 块是不在调用后切块的窄口径，两者不矛盾）。

```
B0  0x100048a0  序言 + P 提取(_ftol2)
B1  0x100048ba  memset(out, 0, n*8)
B2  0x100048db  装 C0.base/C0.count/C1.base/C1.count/C2.base 到局部槽
B3..B14  7 重非空门（每支 je 0x1000500f = 失败口 or eax,-1）
B15 0x1000492d  cmp P,1  ──┬─ =1 → mode1 (0x10004936)
                            ├─ =2 → mode2 (0x100049d1)
                            ├─ =3 → mode3 (0x10004a63)
                            └─ 其它 → 0x10004d42: cmp P,4 → =4 → mode4 (0x10004d4b)
                                                      └ 否则 → 0x10004fd3 (return 0)
```

- 自然环（回边）8 个，与 4 模式 × 2 层循环严格一一对应。
- 无任何子函数调用，除 `_ftol2(0x100148a0)` 与 `memset(0x1001494c)` 各 1 次 ⇒ 「L2M 无递归」的旧结论维持 [A]。

## 三、T1 · mode 1 / mode 2：段内隔笔扫描

$$
\text{mode1: } \forall\,\text{rec}\in C1,\ \text{rec.dir}=-1,\ \text{span}\ge 4,\ 
\forall i\in[S+3,\,E],\ i\mathrel{+}=2:
\ \text{ZG}>\text{C0}[i].p2 \ \wedge\ \text{C0}[S].p2<\text{C0}[i].p2
\Rightarrow \text{out}[\text{C0}[i].idxB]=1
$$

```
0x1000494a  test byte [rec+0x14], 1        ; flags.bit0 = 有效段
0x10004950  eax=[rec+0x0c]=E ; esi=[rec+0x08]=S ; edx=E-S+1
0x1000495c  cmp edx,3 ; setg dl            ; ★span >= 4
0x10004966  cmp [rec+0x10], -1 ; jne skip  ; ★只吃下跌段
0x1000496c  add esi,3 ; cmp esi,eax ; jg skip
0x1000497c  (内层) test byte [C0[i]+0x0c],1 ; jne cont   ; 已登记
0x10004985  fld [rec+0x19] (ZG) ; fcomp [C0[i]+0x21] (p2) ; test ah,0x41 jne cont
0x10004997  fld [C0[S]+0x21]   ; fcomp [C0[i]+0x21]       ; test ah,0x05 jp  cont
0x100049a0  eax = [C0[i]+0x15] (idxB) ; fst [out + eax*8] ; fld1 只压一次
0x100049a6  i += 2 （edx += 0x62 = 2×0x31）
```

mode 2 与之逐条镜像（0x100049e5–0x10004a60）：`dir==+1`、`ZD(+0x25)` 对 `p1(+0x19)`、`C0[S].p1 < C0[i].p1`、写 `idxA(+0x11)`。四个比较站点的 `test ah` 掩码两两互换（`0x41/jne` ↔ `0x05/jp`），是镜像的字节级直证。

**语义 [B]**：段内「相对段首抬高（压低）、但仍贴着中枢带沿（ZG/ZD）」的隔笔 → 标 1。与 Fj/Dg/HLTurn 的 `out[]` 值域 `{0, ±1, ±2}` 一致（本模式只写 `+1`）。

**冗余点 [A]**：`span>=4` 已蕴含 `S+3 <= E`，0x10004971 的 `jg` 是原 `for` 初始化检查的残留。

## 四、T2 · mode 3 / mode 4：C2 槽状态机

遍历改成 **C0 逐笔**（`k = 1 … C0.count-1`），4 路展开（trip `((n-5)>>2)+1`，标量尾起点 `trip*4+1`）。C2 与 C0 同下标同步推进（`esi += 0x60 = 4×0x18`，`ecx += 0xc4 = 4×0x31`）。

```
if (C0[k].mark & 1) goto next;
s2 = C2[k].slotB[2];                 ; +0x16
if (s2 == -3 || s2 == +3) {          ; 0xFD / 0x03 —— 结构边界：清参考
    haveRef = 0;
    if (C2[k].slotB[1] == SEED) { haveRef = 1; refLo = C0[k-1].p2; refHi = C0[k-1].p1; }
    goto next;
}
if (haveRef && C0[k].dir == DIRGATE && refLo < C0[k].p2 && refHi > C0[k].p1)
    out[C0[k].idxB] = 1.0;           ; 「前一笔完全包含当前笔」
next:
if (C2[k].slotB[1] == SEED) { haveRef = 1; refLo/refHi = C0[k-1].(p2, p1); }   ; 0x10004ad1
```

| mode | SEED (`slotB[1]`) | DIRGATE | 参考笔 | 写点 |
|------|-------------------|---------|--------|------|
| 3 | `−2`（`0xFE`） | `+1` | `k−1` | `idxB` |
| 4 | `+2` | `−1` | `k−1` | `idxB` |

- 四个写点：mode3 `0x10004bbc / 0x10004bf8 / 0x10004c35 / 0x10004c72`（+ 标量尾 `0x10004d0b`）；
  mode4 同构 `0x10004ea1 / 0x10004edd / 0x10004f1a / 0x10004f57`（+ 尾 `0x10004d0b` 对应 `0x10005004`）。
- x87 轮转：单元素窗口 `fxch st(1) → fcom p2; fxch st(2) → fcom p1; fxch st(1) → fst; fxch st(1) → fxch st(2) → fxch st(1)`，
  **净栈效应恒等**（三处 `fxch` 归位）；写入的是窗口内的 `st(0)`，即常驻的 `fld1`（1.0）[B]。
- mode3/4 退出时 4 次 `fstp`（栈深 4），mode1/2 只 1 次（栈深 1）—— 栈深差异与展开层数一致 [A]。

**语义 [B]**：`slotB[2] ∈ {±3}` 是「结构边界」标记（清空参考链），`slotB[1] ∈ {±2}` 是「锚点」（把前一笔定为参考）；
其后任何一笔若被参考笔**完全包含**（低更高、高更低），则打标。可理解为「以一个被 ±2 标记的笔为尺，标出其后被其吞没的同向笔」。

## 五、T3 · 包装层与 P 的来源

```
TAFLib 0x100135e0 (ret 0xc):
  code = 0xEA61 ; if (!authorize(code)) { memset(out,0,n*8); return 0; }   ; 试用版清零不报错
  Fetch6Buffers(this, &buf6)                                              ; a3 = &buf6
  fn = (*(this[+0xbc]))->vt[+0x90]                                        ; ch_api 虚表槽 +0x90
  fn(n, out, &buf6, P)                                                    ; P 由导出函数的第 3 实参给出
```

- `P` 在 chlib 侧按 `(int)(*(double**)a4)[0]` 取（`fld qword [[a4]] + _ftol2`），与 NChBi 族「P 分派」同一 idiom。
- `a3[+0xc]`（6-buffer 结构的第 4 个缓冲）在 L2M 内**只做非空门**，随后 `edi` 被 `C0.base` 覆盖，从不解引用 —— [B]；若与 `out` 同址，则等价于把「输出缓冲」写进前置条件，需 frida 确认 [C]。

## 六、T4 · 遗留基元 6 支

| 地址 | 身份 | 关键证据 |
|------|------|----------|
| `0x1000f010` | **C3 单条写入器**（`void f(engine, i)`）：越界返；`C3[i].valid=1, c0Index=i`；`dir = (C0[i].dir==-1) ? +1 : -1`；`barIdx = (dir==-1) ? idxA : idxB`；`hi=p1, lo=p2` | `0x1000f019..f066` 逐字段 |
| `0x1000f070` | **C3 区间打标器**：`for i∈[start..end]`（clamp 到 `C0.count`）`valid = (valid & 0xFE) \| 2`（bit1 = 已收尾） | `0x1000f089..f09d` |
| `0x1000f0b0` | **C3 反向查有效记录**：从 `i` 向 0 扫，返回首个 `valid&1` 的记录指针，越界/无则 0 | `0x1000f0c0..f0d7` |
| `0x1000f490` | **候选点收集器 A（取 p1 = 高）**：`for i=start..end step 2` 压入 `{f64 C0[i].p1, i32 i}`，尾部 `std::reverse` | `0x1000f4ef`（`fld +0x19`）、`0x1000f570` 反转对 |
| `0x1000f5b0` | **候选点收集器 B（取 p2 = 低）**：同上，`fld +0x21` | `0x1000f60f` |
| `0x10013f00` | MSVC **局部展开 / EH 辅助**（funclet `0x10014870` + `0x10014440`），非业务逻辑 | `0x10013f19..f52`；两分支均以 `call 0x10013f00` 自递归做链式展开 |

- **选择者直证 [A]**：`0x1000fe96`、`0x100107ac`、`0x10010974` 三处均为
  `if (rec.dir == -1) call 0x1000f490 else call 0x1000f5b0` ⇒ 下跌段取**高点**序列、其余取**低点**序列。
- **vector 元素 = 12 字节** `{f64 价 @+0, i32 笔序 @+8}`：`0x2aaaaaab` 魔数（/12）与反转步长 `0xc` 双向确证；
  局部记录基址 `[esp+0x14]`，`push` 后 `fstp [esp+0x18]` = 基址 +0、`mov [esp+0x20],edi` = 基址 +8（★栈槽 +4 换算）。

## 七、勘误与待仲裁

1. **勘误（相对第二批旧记）**：L2M 并非「读段数组 `obj[+0x30]` 的 695 行单体」那么简单——
   `obj[+0x30]` 是 **C1 段数组**，但 mode 3/4 完全绕开 C1、改为扫 **C0 笔 + C2 槽**；四个模式的容器依赖不同。
2. **勘误**：`family_recon.txt` 记「记录字段 `[+0x29]/[+0x31]`」是当时把 `ecx` 窗口基址当记录基址的读数；
   按窗口还原后实为 `C0[k].p1(+0x19) / C0[k].p2(+0x21)`（C0 stride 0x31，窗口基址 = `&C0[2].p2`）。
3. **待仲裁 [C]**：`a3[+0xc]` 语义（只做非空门，从不解引用）。
4. **待仲裁 [B]**：mode 3/4 写入值取 `fld1` 常驻 1.0 —— 由「窗口净栈恒等 + 三处 fxch 归位」推出，
   建议 frida 在 `0x10004bbc` 打点核验写入量（`0x10004bbc` 前 `st(0)`）。
5. **待仲裁 [C]**：`0x1000f0b0` 的 `js` 前置判据对应参数 `i < 0`，但进入前 `ecx` 来自何处的符号（正向/反向查）待与调用者对齐。
6. **口径说明**：`cfg_blocks.py` 报 321 块（调用后切块），`cond_*` 工具报 189 块（不切）；本批以支配树为准，两数并用时须注明口径。

## 八、可复现命令

```bat
set PY=C:\Users\Administrator\Documents\a_conda\python.exe
cd /d D:\a_ronglide\clone-ronglide\tools\re-inventory\nchzs

%PY% ..\disasm_func.py 0x100048a0 --max 0x700 --dll ..\..\..\ronglide-app\chlib.dll > chlib_100048a0.txt
%PY% cfg_blocks.py chlib_100048a0.txt -o l2m_cfg.txt
%PY% ..\x87_sim.py chlib_100048a0.txt -o l2m_x87sim.txt
%PY% x87_path.py chlib_100048a0.txt --start 0x10004aac --end 0x10004c90 --init "1,0,0,0" --max-paths 120
%PY% scan_xref.py 0x1000f490 0x1000f5b0 0x10011ba0 0x10011da0 0x100126d0 --back 4
%PY% ..\disasm_func.py 0x100135e0 --max 0xa0 --dll ..\..\..\ronglide-app\TAFLib.dll > taf_100135e0.txt
```

## 九、下一步

1. **（首选）NChZs 族第 3 层剩余产出函数清点**：以 `L2M` 的 4 mode 为模板，反查 `NChZsSel / SelPri / SelSlPri / SelSpPri / NChZsBs3` 里哪些 mode 实际被导出包装传入（P 常量表）。
2. （次选）`0x1000f490/f5b0` 的下游消费者定位：谁读那 12 字节候选序列，是否回填 C3。
3. （第三）新族 kickoff：`ChZhongShu(BIZHONGSHU, EA61)` 或 `zsdg(CHZSDG, EA63)`。
4. （可选，需用户在场）frida 挂 `0x10004bbc`（mode3 写点）与 `0x100135e0`（P 实参）终判 [B]/[C] 项。
