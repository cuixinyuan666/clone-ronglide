# CHBI 第三批 — P=51 分型笔全链与共用后处理

> 2026-10-16 ｜ 目标: `ChBi` @ `0x1000f580`（EA62 门控）
> 证据: `tools/re-inventory/chbi/` 下
> `core_1002c1d0.txt`（两入口全反汇编）、`f_1006a040.txt`+`cond_1006a040.txt`、
> `f_1003eba0.txt`、`f_1003ef00.txt`、`f_1003e200.txt`、
> `f_1003f0d0.txt`、`f_1003f150.txt`、`f_1006a720.txt`、`f_1006a5e0.txt`、`f_1006b050.txt`、
> `f_1003d780.txt`、`f_1003d8a0.txt`；常量经 pefile 直读校验
> 置信度: [A] 字节级实证 ｜ [B] 多路交叉 ｜ [C] 待仲裁

---

## §0 结论摘要

1. **`0x1002c1d0` 全文结构闭合** [A]：
   `db40 → e200 →（P∈{11,12,21,22,31,32} 才跑臂）→ [P==51: a040 → eba0 → ef00 → EA62 门] → 输出环`。
   P=51 时 **eba0/ef00 只跑一次**（在 a040 之后，0x1002c317/0x1002c31d）——
   上一批"可能先空跑一遍"的推测被否定（0x1002c2b5 的 `jne 0x1002c30b` 直接跳过 0x1002c2ff/0x1002c300/0x1002c306）。
2. **输出公式** [A]：遍历 m0（0xA0 步进）：
   `out[elem.bar − 1] = (double)(elem.+0x20)`；若 `elem.+0x98 == 1` 则 `×2`
   （即 −1 → −2；`fild` int→double）；空档位置补 0；**out 数组在入口处先整表清零**
   （0x1002c263 的 `fst qword [edi+eax−8]` 存的是 ST0=0，非 H——修正第一批伪码）。
3. **a040 复核** [A]：`lea esi,[ebx−1]` 仅在循环前执行一次（循环回跳点 0x1006a116），
   故 `esi==1` 是**常量比较**；"向上笔借上一条 push 的底端、向下笔借其顶端"的借用语义确认；
   序号计数从 1 起（先自增后用），`#rec = #标记 − 1`。
4. **3eba0 / 3ef00 首次全文解码** [A]：分别把 m5 记录按方向拆入 ContA(W+0x20, 向下笔) /
   ContB(W+0x30, 向上笔)、以及全量复制到 ContC(W+0x40)；三者同时给 m0 端点戳 ±1 标志
   （`+0x20`: 顶=+1 / 底=−1），与 a040 尾块同构。
5. **e200 判据闭式** [A]：顶 ⇔ H、L 同时严格高于左右邻居；底 ⇔ 同时严格低于；
   无匹配不写（db40 已把 `+0x14` 清 0）。
6. **x87 双操作数比较惯用式修正表**（见 §3.2）与 docs/20 §1.2 勘误一致；
   对 docs/20 §4.3 的 db40 条件表逐行复核：第 5 行（`ah,0x41 / je` = 跳=大于）、
   第 11 行（`ah,0x44 / jnp` = 相等）、第 15 行（`fucompp + jp`）均**无需修订** [A]。
7. 常量：`[0x1006fc28] = 0.001`（double）、`[0x1006fc50] = −1.0f`、`[0x1006fc60] = 2.0f` [A]。

---

## §1 0x1002c1d0 全结构（修正版）[A]

```
sub_1002c1d0(ctx, count, outD, series, iface)         ; ret 0x14 (5 参数)
  ctx   = 指向 W 的持有指针 ([ctx] = W)
  series= { double *H; double *L; double *P; }        ; P 指向 double
  iface = 接口对象 (vtbl[1](code) = 授权查询)

  if (count <= 0)       return -1;                    ; 0x1002c1e1
  if (iface == NULL)    return -1;                    ; 0x1002c1e7
  bufA = new float[count];                            ; 0x1006b34a
  bufB = new float[count];
  for k: bufA[k]=(float)H[k]; bufB[k]=(float)L[k]; outD[k]=0.0;   ; 0x1002c24d

  W *w = *ctx;
  sub_1003db40(w, count, bufA, bufB);                 ; 0x1002c281
  sub_1003e200(w);                                    ; 0x1002c288 (EAX=W)

  P = (int)*(double*)series->P;                       ; 0x1006bc70 = double->int

  k = 0x0B(11) → f170(w,1) ┐
  k = 0x0C(12) → f170(w,2) ├ 这些臂执行完汇于 0x1002c2ff:
  k = 0x15(21) → b1e0(w,1) │   eba0(w); ef00(w);      ; 0x1002c300/0x1002c306
  k = 0x16(22) → b1e0(w,2) │
  k = 0x1F(31) → f430(w,1) │
  k = 0x20(32) → f430(w,2) ┘
  其它 → 直接到 0x1002c30b（跳过 eba0/ef00）

0x1002c30b: if (P == 0x33 /*51*/)
  {
      sub_1006a040(w);                                ; 0x1002c311
      sub_1003eba0(w);                                ; 0x1002c317
      sub_1003ef00(w);                                ; 0x1002c31d
      if (!iface->vtbl[1](0xEA62))  return -1;        ; 0x1002c322..0x1002c334
  }
  /* 输出环 0x1002c33a..0x1002c466 */
  cur = 0;
  for (elem m0.begin() .. m0.end(), 步进 0xA0)
  {
      b = elem->bar;
      while (cur < b-1) outD[cur++] = 0.0;            ; 0x1002c411 rep stosd (2*count dwords)
      v = elem->+0x20;                                ; int
      if (elem->+0x98 == 1) v *= 2;                   ; 0x1002c42d..0x1002c438
      outD[b-1] = (double)v;                          ; fild int / fstp qword
      cur = b;                                        ; 0x1002c450
  }
  free(bufB); free(bufA); delete(it);                 ; 0x1006b344/0x1006b344/0x1006b320
  return 0;                                           ; 0x1002c496
```

- 未支持 P（如 0x40）：db40/e200 的产物留在 m0（+0x20 全 0）→ 输出全 0，与"未授权/未支持 = 空状态"观感一致。
- 失败路径（count<=0 / iface==NULL / EA62 拒绝）统一 `mov eax,-1; ret`。

## §2 P=51 的第二个入口 0x1002c4b0 [A]

```
sub_1002c4b0(EAX=series, arg1=W持有指针, arg2=count, arg3=outD, arg4=iface)
  与 §1 完全同链（无 P 读取）:
  db40(w,count,bufA,bufB); e200(w);
  a040(w); eba0(w); ef00(w);
  if (!iface->vtbl[1](0xEA62)) return -1;
  输出环（同上）; return 0;
```

即"硬编码 P=51 版"。第一道 EA62 门在包装层 `0x1000f580`（docs/18），此处为第二道（对 iface）。

## §3 0x1003e200 复核（严格包含分型）

### 3.1 判据 [A]
```
n = m0.size();  if (n <= 1) return;
it = m0.begin() + 1;                       ; 0x1003f0d0(idx=1)
for (i = 1; i <= n-2; i++, it++)           ; 只处理"内部"元素
    顶(i) ⇔ H[i-1] < H[i] && L[i-1] < L[i] && H[i+1] < H[i] && L[i+1] < L[i]  → +0x14 = +1
    底(i) ⇔ H[i-1] > H[i] && L[i-1] > L[i] && H[i+1] > H[i] && L[i+1] > L[i]  → +0x14 = −1
    其余（含 =、unordered）不写
```
- 等价闭式（docs/20 §5.2 已给）：顶 ⇔ H[i] > max(H[i±1]) 且 L[i] > max(L[i±1])。
- 写点：0x1003e354（顶）/ 0x1003e3d7（底）；仅匹配时写。 [A]

### 3.2 x87 标志语义表（本次实证，与 docs/20 §1.2 勘误一致）[A]
| 关系 (st0 vs st1) | C3 C2 C0 | `test ah,5 / jp` | `test ah,0x41 / jne` | `test ah,1 / je` | `test ah,0x44 / jnp` |
| --- | --- | --- | --- | --- | --- |
| greater | 0 0 0 | 跳 | **落** | 跳 | 落 |
| less | 0 0 1 | **落** | 跳 | 落 | 落 |
| equal | 1 0 0 | 跳 | 跳 | **落** | **跳** |
| unordered | 1 1 1 | 跳 | 跳 | 跳 | 跳 |

- 记忆法：`ah,5` = "≥（含 unordered）"；`ah,0x41` = "严格 >"；`ah,1` = "<（含 unordered）"；`ah,0x44` = "==".
- 复核工具：`0x1006a430`（"a 包含 k"判断：H_a>H_k && L_a<L_k）四路手算与反汇编逐位一致。

## §4 0x1006a040 全解码（复核 + 修正）[A]

- 备战：`n=m0.size(); if (n<=5) return;` 清 m5（0x1006a07e，`W+0x54/0x58` → 对象 W+0x50）。
- 主循环 k=2..n−2 扫描 m0[k] 读 ±1 左右（m0[k−1] / m0[k+1] 用于交替判定）。
- **首个标记元素**: 冻结入 pending（+0x1C/0x20/0x24 三个栈槽），不 push。
- 后续标记: 以 prev标记 + frozen + cur 组成笔对——
  - 向上笔: `push(k1=prev底, k2=frozen顶)` 后 `push(k1=frozen, k2=cur)`；
  - 向下笔: 同样两组 push（镜像）。
- **借用语义** [A]：每条 push 前，从上次 push 留下的栈槽借用端点——
  向上笔借 **+0x08/+0x10**（底端），向下笔借 **+0x04/+0x0C**（顶端）；
  即"bi K 与 bi K−1 共享端点"。
- **`esi==1` 常量比较**（修正）：`lea esi,[ebx−1]`(0x1006a113) 只在循环前执行一次；
  循环回跳目标是 0x1006a116（不是 0x1006a113）。
- 记录字段: `+0x00`=序号（从 **1** 起，先自增后用）；`+0x04`=顶 idx；`+0x08`=底 idx；
  `+0x0C`=顶 H；`+0x10`=底 L；`+0x14`=±1 dir；`+0x18/0x1C/0x20`=0（+0x1C 复制 frozen 类型）；
  `+0x24`=−1.0f（`[0x1006fc50]` [A]）。
- 尾块: 若循环结束时仍有 current（pending 未 flush 计数 `#rec = #标记 − 1` 验证于 0x1006a364）；
  m0 top/bottom 元素戳 `+0x20 = ±1`；所有记录 `+0x20 = 1`。
- count=6 时 wedge 退化为 1 条记录（0x1006a331 特判），与"3 标注 + 1 记录"一致。

## §5 0x1003eba0 / 0x1003ef00（共用后处理）[A]

### 5.1 0x1003eba0 —— 按方向拆分 ContA/ContB + 端点戳

```
prologue: clear ContA(W+0x24/0x28); clear ContB(W+0x34/0x38)   ; W+0x20/0x30 对象的 begin/end
for (rec in m5, 步进 0x28)                                     ; 0x1003f780 迭代器
    rec->+0x20 = 0                                             ; 先清笔端点标志
    ++counter;  tmp.+0x00 = counter                            ; counter 从 1 → 首条 = 2
    tmp.+0x04/+0x08/+0x0C/+0x10 = rec 复制
    if (rec->+0x14 == +1)  push_back(ContB对象, &tmp)          ; dir=+1 → ContB(W+0x30)
    if (rec->+0x14 == -1)  push_back(ContA对象, &tmp)          ; dir=-1 → ContA(W+0x20)
    push_back 用 0x1006a720(0x28 元素)
    m0[rec->+0x04].+0x20 = +1                                  ; 顶
    m0[rec->+0x08].+0x20 = -1                                  ; 底
    rec->+0x1C = tmp.+0x1C(保留); rec->+0x20 = 0
    （+0x24 未写 = 栈垃圾；不可依赖）
```
- m0 端点映射: `+0x04` → +0x20=+1（顶），`+0x08` → +0x20=−1（底）。
  0x1003f0d0 取 `m0.begin()+idx` 后写 `iter->+0x20`。

### 5.2 0x1003ef00 —— 全量复制到 ContC + 端点戳

```
prologue: clear ContC(W+0x44/0x48)
for (rec in m5)
    rec->+0x20 = 0
    ++counter;  tmp.+0x00 = counter                            ; 同样从 2 起
    tmp = rec 复制（+0x18/0x1C/0x20 = 0）
    push_back(ContC对象 = W+0x40, &tmp)                        ; 0x1006a720 家族
    m0[rec->+0x04].+0x20 = +1;  m0[rec->+0x08].+0x20 = -1
```

对照 a040 尾块：三条路径 (a040 / eba0 / ef00) 都执行"顶 +1、底 −1"同构戳记；
且 a040/eba0/ef00 都把记录 `+0x20` 清零（a040 随后重设为 1，eba0/ef00 不设）。
即 **eba0/ef00 是标注器，a040 是记录生成器**；三者在 P=51 链上都对 m0 有"幂等戳记"效果。

> 命名统一：**ContA = W+0x20（向下笔）｜ContB = W+0x30（向上笔）｜ContC = W+0x40（全量）**
> （旧 docs/16 的 m2/m3 命名在此正式替换；真实分派见 §5.1/§5.2）

## §6 与上批伪码的对账（差异清单）

| 位置 | docs/20 / 旧伪码 | 本批实证 |
| --- | --- | --- |
| 输出数组预填 | 未记录 | **整表清零**（0x1002c263 的 fst 存 ST0=0，不是 H） |
| dispatcher 臂后流程 | "eba0/ef00 后 return；P=51 另走" | **无 return**：臂后 eba0/ef00 → 汇于 0x1002c30b 统一判 0x33 |
| P=51 时 eba0/ef00 | "可能先跑一遍再在 a040 后重跑" | **只跑一次**（a040 之后） |
| 输出公式 | "CHBI 序列 顶/底 待定" | `out[elem.bar−1] = (±1) 或 2×(±1)` 若 +0x98 |
| a040 `esi==1` | 动态比较推测 | **常量比较**（lea 在循环外） [A] |
| 0x1003e200 | "顶/底判据 + 待仲裁字段" | 严格四项包含；仅匹配写 +0x14 |
| 0x1006fc28 | "±0.001 修正" | = 0.001(double) 指令直证 [A] |

## §7 助手函数字节级索引（供第四批与 CHDUAN 补正）[A]

| 地址 | 语义 | 关键签名 |
| --- | --- | --- |
| `0x1003f0d0` | `m0.begin() + idx` 迭代器 | ebx=W, esi=out{W,cur}, 栈参 idx, ret 4 |
| `0x1003f150` | `m0.begin()` | ecx=W, esi=out 结构 |
| `0x1003d780` | `m0.size()` | ecx=W |
| `0x1003d8a0` | 区间擦除（A0 元素） | 用于清零 m0 |
| `0x1006a5e0` | m0 的 A0 `push_back` | eax=源, esi=W |
| `0x1006a720` | 0x28 `push_back` | eax=源, esi=容器对象 |
| `0x1006b050` | 0x28 移位/erase | 用于清零 m5 等 |
| `0x1006b1c0/b1f0` | A0/0x28 元素拷贝体 | 快速路径 |
| `0x1006b344` | `operator delete` | |
| `0x1006b320` | `operator delete` 变体 | |
| `0x1006f194` | iterator 检查回调（debug 钩子） | 不参与语义 |

## §8 待办（移交第四批）

- [ ] db40：状态机 minij 表格逐条落地（96 基本块 / 25 条件），重点复核 `[esp+0x30]` 与
      `cand`（[esp+0xe0]）的互斥消费；生成 db40 的可运行单元测试。
- [ ] db40 中 `ebp=-1` 初值语义（candidate 号 = -1 表示"未设定"）。
- [ ] CHDUAN 第四批：ContA/ContB 的**顺序敏感性**（eba0 拆表顺序是否影响 prep 0x10053540 的结果）。
- [ ] 动态验证：在 m5 稳定后 dump `W+0x50` 记录表，与 Python 重放对拍。
- [ ] e200：`i=n-1` 边界之 next 判定（`it+1` 是否触发 debug 检查回调）——语义上无影响。
- [ ] 输出环在 `elem.bar` 非单调时是否会溢出（理论不可达；留观察）。
