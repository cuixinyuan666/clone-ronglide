# NChZs 第五批 — 招牌成员消费链收口（Fj / Dg / HLTurn + mode 选用者）

> 批次：NChZs 族第五批（2026-10-17）　｜　范围：chlib.dll @0x10000000 + TAFLib.dll @0x10000000
> 前置：docs/31（入口链）· docs/32（核心体/三兄弟）· docs/33（构建链中段/C1 语义）· docs/34（消费侧闭环）
> 本批不改动任何软件安装目录文件；全部证据为静态反汇编 + 常量读数 + 跨模块 xref。

## 一、背景与目标

NChZs 族前三批已把「引擎对象 → 4+1 容器 → 构建链 → C3 写入器 → V 产线」全部打开，
但**招牌成员**（直接用公式名导出的 NChZsFj / NChZsDg / NChZsHLTurn）一直只有地址没有解码。
本批目标：

1. 三支成员逐条解剖（签名、容器依赖、门表、输出语义）；
2. 钉死 `engine[+0x14]/[+0x18]` 与 **mode 1 / 2 / 0x66** 的选用者（与 engine vt[+0x10] 相关）；
3. 顺手把消费侧读 C3 的**真实字段布局**从"推测"升级为"三支交叉实证"。

## 二、摘要表

| 项 | 结论 | 证据 |
|---|---|---|
| 三支签名 | `int fn(int n, double* out, void* buf, int arg3)`，`ret 0x10`；成功返 0、容器缺失返 -1 | 三支 prologue/epilogue |
| 三支共同外壳 | `memset(out,0,n*8)` → `engine = this[+0x18]` → C0/C3/C0.count 三重非空门 | 同上 |
| 输出语义 | `out[bar] ∈ {0, ±1, ±2}`：±1 = 成员主体写（方向），±2 = 共用收尾器 0x100069b0 写（段级端点） | `_read_consts.py`：±2.0/±DBL_MAX |
| Fj（0x10005020, 384 行） | **C3 端点直译器**：`out[C3.barIdx9] = ±C3.dir`，**0 个 x87 比较站点** | x87_sites.txt |
| Dg（0x10005160, 260 行） | **段内极值点**：升笔取最高高价、降笔取最低低价，写 `out[极值 bar] = ±1` | 4 个比较站点 |
| HLTurn（0x10005480, 318 行） | **段起点/转折点**：升笔取最低低价、降笔取最高高价 | 10 个比较站点 |
| 价格数组 | **engine[+8] = 高价数组、engine[+0xc] = 低价数组**（本批确权） | Dg 指针差换算 + p1/p2 语义交叉 |
| C3 布局 | `{i32 dir@0, u8 valid@4, i32 c0Index@5, i32 barIdx@9, f64 高@0xd, f64 低@0x15}` | 三支交叉读取点 |
| dispatch 三 mode | **1 / 2 / 0x66**（前三批记 0x65，本批勘误：`sub 1 + sub 1 + sub 0x64`） | 0x1000ed20 |
| mode 选用者 | **静态侧无选用者**（两模块 100% 覆盖、`call [reg+0x10]` 计数 = 0） | mode_selectors.txt |
| limit 源 | 只有 **engine[+0x14] = n** 作右边界兜底；engine[+0x18] 三支 **0 次读取** | 0x10011500 等 |
| 授权码 | 三支均 `(this[+0xb8] > 1) ? 0xEA63 : 0xEA61`；失败 → **清零输出并返 0** | taflib_10013660/… |

## 三、T1 NChZsFj @0x10005020（384 行）— C3 端点直译器

### 3.1 调用链（本批新增实证）
```
TAFLib 0x10013660 (NChZsFj 导出, ret 0xc)
   ↓ code = this[+0xb8]>1 ? 0xEA63 : 0xEA61 ; Authorize(0x10014e60, code)
   ↓ Fetch6Buffers(0x10006cc0)(this, &buf)
   ↓ api = this[+0xbc] ; fn = api->vt[+0x94]
chlib 0x10005020 (NChZsFj 实现)
```
ch_api 虚表 **0x10015214** 实测：`+0x94→0x10005020`、`+0x98→0x10005160`、`+0x9c→0x10005480`，
邻槽 `+0x80/84/88/8c/90 → 0x100046c0/46e0/4700/4720/48a0`、`+0xa0/a4/a8/ac/b0 → 0x10005810/58f0/5a50/5bb0/5d10`。
注册表（`scan_registry.py` 重跑，274 条）`NCHZSFJ=1262 / NCHZSDG=1263 / NCHZSHLTURN=1264` 连续，三支确为同族邻居。

### 3.2 主体
```
int NChZsFj(int n, double* out, void* buf, int a3)          // ecx = ch_api*
{
  memset(out, 0, n*8);
  engine = *(Eng**)&this[+0x18];
  if (!engine->C0.base || !engine->C3.base || !engine->C0.count) return -1;   // 0x10005156
  last = -1; i = 0;
  if (engine->C0.count >= 4) {                       // 4× 展开（指针步进 0x74 = 4×0x1d）
     for (; i < C0.count - 3; i += 4)
        for (s = 0; s < 4; s++) {
           e = C3[i+s];
           if (e.valid(+4) & 1 && e.barIdx9 >= 0 && e.barIdx9 < n) {
              out[e.barIdx9] = (double)e.dir;        // ★ fild dword [e+0] → fstp qword
              last = i + s;
           }
        }
  }
  for (; i < C0.count; i++) { /* 尾循环 0x100050f7..0x10005124，同一逻辑 */ }
  if (last > 0 && last < n-1)
     tail(out, C0.base, C0.count, C3[last].dir, /*eax=*/C3[last].c0Index5 + 3);   // 0x100069b0
  return 0;
}
```
- **迭代上界用 `C0.count`、元素步进用 C3 的 0x1d** ⇒ 隐含 `C3.count == C0.count`（与 docs/33 的 C2/C3 同源于 C0 一致）。
- 语义：**逐条把 C3 两端点按方向打点**，不涉及任何价格比较（`x87_sites.txt` 对 Fj 输出"**无任何 fcom/fcomp 站点**"）。

## 四、T2 NChZsDg @0x10005160（260 行）— 段内极值点

```
int NChZsDg(int n, double* out, void* buf, int a3)
{
  memset(out, 0, n*8);
  engine = this[+0x18];
  hiArr = engine[+8]; loArr = engine[+0xc];          // ★ [esp+0x20]/[esp+0x10]（+4 换算见 §7.1）
  if (!engine->C0.base || !engine->C3.base || !engine->C0.count) return -1;
  vector<Rec29> tmp; tmp.resize(C0.count);           // 0x10006b60：元素 0x1d（imul esi,0x1d）
  for (i = 0; i < C0.count; i++)
     if (C3[i].valid && C3[i].barIdx9 >= 0) { memcpy(tmp[m++], &C3[i], 0x1d); }   // rep movsd×7+movsb
  if (m <= 0) goto done;
  for (k = 0; k < m; k++) {
     cur = tmp[k];
     acc = (cur.dir == 1) ? hiArr[cur.barIdx9] : loArr[cur.barIdx9];
     best = cur.c0Index5;
     // 前段：C0 索引 (k==0 ? cur.c0Index5 : tmp[k-1].c0Index5 + 3) .. cur.c0Index5
     for (j = prev5 + 3; j <= cur.c0Index5; j++) {
        lo = (C0[j].dir == -1) ? C0[j].idxB(+0x15) : C0[j].idxA(+0x11);
        hi = (C0[j].dir == -1) ? C0[j].idxA(+0x11) : C0[j].idxB(+0x15);
        if (lo <= lastBest) continue;
        for (b = lo; b <= hi && b <= n-1; b++) {
           if (cur.dir == 1) { if (acc <= hiArr[b]) { acc = hiArr[b]; best = b; } }   // max(高)
           else              { if (acc >  loArr[b]) { acc = loArr[b]; best = b; } }   // min(低)
        }
     }
     // 后段：cur.c0Index5 + 3 .. tmp[k+1].c0Index5 - 3（0x10005332..0x100053e6）
     out[best] = (double)cur.dir;                    // 0x100053f9 fild [ecx-5] → 0x10005407
  }
  if (lastBest > 0 && lastBest < n-1)
     tail(out, C0.base, C0.count, tmp[lastBest].dir, /*eax=*/lastBest + 3);
done:
  free(tmp);  return 0;
}
```
`[B]` **疑点（保留）**：`best` 初值取 `cur.c0Index5`（C0 笔序号），而扫描命中后取 **bar 下标**，
`out[best]` 两者混用 ⇒ 原始代码在"该记录无任何有效扫描区间"时存在**下标种类混用**的隐患
（死循环不会崩，但会写到错误 bar）。登记为遗留，不掩盖。

## 五、T3 NChZsHLTurn @0x10005480（318 行）— 段起点/转折点

```
int NChZsHLTurn(int n, double* out, void* buf, int a3)
{
  memset(out, 0, n*8);
  engine = this[+0x18]; hiArr = engine[+8]; loArr = engine[+0xc];
  if (!C0.base || !C3.base || !C0.count) return -1;
  vector<Rec29> tmp; tmp.resize(C0.count);
  for (i = 0; i < C0.count; i++)
     if (C3[i].valid && C3[i].barIdx9 >= 0) tmp[m++] = C3[i];
  if (m <= 0) goto done;
  accMin = +DBL_MAX; accMax = -DBL_MAX;               // 0x100154c0 / 0x100154c8 + fld st(1)×2
  best = -1;
  for (k = 0; k < m; k++) {
     cur = tmp[k];
     if (k == 0) out[cur.barIdx9] = (double)cur.dir;   // 首点直打（0x10005562）
     for (j = k+1; j < m && tmp[j].dir != cur.dir; j++) ;
     if (j >= m) { /* 尾处理 0x10005599 */ continue; }
     // 段扫描（0x100055d4）：idx0 = max(cur.barIdx9, best); limit = tmp[j].barIdx9
     //   if (n - idx0 < 4) 走短路径 0x10005759（单步直到 n，无 limit）
     //   否则 4× 展开 + 尾块：
     //     dir == 1  → 在 loArr 上求 min（test ah,0x41 / jne）
     //     dir == -1 → 在 hiArr 上求 max（fxch 后 test ah,0x05 / jp）
     if (hitBar >= 0) { out[hitBar] = (cur.dir == 1) ? +1.0 : -1.0; best = hitBar; }
       // 0x100057c5..e0: cmp dir,1 / setne / lea eax,[eax+eax-1] → +1 或 -1
  }
done:
  free(tmp); return 0;
}
```
- 与 Dg 的**方向恰好相反**：Dg 取"段内最高高/最低低"（顶底），HLTurn 取"段内最低低/最高高"
  （起涨低点 / 起跌高点）⇒ HLTurn 是**转折点**标注，Dg 是**极值点**标注。
- 首点直打（k==0）+ 段末极值各打一次，是两支之外**独有**的"双写"形态。

## 六、T4 mode 1/2/0x66 与 limit 源（本批点睛）

### 6.1 dispatch 三 mode 精确值（★ 勘误 0x65 → 0x66）
```
0x1000ed20: if (mode==0) return -1;  V.compact(&engine[+0x5c]);
            movzx eax, byte [ebp+8]
            sub 1 → je 0x10011500        ; mode 1
            sub 1 → je 0x10011660        ; mode 2
            sub 0x64 → jne fail          ; mode = 1+1+0x64 = 0x66
            call 0x100117b0              ; mode 0x66
```

### 6.2 三支 producer 对照（V 子记录 = `{u8 tag, i32 bar, f64 v1, f64 v2, f64 v3}`，0x1d）
| 项 | mode 1 @0x10011500 | mode 2 @0x10011660 | mode 0x66 @0x100117b0 |
|---|---|---|---|
| 循环 | `C0.count <= 1` 退出；i 从 0 起、看 C0[i+1] | `<= 2` 退出；i 从 2 起、看 C0[i] 与 C0[i-1] | 同 mode 2 |
| C2 解析 | `i8[+0x14]<0→ptr[+4]`，`i8[+0x17]<0→ptr[+0x10]` | 同（`jge/jge`） | `jle/jle`（符号翻转） |
| 子对象方向 | `p[0x10]==1` | `p[0x10]==1` | `p[0x10]==-1` |
| span 门 | `(span>3?span-1:span) >= 7` ⇒ span ≥ 8 | `>= 5` ⇒ span ≥ 6 | 同 |
| 相位门 | `i - lo + 1 == 8`（i = lo+7） | `i - lo == 8` | 同 |
| C0 方向 | `C0[i+1].dir == 1` | `C0[i].dir == 1` | `== -1` |
| 单调门 | `C0[i+1].p2 > C0[lo..i].p2` 全部 | `C0[i-1].p2 < C0[i].p2` | `C0[i-1].p1 > C0[i].p1` |
| 扫描起点 | `C0[i+1].idxB(+0x15)` | `C0[i].idxB(+0x15)` | `C0[i].idxA(+0x11)` |
| 扫描上界 | `(i+2<count) ? C0[i+2].idxA : engine[+0x14]-1` | 同（idxA） | 同（idxB） |
| 价格数组 | engine[+8] | engine[+8] | engine[+0xc] |
| 命中条件 | `price[b] < C0[i].p2`（跌破前低） | `price[b] < C0[i-1].p2` | `price[b] > C0[i-1].p1`（突破前高） |
| V.v1(+5) | `C0[i].p2`（低） | `C0[i].p2` | `C0[i].p1`（高） |
| V.v2(+0xd) | `C0[i+1].p2` | `C0[i-1].p2` | `C0[i-1].p1` |
| V.v3(+0x15) | 0.0 | 0.0 | 0.0 |

⇒ mode 1 = "**低点抬高**序列后首个跌破前低的 bar"；mode 2 = "相邻两笔低点抬高后首个跌破前低"；
mode 0x66 = 上述的镜像（**高点降低** + 首个突破前高）。
三者都把结果 `push_back` 到 V（0x10011a70），出口唯一。

### 6.3 V 向量与 push_back（0x10011a70）
- 入口 `esi = engine+0x58` ⇒ 向量三字段 `begin=engine[+0x5c]`、`end=engine[+0x60]`、`capEnd=engine[+0x64]`。
- 元素大小由魔数 `0x8d3dcb09`（2^36/0x1d 定点倒数）+ `sar 4` 确证 = **0x1d**。
  `[B]` 勘误候选：docs/32/34 的"V 元素 0x74 = 4×0x1d"应改述为 **元素 = 0x1d**（0x74 只出现在 C3 的 4-路展开步进）。
- `0x10011a70` 的 xref 全表 = `0x10011627 / 0x1001177a / 0x100118ca`（恰为三支 producer）。
- `tag@+0` 三支**均未写**（`[esp+0x18]` 无写点）⇒ `[B]` 待仲裁。

### 6.4 ★ mode 选用者：静态侧「无」
| 检查项 | 结果 |
|---|---|
| chlib `.text` 覆盖率 | 81920/81920 B = 100.0%（InvalidByte 续扫，resync 仅 1 B） |
| chlib `call 0x1000ed20` 立即数 | 0（唯一引用 = .rdata+0x4ac = 虚表槽 **0x100154ac**） |
| chlib `call/jmp [reg+0x10]`（capstone） | 0 |
| chlib 字节级 `FF /2,/4 mod=01 rm=reg disp8=0x10` | 0 |
| TAFLib `.text` 覆盖率 / insns | 450560/450560 B = 100.0% / 142880 |
| TAFLib `call/jmp [reg+0x10]` | 0 |
| TAFLib 全部非索引 mem-call | 全为导入表 `0x1006f0xx/0x1006f1xx…`，无小位移虚调用 |

⇒ **engine vt[+0x10] 在两个模块内都没有调用点**；dispatch + 三支 producer + push_back 构成
**不可达子图**（当前构建）。TAFLib 侧不做任何虚调用（只走导入），也无法反触引擎私有虚表。
旁证：V 记录 `tag@+0` 未初始化，符合"遗留/未接线代码"画像。

`[C]` frida 验证方案（等用户在场执行，脚本可用 `tools/frida_trace.py` 改）：
```js
var base = Module.findBaseAddress('chlib.dll');
[0x10011a70, 0x1000ed20, 0x10011500].forEach(function(off){
  Interceptor.attach(base.add(off - 0x10000000), {
    onEnter: function(a){ console.log('HIT', off.toString(16), 'arg0=' + a[0].toInt32()); }
  });
});
// 操作：逐个加载 NChZs / NChZsSelPri / NChZsFj 指标并滚动 K 线 → 看三处计数
// 判定：全 0 ⇒ 死代码成立；若 0x1000ed20 命中 ⇒ 回查是否动态构造调用（自校验基址：chlib 与 TAFLib 首选基址同为 0x10000000）
```

### 6.5 limit 源
- **engine[+0x14] = n（bar 数）**（setter 0x1000e0b0 第 5 槽 ← 核心体 `0x100045f0` 的 a1）：
  三支 producer 均以 `engine[+0x14] - 1` 作**扫描右边界兜底**，仅在 `i+2 >= C0.count` 时启用。
- **engine[+0x18] 三支 producer 内 0 次读取**（派单假设需**勘误**）；本批全族证据内未见任何读者，
  登记为遗留项（布局表记 u8 标志）。
- 主边界优先用**下一笔的索引**：`C0[i+2].idxA`（mode 1/2）或 `C0[i+2].idxB`（mode 0x66）。

## 七、勘误与待仲裁

### 7.1 ★ 栈槽 +4 换算（铁律，再次生效）
Dg 首段 `mov [esp+0x2c],ecx`（ecx=engine[+8]）在 `add esp,0xc` **之前**，
第二次 `mov [esp+0x2c],ecx`（ecx=C0.base）在**之后** ⇒ **两个不同栈槽**：
- 0x10005194 的 `[esp+0x2c]` = 后续代码的 **`[esp+0x20]`**（差 0xc）。
⇒ `[esp+0x20]=engine[+8]`、`[esp+0x10]=engine[+0xc]`、`[esp+0x2c]=C0.base`、`[esp+0x40]=C0.count`。
（WIP-A 把它记作"无写点局部"是**读错**，本批作废。）

### 7.2 C3 记录布局（相对 docs/34 权威表五节的更正）
三支交叉读取点一致给出：
| 偏移 | 类型 | 语义 | 依据 |
|---|---|---|---|
| +0x00 | i32 | **dir ±1** | Fj `fild [e]`；Dg/HLTurn `fild [ecx-5]` |
| +0x04 | u8 | **valid bit0** | 三支 `test byte [e+4],1` |
| +0x05 | i32 | **C0 笔序号**（扫描边界/补点起点） | Fj `eax = [e+5]; add eax,3` 送 C0 扫描；Dg `imul 0x31` 索引 C0 |
| +0x09 | i32 | **bar 下标**（out[]/价格数组） | 三支 `[e+9]` 做 `*8` 下标 |
| +0x0d | f64 | **高价**（= C0.p1 +0x19） | 0x1000ebe0 后处理写入 |
| +0x15 | f64 | **低价**（= C0.p2 +0x21） | 同上 |
⇒ docs/34 / `chzs_container_layout.txt` 五节原记 `{i32 barIdx@0, f64 价@4, u8=1@0xc}` **不成立**，
本批按上表为准（已在权威表加勘误段）。
同时确权：**C0.p1(+0x19)=高、C0.p2(+0x21)=低**（GG/DD 更新器 0x1000edb0/edd0 判据）。

### 7.3 dispatch 第三 mode = 0x66（前三批记 0x65）
`sub eax,1 / sub eax,1 / sub eax,0x64` 累减 ⇒ 1 + 1 + 0x64 = **0x66**。

### 7.4 engine[+8]/[+0xc] = 高/低价数组
Dg 用 `hiArr - loArr` 的字节差做同下标换算（`sub edi,[esp+0x10]`）后 `fcom [edi+edx]`，
才能读到 `hiArr[idx]`；再结合 mode 1/0x66 的 p1/p2 用法（低点抬高 / 高点降低），
三方自洽 ⇒ **+8 = 高、+0xc = 低**。

### 7.5 待仲裁
- `[B]` Dg 的 `best` 下标种类混用（C0 序号 vs bar），见 §4。
- `[B]` V 记录 `tag@+0` 未初始化，三支皆然，消费者（SelPri）如何解读待查。
- `[B]` V 元素尺寸表述（0x74 → 0x1d），docs/32/34 相关句子待统一。
- `[C]` dispatch 无调用者 ⇒ 死代码判定，需 frida 终判（§6.4）。
- `[C]` Fj 尾调用 `0x100069b0` 的第 5 参走 **eax 寄存器**（非 cdecl），已由两处调用点交叉确认，
  但同族是否还有其它"寄存器实参"约定未系统排查。

### 7.6 授权/试用行为（新发现，产品级）
包装层未授权时**不是返回错误码，而是 memset 清零输出并返回 0** ⇒
试用版这些指标显示为全 0（看起来像"没信号"），而非报错。三支一致（Fj/Dg/HLTurn）。

## 八、可复现命令

```bash
PY=C:/Users/Administrator/Documents/a_conda/python.exe
cd /d/a_ronglide/clone-ronglide

# 1) 三支成员全文（含函数尾）
$PY tools/re-inventory/disasm_func.py 0x10005020 --max 0x700 --dll ronglide-app/chlib.dll
$PY tools/re-inventory/disasm_func.py 0x10005160 --max 0x700 --dll ronglide-app/chlib.dll
$PY tools/re-inventory/disasm_func.py 0x10005480 --max 0x700 --dll ronglide-app/chlib.dll

# 2) 共用收尾器 / 分配器 / push_back
$PY tools/re-inventory/disasm_func.py 0x100069b0 --max 0x140 --dll ronglide-app/chlib.dll
$PY tools/re-inventory/disasm_func.py 0x10006b60 --max 0x100 --dll ronglide-app/chlib.dll

# 3) TAFLib 包装（授权码直证）
$PY tools/re-inventory/disasm_func.py 0x10013660 --max 0xa0 --dll ronglide-app/TAFLib.dll

# 4) x87 站点表 + 四个常量
$PY tools/re-inventory/nchzs/x87_sites.py            # 需在 tools/re-inventory/nchzs/ 下执行
$PY tools/re-inventory/nchzs/_read_consts.py

# 5) dispatch 选用者（双模块）
$PY tools/re-inventory/nchzs/scan_dispatch.py -o tools/re-inventory/nchzs/dispatch_scan.txt
$PY tools/re-inventory/nchzs/scan_xref.py 0x1000ed20 0x10011500 0x10011660 0x100117b0
$PY tools/re-inventory/nchzs/scan_xref.py 0x10011a70 0x10012550
```

## 九、下一步（候选，按优先级）
1. **NChZsL2M 分块收口**（695 行 / 189 基本块 / 仅 2 个直接调用）——按支配树分块，先出块表再逐块判语义。
2. **T3 遗留基元**：`0x1000f490` / `0x1000f5b0`（候选生成器）+ `0x1000f070` / `0x1000f010` / `0x1000f0b0` / `0x10013f00`。
3. **frida 终判**（需用户在场）：V 产线可达性 + 三支成员的 out[] 实际取值分布（±1/±2 验证）。
4. **新族 kickoff**：`ChZhongShu`（BIZHONGSHU, EA61）或 `zsdg`（CHZSDG, EA63）。
