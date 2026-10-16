# NChBi 第三批 WIP — NChBiZj/ZjOrder 链 + Out 静态深挖

起点：`49d8d66`（origin/old1 0/0）。本轮主攻静态覆盖度。

## T1 — NChBiZj（ch_api vt[+0x44] = 0x10002ea0）

反汇编：`chlib_worker_10002ea0.txt`（108 行，`ret 0x10`）。

### 签名与出口
- 4 参：arg1=count(int) / arg2=out(double*) / arg3 / arg4（arg3/arg4 本函数内未用）
- **出口**：成功 `xor eax,eax; ret 0x10`（return 0）；失败统一 `or eax,-1; ret 0x10`（return -1）
- 首段：`memset(arg2, 0, arg1*8)`（call 0x1001494c，dst=arg2/val=0/size=arg1*8）→ **out 是 double[arg1]，先清零**

### 四道门（与 NChBiSta 同构）
1. `this[+0x10]` = obj10；`obj10[+0x30]` = Item21 数组基址（→ecx）；`obj10[+0x3c]` = 条数（→edi）
2. 基址==0 → return -1
3. `this[+4]` == 0 → return -1（ch_auth* 缺失）
4. `Authorize(0xEA61)`（vt[+4]，push 0xea61）失败 → return -1
   - ★ **NChBiZj 授权码 = 0xEA61**（与 NChBiSta 同码，非 0xEA62）

### 核心：Item21 散射（scatter）
- 遍历 Item21 数组，stride **0x21**，条数 = `obj10[+0x3c]`（edi）
- 主循环按 4 条展开（`0x10002f00–0x10002f7e`，`add eax,0x84`=4×0x21）；余数走尾循环（`0x10002f80–0x10002fb2`，`add eax,0x21`）
- 每条判定与动作（四个展开体偏移交叉确证，见下）：
  - `test byte ptr [item+0x04], 4` → 若 **bit2 未置位则跳过**（flags@+0x04）
  - `mov ecx, [item+0x1d]`；`test ecx,ecx; jl skip`；`cmp ecx,ebx(count); jae skip` → 越界保护
  - `fild dword ptr [item+0x00]` → **value@+0x00 视为 int32，转 double**
  - `fstp qword ptr [out + ecx*8]` → **out[ item.barIdx@+0x1d ] = (double)item.value@+0x00**
- 四个展开体的字段偏移对照（eax 初值 = base+0x3e，逐条 +0x84）：
  - item0：val@[eax-0x3e] / flags@[eax-0x3a] / idx@[eax-0x21]
  - item1：val@[eax-0x1d] / flags@[eax-0x19] / idx@[eax]
  - item2：val@[eax+4]   / flags@[eax+8]   / idx@[eax+0x21]
  - item3：val@[eax+0x25]/ flags@[eax+0x29]/ idx@[eax+0x42]
  - （相对各 item 基址：+0x00 / +0x04 / +0x1d —— 三条全对齐，置信 [A]）

### 与 NChBiSta / NChBi 的关系
- **共享 obj10**：同样读 `this[+0x10]` 的 `[+0x30]`(基址)/`[+0x3c]`(条数) → 与 NChBiSta 读同一实例同一字段 ⇒ **NChBiZj 依赖 NChBi 先填 obj10（Item21）**
- **不读 obj8**：本函数无 `this[+8]` 引用 → 比 ZjOrder 简单
- x87：无比较链，仅 `fild`(int→double) / `fstp`（待 x87_sim 确认 0 条件）

### 待确认
- [B] 0x1001494c 是否即 memset（参数序 dst/val/size 已按 push 序推定）
- [A] flags bit2 语义 = "参与 Zj 散射"（与 NChBiSta 的 bit0/bit3 不同门）

### WIP-END T1

## 辅助函数辨识（IAT 实证，[A]）
- chlib.dll 导入仅 MSVCR80 / MSVCP80 / KERNEL32（**无 TAFLib**，再次坐实 chlib 不回调主模块）
- `0x1001494c` = thunk `jmp [0x100150c4]` = **memset** [A]
- `0x100150b0` = **free**；`0x100150b4` = **malloc**；`0x100150b8` = operator new；`0x100150c0` = operator delete
- `0x10006c00` = **std::vector<double>::resize(n)**（esi=this/向量对象，arg=n；`nv=malloc(n*8); memset(nv,0,n*8); memcpy(nv,old,size*8); free(old)`）[A]
- `0x10011900` = **std::vector 析构/清零**（`if(begin) free(begin); begin=cap=size=0`，三指针布局 begin@+0 / cap@+4 / size@+8）[A]

## T2 — NChBiZjOrder（ch_api vt[+0x4c] = 0x10003180）

反汇编：`chlib_worker_10003180.txt`（148 行，`ret 0x10`）。SEH 帧 + 栈对齐 `and esp,-8`。

### 签名与出口
- 4 参：arg1=count(int) / arg2=out(double*) / arg3=透传 / **arg4=阈值指针**
- `THR = (int)( *(double*)(*arg4) )`（`mov eax,[ebp+0x14]; mov ecx,[eax]; fld [ecx]; call _ftol2`）[A]
- 首段同 NChBiZj：`memset(out, 0, count*8)` → out 是 double[count]，先清零
- 出口：成功 `xor eax,eax; ret 0x10`；失败 `or eax,-1`

### 三段结构
**段 1（0x100031d5–0x10003237）：填本地向量**
- 取 A=`obj8[+0x1c]`、B=`obj8[+0x28]`（obj8 = this[+8]）；BASE=`obj10[+0x30]`、CNT=`obj10[+0x3c]`（obj10 = this[+0x10]）
- 门：A==0 → -1；BASE==0 → -1
- 局部 `std::vector<double> vec`（三 dword 清零）→ `0x10006c00(&vec, count)` = **vec.resize(count)**
- **调用 `vt[+0x5c]` = NChBiZjNum(count, vec.begin, arg3, arg4)**（`mov edx,[edi]; mov edx,[edx+0x5c]; … call edx`）
  - ★ vec.begin 由 `mov esi,[esp+0x2c]`→S-0x1c 取得（已修正 esp 换算，见勘误）
  - 返回非 0 → free(vec) 后 return -1；返回 0 → 继续

**段 2（0x10003261–0x10003285）：授权门（在调用 ZjNum 之后！）**
- `this[+4]`(ch_auth*) == 0 或 `Authorize(0xEA61)` 失败 → `0x10011900` 析构 vec → return -1
- ★ **NChBiZjOrder 授权码同样是 0xEA61**

**段 3（0x10003287–0x100032fe）：过滤 + 散射**
- 遍历 Item21（stride 0x21，CNT 条，esi 从 BASE+9 起）：
  - `flags@+0x04`：**bit0 必须置位**（valid），**bit3 必须清零**（排除 ×2 那类）
  - `recIdx@+0x09`：`0 <= recIdx < B`（B = Rec20 条数）
  - `barIdx@+0x1D` → `fld vec[barIdx]; fabs; _ftol2` → `if |vec[barIdx]| < THR → skip`
  - `recIdx+1 < B`
  - `fild value@+0x00` → `out[ *(int*)(A + (recIdx+1)*0x20) ] = (double)value`
    - A=`obj8[+0x1c]` = **Rec20 数组基址，stride 0x20**；取 `Rec20[recIdx+1].startBar@+0x00` 作目标下标
- 收尾：析构 vec、return 0

### T1↔T2 关系
- **共享同一组容器**：都读 obj10（Item21@+0x30 / 条数@+0x3c）；T2 额外读 obj8（Rec20@+0x1c / 条数@+0x28）
- **门相同**：两者都用 `Authorize(0xEA61)`
- **T2 内嵌 T1 的输出**：T2 先调 vt[+0x5c]=NChBiZjNum 把 ZjNum 结果灌进本地 vec，再用它做阈值过滤 → **ZjOrder 是 ZjNum 的"下游消费 + 按记录序列重排"**
- **差异段**：Zj 只做 `out[item.barIdx] = value`（bit2 门）；ZjOrder 做 `out[Rec20[recIdx+1].startBar] = value`（bit0 门 + 非 bit3 + |ZjNum|阈值 + recIdx 边界）→ "Order" = **按记录序（下一段起始 bar）重排**，证据 0x100032d7–0x100032e7（[A]）

### 勘误（本批自查）
- 初版把 `mov esi,[esp+0x2c]`（call 前 esp=S-0x48）误算成 A 槽；实为 **S-0x1c = &vec 的首 dword = vec.begin**。修正依据：`call 0x10006c00` 的 `ret 4` 会同时弹返回址+参数，`sub esp` 链回到 S-0x44；由此 line40/41/42/25/35 与循环内 `[esp+X]` 全部自洽（[A]）

### WIP-END T2

## T3 — Out 向量静态深挖：Item21 写入者确权（重大进展）

### 关键发现：消费 vs 生产
- **NChBi(0x10002340) 不写 Item21**，它只**读** obj10[+0x30] 再散射到 out[]（本批全部复核）
- Item21 的真正生产者 = **`obj10->vt[+8]()`**
  - obj10 虚表 = `0x10015438`：`+0x00→0x100098d0` / `+0x04→0x100099e0` / **`+0x08→0x10009a20`** / `+0x0c→0x1000e0b0`(5参setter) / `+0x10→0x100158b8` / `+0x14→0x1000bed0` …
  - `0x10009a20` = 按 `obj10[+0x1c]`(**类型码**) 分派：`0 → 0x10009a50`；`1..6 → jmp 0x10009dd0`；其它 → -1
  - `0x10009930` = 类型码 setter：`obj10[+0x1c] = f(P)`（P-0xb 查 0x10009988 跳表，值∈{2,1,4,3,6,5,0}，与 docs/26 P 编码一致）

### Item21 填充体（P=51 / code 0）：`0x10009a50`（274 insn，ebx=obj10 寄存器约定）
- 前置门：`obj10[+0x24]`(=obj8[+0x28]=Rec20 条数)、`obj10[+0x20]`(=obj8[+0x1c]=Rec20 基址)、`obj10[+0x2c]`(=obj_c[+0x34]=源条数)、`obj10[+0x28]`(=obj_c[+0x28]=源基址) 均非 0
  - ★ obj10 的 [+0x20..0x2c] 由 **NChBi(0x10002340) 第 68–79 行**从 obj8/obj_c 拷入（见上）
- `call 0x1000b9b0(obj10, count)` → 分配 obj10[+0x30] 数组；`obj10[+0x3c]=0`
- 源记录 **stride 0x1D（29B）**：`+0x00` int value / `+0x04` u8 flag / `+0x05` int rec / `+0x09` int bar / `+0x0d` double / `+0x15` double
- 目的 Item21 **stride 0x21（33B）**，用 `rep movsd ×8 + movsb`=33B 整体拷入：
  | Item21 | 来源 | 语义 |
  |---|---|---|
  | +0x00 | raw[+0x00] | **value（int）** |
  | +0x04 | 计算 flags | 见下 |
  | +0x05 | 1-based 源序号(ordinal) | 序号 |
  | +0x09 | raw[+0x05] | **recIdx** |
  | +0x0d | raw[+0x0d] | double（备用） |
  | +0x15 | raw[+0x15] | double（备用） |
  | +0x1d | raw[+0x09] | **barIdx（out 目标下标）** |
- **flags 位语义（[A]，0x10009ae2–0x10009b45 等）**：
  - `bit0(0x01)` 恒置位（首件 flags=1）
  - `bit5(0x20)` ← `raw[i][+0x04] & 1`
  - `bit4(0x10)` ← `(raw[i-1][+0x05]+1 == raw[i][+0x05]) && (raw[i-1][+0x04] & 1)`
  - `bit3(0x08)` ← `raw[i][+0x04] & 2`  （→ 消费者做 **×2**）
  - **本路径(code 0)不产生 bit2(4)** ⇒ NChBiZj 的 bit2 门属于 **code 1..6 路径(0x10009dd0)**（待补证）

### 升级的判定表（部分）
- **NChBi 主(out) 判定**（0x10002340）：
  - `flags bit0` 置位 → `out[barIdx] = value`；若同时 `bit3` → `out[barIdx] *= 2.0`（`fld 2.0@0x100154b8; fmul`）[A]
  - 之后按首件 value 符号：`>=0` → 在 out[0..N) 求**最小**（种子 +DBL_MAX@0x100154c0）；`<0` → 求**最大**（种子 -DBL_MAX@0x100154c8）[A]
  - 末：`out[bestIdx] = -2 * firstValue`（`neg eax; add eax,eax` → -2×）[A]
- **NChBiZj**：`flags bit2` + `out[barIdx] = value`（无缩放）[A]
- **NChBiZjNum**：`flags bit0` → `out[barIdx] = cnt`（cnt=自上个 bit0 项以来、且 value 变化的 bit2 项计数；命中后 cnt=0、并记住 ecx=该件 value 供 `cmp` 用）[A]
- **NChBiZjOrder**：过滤(bit0 & 非 bit3 & recIdx 界 & |ZjNum[barIdx]|>=THR) → `out[Rec20[recIdx+1].startBar] = value`[A]

### 对 docs/26 §7.2 待仲裁的推进
- **#1 value 是否恒 ±1**：**未证实但已定位源头** —— value = 原始 29B 记录 `raw[+0x00]`，非本层合成；raw 数组来自 **obj_c[+0x28]（条数 obj_c[+0x34]）**，写入者应为 obj_c vt[+8]=`0x1000e1c0`（待反汇编）⇒ 置信 **[B]**（±3 = 3×value，故 value 若 ±1 则 ±3 确为该值×3 的唯一产物）
- **#3 ±2 / ±10 语义**：**×2 = flags bit3**（NChBi 0x100024a6 与 NChBiSta 段B 双证，[A]）；**×10 = NChBiSta 段A 独立缩放**（docs/26 段A）；**×3 = NChBiSta 段C**。三者 = 同一 base value 在不同槽位的强度缩放 ⇒ 非独立值域 [A/B]

### WIP-END T3-A

## T3-B — 完整数据流闭环（Item21 全字段来源确权）

### 第三层：obj_c = 26 字节原始记录生产者（`obj_c.vt[+8] = 0x1000e1c0`）
- 输入：`obj_c[+0x20]` = **bar 数组**（stride 0x20=32B，含 [bar-8]/[bar]/[bar+0x10]/[bar+0x14]/[bar+0x18]/[bar+0x20]/[bar+0x38]/[bar+0x40] 用于分型几何判定）；`obj_c[+0x24]` = bar 条数
- 输出：`obj_c[+0x28]` = **raw 记录数组**（stride **0x1D**）；计数 `obj_c[+0x34]`（`call 0x10006b60(obj_c[+0x28], n)` 预分配）
- 每条 raw 由本地 29B 缓冲 `[esp+0x20]` 经 `rep movsd×7 + movsb` 整体写回：
  | raw | 写点 | 取值 |
  |---|---|---|
  | +0x00 value | 0x1000e280/0x1000e307/0x1000e3e2 … | **`∈ {0, +1, -1}`**（0x1000e420 初值 0；命中顶/底→1 或 -1） |
  | +0x04 flag | 0x1000e2a0(→1)/0x1000e3fb(`or ...,2`) | bit0 / bit1 |
  | +0x05 rec | 0x1000e33c ([esp+0x25]=edi) | 源 bar 序号 |
  | +0x09 bar | 0x1000e289/0x1000e3e5 ([esp+0x29]=bar[+0x10 or +0x14]) | 对应 bar 号 |
  | +0x0d dbl | [esp+0x2d] | 几何量 |
  | +0x15 dbl | [esp+0x35] | 几何量 |
- x87：8 条 `fcom/fcomp + test ah,5 jp`（≥侧）/`test ah,0x41 jne`（≤侧）分型几何比较（0x1000e24c–0x1000e3e0）

### ★★ 结论：docs/26 §7.2 待仲裁 #1 —— **Item21.value ≡ ±1（或 0）得证 [A]**
- 证据链：`raw[+0x00] ∈ {0,+1,-1}`（0x1000e1c0 写点，[A]）→ Item21[+0x00] = raw[+0x00]（0x10009a50，[A]）→ 消费者仅做整数倍缩放
- ⇒ **±3 = 3×value 唯一产物**（NChBiSta 段C）、**±2 = 2×value**（flags bit3）、**±10 = 10×value**（NChBiSta 段A）——三者皆为同一 ±1 基值在不同槽位的强度缩放，**非独立值域** [A]
- code1-6 路径另有显式合成：`cmp [edi],1; setne al; lea eax,[eax+eax-1]` → **值 ∈ {+1,-1}**（0x10009ef5–0x10009f01）[A]

### ★★ bit2(4) 的确切语义 —— NChBiZj 的门得证 [A]
- 全 .text 扫描「向字节字段或 bit2 的指令」仅 6 处，与本族相关的唯一一处：
  **`0x1000b0bb  or byte ptr [edi+4], 4`**（在 `0x1000b000` 内）
- `0x1000b000(Item21_i)`（eax=obj10/esi，栈参 i；`ret 4`；返回 bool）逻辑：
  1. `i<2` → false；`Item21[i].flags & 1` → false（只对 bit0=0 的项）
  2. `j = 0x1000a250(obj10, i)`（**配对查找**，返回 index 或 <0）
  3. `j<0` → true（无配对）
  4. `Item21[j].value != Item21[i].value` → false
  5. `value==1`：要求 `g(barIdx[j]) > g(barIdx[i])`（0x1000a060）；否则要求 `g(barIdx[j]) < g(barIdx[i])`（0x1000a080）
  6. `0x1000abb0(...)` 复核通过 → **`Item21[j].flags |= 4`** → true
- ⇒ **flags bit2 = "该项已被 0x1000b000 配对确认为 Zj 点"**，写在后件 j（前件 i 未置位）
- ⇒ **NChBiZj 的门就是 bit2**：只输出"经配对确认"的 Zj 项 → T1 的输出码判定链闭合成 [A]
- 调用者：code1-6 填充路径 `0x10009ff5` → `call 0x1000b000`；另有 `0x1000b100(obj10,i)`（0x10009fff6）

### 完整数据流图
```
bar 数组(obj_c[+0x20])  ──0x1000e1c0──▶ raw 记录(obj_c[+0x28], stride 0x1D, value∈{0,±1})
   （分型几何判定, x87 8 条件）
        │  NChBi(0x10002340) 拷 obj_c[+0x28]/[+0x34] → obj10[+0x28]/[+0x2c]
        ▼
obj10[+0x28]/[+0x2c]  ──obj10.vt[+8](0x10009a20 按类型码分派)──▶ Item21 数组(obj10[+0x30], stride 0x21)
   ├ code0(P=51):  0x10009a50  flags∈{1,0x21,0x11}|8
   └ code1..6:     0x10009dd0  flags∈{0,0x10,0x20}|8；且对 bit0 项生成配对件(value=±1, flags=0x20)
        │              └ 0x1000b000 置 bit2（Zj 配对确认）
        ▼
Item21  ──消费者──▶ out[] (double[count])
   ├ NChBi(0x10002340): bit0→out[barIdx]=value；bit3→×2；再 argmax/argmin(ref 首件符号)→out[best]=-2×首值
   ├ NChBiSta(0x10002770): ×10 段A / ×1 或 ×2(bit3) 段B / ×3 段C / 尾广播
   ├ NChBiZj(0x10002ea0): bit2→out[barIdx]=value
   ├ NChBiZjNum(0x100038b0): bit0→out[barIdx]=cnt（间隔计数）
   └ NChBiZjOrder(0x10003180): (bit0 & !bit3 & recIdx界 & |ZjNum[barIdx]|>=THR)→out[Rec20[recIdx+1].startBar]=value
   授权码：NChBi/…=0xEA62；NChBiSta/Zj/ZjOrder=0xEA61；ZjNum=0xEA62
```

### WIP-END T3-B
