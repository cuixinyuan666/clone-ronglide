# NChBi 第一批 WIP（入口链 + P 分派 + 复用判定）

> 证据目录：`tools/re-inventory/nchbi/`。写入时间：2026-10-17。模型：deepseek-v4.1-flash。
> 铁律：栈槽 +4 修正 / x87 链用工具验证 / InvalidByte 续扫 / 疑点留 [A]/[B]/[C]。

## 1. NChBi 入口链 [A]

### 1.1 导出与包装层签名

`NChBi` @ **0x10012a50**（TAFLib.dll）。`ret 0xc` + `mov esi, ecx` ⇒ **`__thiscall`，3 个栈参数**。
含 SEH 帧（`push -1; push 0x1006ce93` handler；SEH 记录在 `[esp+0x40]`）。

栈帧（`and esp,-8` 后）：cookie@`[esp+0x00]`，edi@+4，esi@+8，ebx@+0xc，0x30 字节局部@+0x10..0x3f，
SEH 记录@+0x40，SEH state@+0x48/+0x4c。

签名（推定）：
```c
bool __thiscall NChBi(this /*ecx*/, int count /*[ebp+8]*/,
                      void* out /*[ebp+0xc]*/, ParamStruct* p /*[ebp+0x10]*/);
```

### 1.2 P 取值与授权门 [A]

```
10012a82  eax = [ebp+0x10]          ; p
10012a85  ecx = [eax]               ; ★ NChBi 的 P 指针在 p+0x00
10012a87  fld qword [ecx]           ; ST0 = *P
10012a89  call 0x1006bc70           ; P 转码器 → eax/edi = 整数模式
10012a90  test edi,edi ; je  auth   ; edi==0  → 需要授权
10012a94  cmp edi,0x33 ; jne skip   ; edi!=51 → 免授权直通
                                     ; edi==51 → 需要授权
10012a99  push 0xea62; call 0x10014e60   ; Authorize(this, 0xEA62)
10012aa5  test al,al ; jne 0x10012ad9    ; 已授权 → 建对象
10012aa9  memset(out, 0, count*8) ; return false   ; ★ 未授权 = 输出清零 + 返回 0
```
**对照 CHBI**（`0x1000f580`）：CHBI 读 `p+0x08` 且门控只需 **P==51**；
NChBi 读 `p+0x00` 且门控为 **P∈{0, 51}**。⇒ **P 结构体字段偏移与门控条件都不同** [A]。

### 1.3 对象构造段（与 CHBI 逐句同构）[A]

```
10012ad9  operator new(0x30)                      ; 0x1006b32c
10012af3  ctor 0x10001cc0(newptr)                 ; ★ 与 CHBI 同一个 ctor
10012b0e  [obj+0x08] = 1
10012b15  [obj+0x0c] = 0
10012b1c  push [this+0xc]+4 ; lea ecx,[obj+0x14] ; call [0x1006f07c]
10012b33  byte [obj+0x10] = 1
10012b37  call 0x1001c110                         ; ★ 与 CHBI 同一个 shared_ptr 桩
10012b45  call [0x1006f220]
10012b5a  lock xadd 引用计数递减 ×2 + 虚拟析构
```
IAT 解析（本批新增）：
| IAT 槽 | 目标 |
| --- | --- |
| 0x1006f07c | `MSVCP80!std::string::operator=(const std::string&)` |
| 0x1006f220 | `RDM_C!DmcApi::PushEvent(boost::shared_ptr<rld::evt::evtbase> const&)` |
| 0x1006f328 | **`chlib!ch::ch_api::CreateLib(ch::ch_auth*)`** |
| 0x1006f194 | `MSVCR80!_invalid_parameter_noinfo` |

⇒ 0x30 字节对象 = **图表事件对象**（`+0x14` 持 std::string（来自 `this+0xc+4`），`+0x10` 标志，
shared_ptr 指向事件基类），最终 `DmcApi::PushEvent` 推送。与算法无关，只做"事件通知" [A]。

### 1.4 真工作函数 = 虚调用，不在 TAFLib [A]

```
10012c06  eax = [ebp+0x10]                 ; p
10012c09  ecx = [esi+0xbc]                 ; ★ this->[+0xbc] = ch::ch_api*
10012c0f  edx = [ecx]                      ; vtable
10012c11  edx = [edx+0x34]                 ; ★ 槽 +0x34
10012c14  push eax(p) ; push &local ; push out ; push count
10012c22  call edx                          ; ch_api->vt[+0x34](count, out, &local, p)
```
对照 CHBI 尾部：CHBI 是 **直接调用** `0x1002c1d0([this+0xb0], count, out, p, tempObj)`（5 参）。
⇒ **NChBi 与 CHBI 不共享工作函数**：CHBI 走 TAFLib 内部实现；NChBi 走 **chlib.dll 的 ch_api 虚接口** [A]。

### 1.5 `this+0xbc` 的来历 [A]

TAFLib ctor（0x10001eee..0x10001f86 区）：
```
10001f5a  push 0x10083c58
10001f64  call [0x1006f328]     ; ch::ch_api::CreateLib((ch::ch_auth*)0x10083c58)
10001f6a  mov [esi+0xbc], eax   ; this->[+0xbc] = ch_api*
```
`0x10083c58` 是 TAFLib 自带的 `ch_auth` 派生实例（静态/单例，在 .data）。读取点覆盖
0x100127b0–0x100136xx 整个 NChB* 家族（每函数 1 次 `mov ecx,[esi+0xbc]`）⇒ **家族共用同一 ch_api 句柄** [A]。

## 2. ch::ch_api 虚表族 → chlib 实现地址映射 [A]

`chlib!CreateLib` (0x10001010) → `ch_api::ch_api(auth)` (0x100010d0) → `[esi] = 0x10015214`（ch_api 虚表）。
另一虚表 0x10015134（`[ecx]=0x10015134`，0x100010a0/b0）是**基类/被包容类**（槽 0 之后全是 `0x10013f56` 占位）。

| TAFLib 导出 | 地址 | 授权码 | 门控 | ch_api 槽 | **chlib 实现** |
| --- | --- | --- | --- | --- | --- |
| NChBi | 0x10012a50 | EA62 | P∈{0,51} | +0x34 | **0x10002340** |
| NChBiSta | 0x10012c40 | EA61 | 恒 | +0x38 | 0x10002770 |
| NChBiSta2 | 0x10012cb0 | EA61 | 恒 | +0x3c | 0x10002900 |
| （未见于导出表） | — | — | — | +0x40 | 0x10002d80 |
| NChBiZj | 0x10012d20 | EA61 | 恒 | +0x44 | 0x10002ea0 |
| （未见于导出表） | — | — | — | +0x48 | 0x10002fc0 |
| NChBiZjOrder | 0x10012e00 | EA62 | 恒 | +0x4c | 0x10003180 |
| （未见于导出表） | — | — | — | +0x50 | 0x10003330 |
| （未见于导出表） | — | — | — | +0x54 | 0x10003450 |
| NChBiFxNum | 0x10012e70 | EA62 | 恒 | +0x58 | 0x10003680 |
| （未见于导出表） | — | — | — | +0x5c | 0x100038b0 |
| NChBiSpeed | 0x10012f50 | EA62 | 恒 | +0x60 | 0x10003a90 |
| （未见于导出表） | — | — | — | +0x64 | 0x10003cd0 |

- `chlib` 只导出 `CreateLib`/`FreeLib`；`TAFLib` 也只导入这两个 ⇒ **算法全在 chlib 内实现，TAFLib 仅做绑定** [A]。
- `NChBhl`(0x100127b0)/`NChRef`(0x10012820) 也读 `[esi+0xbc]`，槽位待补（应在 +0x28..+0x30 段）。

## 3. 待续
- [ ] chlib 0x10002340 反汇编 + P 分派解析
- [ ] 复用判定（0x1003eba0 / 0x10053540 / 0x1003ef00 / 0x1001c110）
- [ ] 输出向量初探（NCHBISTA=-3 底分型）

---

## 4. P 分派表 [A]

### 4.1 `0x1006bc70` 不是转码器 = `_ftol2`

反汇编 `0x1006bc70` 得 `cvttsd2si` / `fistp qword` / `fild qword` / `0x7fffffff` / `0x80000000` 组合
⇒ 它是 MSVC 的 **`_ftol2`（double→int 转换助手）**，不是"P 转码器"。
⇒ `edi = (int)P`（`float64 P` 截断取整）。

### 4.2 包装层 P 行为表（`0x10012b92`–`0x10012c06` 的 cmp/switch 链）[A]

| `(int)P` | 授权门 | 行为 | 常量来源 |
| --- | --- | --- | --- |
| 0 | **EA62 必检** | 落进 chlib 工作函数（真正的计算入口） | — |
| 11 | 免检 | `*p = 2.0`，**不调用工作函数** | `[0x1006fb48]` = 2.0 |
| 12 | 免检 | `*p = 1.0` | `fld1` |
| 21 | 免检 | `*p = 4.0` | `[0x1006fcd8]` = 4.0 |
| 22 | 免检 | `*p = 3.0` | `[0x1006fc90]` = 3.0 |
| 31 | 免检 | `*p = 6.0` | `[0x1006fcd0]` = 6.0 |
| 32 | 免检 | `*p = 5.0` | `[0x1006fcc0]` = 5.0 |
| 51 | **EA62 必检** | `*p = 0.0`，**不调用工作函数** | `fldz` |
| 其它 | 免检 | 落进 chlib 工作函数 | — |

**编码规律** [A]：`P = 10a + b`（`a = P//10 ∈ {1,2,3}` 级别、`b = P%10 ∈ {1,2}` 顶/底），
返回值 = `2(a-1) + (3-b)` ⇒ 11→2, 12→1, 21→4, 22→3, 31→6, 32→5。
顺序 (12,11,22,21,32,31) ↦ (1,2,3,4,5,6) = 类型码枚举。

**语义读数** [B]：`P ∈ {11,12,21,22,31,32}` = **类型探测查询**（框架问"NCHBI 里 P=xx 属于哪一类"，返回枚举码，
免费）；`P = 0` = **真正计算入口（默认/自动模式，付费 EA62）**；`P = 51` = 分型笔模式（付费，返回 0.0）。
⇒ 与 CHBI 的差异：CHBI 的 P 语义全在**工作函数内部**分派（docs/20 §3），包装层无常量表；
NChBi 的 P 语义在**包装层**短路。两者 **P 编码约定相同（11/12/21/22/31/32/51），但付费触发点不同**（CHBI=51；NChBi=0 与 51）[A]。

## 5. chlib 工作函数 0x10002340 结构 [A]

签名（`ret 0x10` + `mov esi,ecx` ⇒ `__thiscall`，4 栈参）：
```c
int __thiscall ch_api::vt34(this /*=ch_api*/, int count, double* out, Ctx6* ctx, double** p);
//   count = [ebp+8], out = [ebp+0xc], ctx = [ebp+0x10], p = [ebp+0x14]
```
- `ctx` = TAFLib 前置 `0x10006cc0` 填的 **6 行情缓冲指针** [A]：
  `+0x00 HighBuffer`、`+0x04 OpenBuffer`、`+0x08 LowBuffer`、`+0x0c CloseBuffer`、
  `+0x10 VolumeBuffer`、`+0x14 AmountBuffer`
  （全部来自 `RData.dll!XTAData::Get*Buffer()`；IAT 0x1006f254/258/250/240/280/2dc）
- 函数体：
  1. `memset(out, 0, count*8)`；
  2. 早退：`if (ctx[+0]==0) return -1`；`if (ctx[+8]==0) return -1`；
  3. `ebx = 0x100148a0(P)`（chlib 侧 P 判定）；`if (ebx==0)` → **第二道授权门**
     `this->[+4]`(=ch_auth*)`->vt[+4](0xEA62)`；不通过 → `return -1`；
  4. `0x10006670(count)` 早退检查；
  5. 通过 `this->[+0x10]` 子对象的 `vt[+4]` / `vt[+0xc]` 做数据准备，再调用 `0x10009930`；
  6. **两个 argmax/argmin 循环**（见 5.1）。
- **0x10002340 内部不比较 P**：无 `cmp P, 11/12/...` ⇒ P 只用于授权判定，不选算法分支 [A]。

### 5.1 分型判定内核 [A]
常量 `0x100154c8 = -DBL_MAX`、`0x100154c0 = +DBL_MAX`。

| 分支 | 种子 | 比较 | test | 跳转成立 | 语义 |
| --- | --- | --- | --- | --- | --- |
| `0x10002606` | `fld [0x100154c8]` (-DBL_MAX) | `fcom [ecx-0x10] [-8] [0] [+8]` 与 `[esi+edx*8]` | `ah,5 jp` | `>|=|U` | **H 数组 argmax**（求最高点索引 → `edi`） |
| `0x100026a4` | `fld [0x100154c0]` (+DBL_MAX) | 同上（用 `ctx[+8]`=LowBuffer） | `ah,0x41 jne` | `<|=|U` | **L 数组 argmin**（求最低点索引 → `edi`） |

- 窗口推进：`ecx += 0x20`（4 个 double 展开）、尾段 `add edx,1`；计数 `[esp+0xc]`。
- 出口 `test edi,edi; jl 0x10002757` ⇒ 索引 < 0 → 无分型。
⇒ **NChBi = 在 H/L 缓冲上定位极值点（顶/底分型候选）**，与 NCHBISTA=-3(底分型) 语义吻合 [B]。
- 条件表证据：`tools/re-inventory/nchbi/cond_chlib_10002340.txt`（10 条，92 块，conflicts=17 因 `fnstsw ax` 后
  `fstp/fld` 交替导致 ST 追踪退化，但 10 条关系的真值已由 `ah,5`/`ah,0x41` 表直接给出）。

## 6. 复用判定 [A]

| 目标 | 是否复用 | 调用点/依据 |
| --- | --- | --- |
| `0x1001c110`（boost::shared_ptr 构造桩） | **复用** | NChBi 包装层 `0x10012b37`；CHBI 包装层 `0x1000f692`；内部调 `0x1001c940`（shared_count ctor） |
| `0x1003eba0`（CHBI/CHDUAN 共用 m[2] 拆表） | **不复用** | NChBi 包装层调用表（下表）无此目标；chlib 只依赖 MSVCRT/KERNEL32，不可能回调 TAFLib |
| `0x10053540`（CHDUAN prep） | **不复用** | 同上 |
| `0x1003ef00`（方向标注） | **不复用** | 同上 |
| `0x1002c1d0`（CHBI 真工作函数） | **不复用** | NChBi 走 chlib `ch_api::vt[+0x34] = 0x10002340`，与 CHBI 的直接调用路径不同 |

NChBi 包装层完整调用表（`0x10012a50`–`0x10012c38`）：
`0x1006bc70`(_ftol2) / `0x10014e60`(Authorize) / `0x1006bd22`(memset) / `0x1006b32c`(operator new) /
`0x10001cc0`(事件对象 ctor) / `[0x1006f07c]`(std::string::operator=) / **`0x1001c110`**(shared_ptr 桩) /
`[0x1006f220]`(DmcApi::PushEvent) / `0x10006cc0`(取 6 行情缓冲) / **chlib `ch_api::vt[+0x34]`**。
⇒ 无 `0x1003eba0` / `0x10053540` / `0x1003ef00` / `0x1002c1d0`。

## 7. 输出向量初探 [B]

- 工作函数输出 = `out[]`（`count` 个 double，线性数组，`memset 0` 起）——即"每 bar 一个值"的指标数组。
- `NCHBISTA`（用户公式 `SELECT(VAR2=-3)`）走**另一个槽** `+0x38 = chlib 0x10002770`，返回**状态码**而非价格；
  用户文档给 -3 = **底分型**（+3 应为顶分型，0 为无）——本批仅作方向性结论，第二批深挖。
- 包装层 `*p`（P 槽）除输入外还被**写回**常量（P∈{11,12,21,22,31,32,51} 时）⇒ P 参数是双向的。
- 事件对象（0x30B）只是 `DmcApi::PushEvent` 的通知载体，不参与算法输出。

## 8. 待续（第二批）
- [ ] chlib `0x10002770`（NChBiSta）逐条解剖 → 输出码 -3/+3/0 的判定条件
- [ ] chlib `0x10006670` / `0x10009930` / `0x100148a0` / `this->[+0x10]` 子对象 vt[+4]/vt[+0xc] 语义
- [ ] chlib 数据流：`ctx`(H/O/L/C/V/A) → 内部容器 → out[]
- [ ] 输出向量与 NCHBISTA/NCHBIZJ 组合（顶/底/笔/段）交互

---

## 9. 补正：chlib 侧 `0x100148a0` 也是 `_ftol2` [A]

`chlib!0x100148a0` 反汇编与 TAFLib `0x1006bc70` **逐句同形**（`cmp [0x10017508],0` guard →
`cvttsd2si` 快路径 → `fistp/fild` + `0x7fffffff/0x80000000` 慢路径）⇒ 同为 **`_ftol2`**（chlib 自带的静态副本）。
故 chlib 工作函数里 `ebx = (int)P`，`test ebx,ebx; jne skip` ⇒ **`(int)P == 0` 时才做第二道授权检查**
（`ch_auth->vt[+4](0xEA62)`），且 `cmp [this+4], 0; je return -1` 先挡空 auth 指针。

⇒ **两层门一致**：真正的计算入口 `P == 0` 在 TAFLib 包装层与 chlib 工作函数内**各检查一次** [A]。
⇒ P ∈ {11,12,21,22,31,32,51} 在包装层就被短路，**永不进入 chlib** [A]。
