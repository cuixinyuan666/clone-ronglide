# docs/25 — NChBi 第一批：入口链与 P 分派

> 批次：NChBi 第一批（付费函数覆盖表 缠论基础组 EA62，`无脑买入` 家族下一支）
> 日期：2026-10-17　模型：deepseek-v4.1-flash
> 证据目录：`tools/re-inventory/nchbi/`　伪码：`pseudocode/nchbi.c`
> 背景：CHBI 五批 + CHDUAN 四批已闭环（docs/18/20/21/22/23/24）。本批按 docs/24 §十二推荐启动 NChBi。

---

## 一、背景与结论摘要

| 项 | 结论 | 置信 |
| --- | --- | --- |
| `NChBi` 导出地址 | TAFLib.dll `0x10012a50`，`__thiscall`，`ret 0xc`（3 栈参） | [A] |
| 授权码 | `Authorize(this, 0xEA62)` @ `0x10012aa0`；未授权 → `memset(out,0,count*8)` + 返回 0 | [A] |
| 授权门控 | `(int)P == 0` **或** `== 51`（CHBI 只有 `==51`） | [A] |
| **真工作函数** | **不在 TAFLib**，而在 **chlib.dll** `ch::ch_api` 虚表槽 **+0x34 = `0x10002340`** | [A] |
| `this+0xbc` | `ch::ch_api*`（由 `chlib!CreateLib(ch_auth*)` 于 TAFLib ctor `0x10001f64` 建立） | [A] |
| P 分派 | 包装层 `switch(P)`：`{11,12,21,22,31,32,51}` 返回常量、**不进工作函数** | [A] |
| 与 CHBI 是否共享工作函数 | **否**（CHBI 直接调 TAFLib `0x1002c1d0`；NChBi 走 chlib 虚接口） | [A] |
| 与 CHBI 共享的部分 | 仅 `0x1001c110`（boost::shared_ptr 构造桩）与事件推送段 | [A] |

**一句话**：NChBi 与 ChBi 是**两套独立实现**——ChBi 用 TAFLib 内置缠论引擎（`0x1002c1d0` 族），
NChBi 用**独立模块 chlib.dll 的 `ch::ch_api` 虚接口**（`0x10002340`）。二者只在 P 编码约定与包装层骨架上同构。

---

## 二、入口链

### 2.1 包装层签名与栈帧 [A]

```
0x10012a50  push ebp / mov ebp,esp / and esp,-8      ; 8 字节对齐
            push -1 / push 0x1006ce93 / push fs:[0]  ; SEH 帧 (handler 0x1006ce93)
            sub esp,0x30 / push ebx,esi,edi / push cookie(eax=[0x1007c018]^esp)
            mov esi,ecx                              ; __thiscall → this
```
- 局部：`[esp+0x14]`=this、`[esp+0x18]`=new 对象、`[esp+0x1c]`=shared_ptr 临时、`[esp+0x24]`=控制块；
  SEH 记录 `[esp+0x40]`、SEH state `[esp+0x48]/[esp+0x4c]`。
- 参数：`[ebp+8]`=count、`[ebp+0xc]`=out、`[ebp+0x10]`=p（`double**`）。

```c
bool __thiscall NChBi(this, int count, double* out, double** p);
```

### 2.2 控制流骨架 [A]

```
①  P 判定    fld **p → _ftol2(0x1006bc70) → edi = (int)P
              if (edi==0 || edi==51) { if (!Authorize(0xEA62)) { memset(out,0,count*8); return 0; } }
②  事件对象  new(0x30) → ctor 0x10001cc0 → [obj+8]=1,[obj+0xc]=0,[obj+0x10]=1,
              [obj+0x14] ← std::string::operator=([this+0xc]+4)；
              shared_ptr(0x1001c110) → DmcApi::PushEvent([0x1006f220]) → 引用计数递减
③  取行情    call 0x10006cc0(this, &ctx6)   ; 填 6 个缓冲指针
④  P 短路    switch (edi): 11→*p=2.0, 12→1.0, 21→4.0, 22→3.0, 31→6.0, 32→5.0, 51→0.0  ← 直接返回
⑤  真计算    [this+0xbc] (=ch_api*) → vtable[+0x34](count, out, &ctx6, p)
⑥  return 1
```

对照 CHBI（docs/18 §1）：CHBI 的骨架**缺 ③④**，且 ⑤ 是**直接调用** `0x1002c1d0([this+0xb0], count, out, p, tempObj)`。

---

## 三、P 分派表

### 3.1 `0x1006bc70` = `_ftol2`（勘误：不是"P 转码器"）[A]

`cmp [0x10084160],0` 守卫 → `cvttsd2si` 快路径 → `fistp qword`/`fild qword` + `0x7fffffff`/`0x80000000` 慢路径
⇒ MSVC **`_ftol2`**。因此 `edi = (int)P`（截断取整），后续所有比较都是**整数比较**。

> 勘误：本仓库此前（docs/18/20 语境）把该地址描述为"P 转码器"。实际是编译器的 double→int 助手。

### 3.2 包装层 `switch` 表（`0x10012b92`–`0x10012c06`）[A]

| `(int)P` | 授权 | 返回常量 | 常量地址 | 是否调用工作函数 |
| --- | --- | --- | --- | --- |
| **0** | **EA62** | — | — | **是（真计算入口）** |
| 11 | 免 | **2.0** | `[0x1006fb48]` | 否 |
| 12 | 免 | **1.0** | `fld1` | 否 |
| 21 | 免 | **4.0** | `[0x1006fcd8]` | 否 |
| 22 | 免 | **3.0** | `[0x1006fc90]` | 否 |
| 31 | 免 | **6.0** | `[0x1006fcd0]` | 否 |
| 32 | 免 | **5.0** | `[0x1006fcc0]` | 否 |
| **51** | **EA62** | **0.0** | `fldz` | 否 |
| 其它 | 免 | — | — | 是 |

**编码规律** [A]：`P = 10a + b`（`a = P//10 ∈ {1,2,3}` 级别；`b = P%10 ∈ {1,2}` 顶/底），
常量 = `2(a-1) + (3-b)`。即 `(12,11,22,21,32,31) ↦ (1,2,3,4,5,6)`。

**语义读数** [B]：`P ∈ {11,12,21,22,31,32}` 是**类型探测查询**（框架询问"P 属于哪一类"，返回枚举码 1..6，免费）；
`P = 0` 是**真正的计算入口**（默认/自动模式，付费）。这解释了用户公式 `VAR1:=NCHBI(P); VAR2:=NCHBISTA;` 中
`NCHBISTA` 无参（等价 P=0）却需要付费授权。

> 与 CHBI 的差异 [A]：CHBI 的 P 语义全部在**工作函数 `0x1002c1d0` 内部**分派（docs/20 §3：
> `{11,12}→0x1003f170`、`{21,22}→0x1004b1e0`、`{31,32}→0x1004f430`、`51→0x1006a040`），包装层无常量表；
> NChBi 的 P 语义在**包装层**短路。两者 **P 编码约定相同**，但**付费触发点不同**（CHBI=51；NChBi=0 与 51）。

---

## 四、真工作函数：chlib.dll `ch::ch_api::vt[+0x34] = 0x10002340`

### 4.1 定位过程 [A]

1. NChBi 尾部 `0x10012c09` 读 `ecx = [this+0xbc]`，`0x10012c11` 取 `[vtable+0x34]`，虚调用。
2. TAFLib 导入表：`0x1006f328 = chlib!ch::ch_api::CreateLib(ch::ch_auth*)`。
3. TAFLib ctor 段 `0x10001f5a`：`push <ch_auth*>; call [0x1006f328]; mov [esi+0xbc], eax`。
4. `chlib!CreateLib(0x10001010)` → `ch_api::ch_api(ch_auth*)(0x100010d0)` → 首句 `mov [esi], 0x10015214` = **ch_api 虚表**。
5. 虚表 `+0x34 = 0x10002340`。

### 4.2 ch_api 虚表槽 ↔ TAFLib NChB* 家族映射 [A]

| TAFLib 导出 | 地址 | 授权码 | 门控 | 槽 | chlib 实现 |
| --- | --- | --- | --- | --- | --- |
| **NChBi** | `0x10012a50` | EA62 | P∈{0,51} | **+0x34** | **`0x10002340`** |
| NChBiSta | `0x10012c40` | EA61 | 恒 | +0x38 | `0x10002770` |
| NChBiSta2 | `0x10012cb0` | EA61 | 恒 | +0x3c | `0x10002900` |
| （未在该批导出清单） | — | — | — | +0x40 | `0x10002d80` |
| NChBiZj | `0x10012d20` | EA61 | 恒 | +0x44 | `0x10002ea0` |
| （未在该批导出清单） | — | — | — | +0x48 | `0x10002fc0` |
| NChBiZjOrder | `0x10012e00` | EA62 | 恒 | +0x4c | `0x10003180` |
| （未在该批导出清单） | — | — | — | +0x50 / +0x54 | `0x10003330` / `0x10003450` |
| NChBiFxNum | `0x10012e70` | EA62 | 恒 | +0x58 | `0x10003680` |
| （未在该批导出清单） | — | — | — | +0x5c | `0x100038b0` |
| NChBiSpeed | `0x10012f50` | EA62 | 恒 | +0x60 | `0x10003a90` |
| （未在该批导出清单） | — | — | — | +0x64 | `0x10003cd0` |

- `NChBhl`(`0x100127b0`)/`NChRef`(`0x10012820`) 亦读 `[esi+0xbc]`（槽 +0x1c / +0x20）。
- TAFLib 侧全家族槽位实际覆盖 **+0x18 … +0xc4**（扫描 `0x10012700`–`0x10014200`，共 36 处 `[edx+slot]` 取槽），
  远超本批给定的 7 个导出 ⇒ 缠论组实际约 40+ 个绑定函数 [B]。
- **chlib 只导出 `CreateLib`/`FreeLib`**，TAFLib 也只导入这两个 ⇒ 算法全部封装在 chlib 内，
  TAFLib 仅做"授权 + 行情缓冲 + 事件推送 + 虚调用"绑定 [A]。

### 4.3 工作函数 `0x10002340` 结构 [A/B]

```c
int __thiscall ch_api::vt34(ch_api* this, int count, double* out, Ctx6* ctx, double** p);
```
- 前置 `0x10006cc0(this, &ctx6)` 填 **6 个行情缓冲指针**（IAT 全部来自 `RData.dll!XTAData::Get*Buffer()`）[A]：

  | ctx 偏移 | 缓冲 |
  | --- | --- |
  | +0x00 | HighBuffer |
  | +0x04 | OpenBuffer |
  | +0x08 | LowBuffer |
  | +0x0c | CloseBuffer |
  | +0x10 | VolumeBuffer |
  | +0x14 | AmountBuffer |

- 主体：
  1. `memset(out, 0, count*8)`；
  2. `if (ctx[+0]==0) return -1; if (ctx[+8]==0) return -1;`
  3. `ebx = _ftol2(P)`（chlib 自带的 `0x100148a0`，与 TAFLib `0x1006bc70` 逐句同形）；
     `if (ebx == 0) { if (ch_auth==NULL) return -1; ch_auth->vt[+4](0xEA62) → 失败 return -1; }`
     ⇒ **第二道授权门**；
  4. `0x10006670(count)` 早退检查；
  5. 通过 `[this+0x10]` 子对象的 `vt[+4]`/`vt[+0xc]` 预处理，再 `0x10009930`；
  6. **两个 argmax/argmin 循环**（见 4.4）。
- **`0x10002340` 内部不比较 P**（无 `cmp P,11/12/...`）⇒ P 仅用于授权判定，不选算法分支 [A]。
- 因包装层已短路 `{11,12,21,22,31,32,51}`，**chlib 只会见到 P ∉ 该集合**（典型为 0）[A]。

### 4.4 分型判定内核 [A]

常量：`chlib!0x100154c8 = -DBL_MAX`、`chlib!0x100154c0 = +DBL_MAX`。

| 分支 | 种子 | 比较对象 | test | 跳转成立 | 语义 |
| --- | --- | --- | --- | --- | --- |
| `0x10002606` | `fld [-DBL_MAX]` | `[ecx-0x10] [-8] [0] [+8]`，尾段 `[esi+edx*8]` | `ah,5 jp` | `>=\|=U` | **H 数组 argmax** → `edi` = 最高点索引 |
| `0x100026a4` | `fld [+DBL_MAX]` | 同上（用 `ctx[+8]`=LowBuffer） | `ah,0x41 jne` | `<=|=U` | **L 数组 argmin** → `edi` = 最低点索引 |

- 推进：`ecx += 0x20`（每轮展开 4 个 double）+ 尾段 `add edx,1`；计数 `[esp+0xc]`。
- 出口：`test edi,edi; jl 0x10002757` ⇒ 索引 < 0 → 无分型。
- 条件总数 **10 条**（两组各 5），与 TAFLib CHBI 族（docs/20 §7）的 `ah,5 jp`（≥ 侧）/`ah,0x41 jne`（≤ 侧）
  **极性完全同构** —— chlib 是同一套缠论代码的**独立重写/新版本** [B]。

### 4.5 输出向量初探 [B]

- `out[]` = `count` 个 double 的线性数组（先 `memset 0`）⇒ "每 bar 一个值"的指标数组。
- 用户公式的 `NCHBISTA`（`SELECT(VAR2=-3)`，文档注 -3 = 底分型）走**另一槽** `+0x38 = 0x10002770`，
  返回**状态码**而非价格（+3 推定为顶分型，0 为无）——本批仅方向性结论，第二批深挖。
- `p`（P 槽）在 `{11,12,21,22,31,32,51}` 时被**写回**常量 ⇒ P 参数是**双向**的（入参 + 类型回显）。

---

## 五、复用判定

| 目标 | 复用 | 调用点 / 依据 |
| --- | --- | --- |
| `0x1001c110`（boost::shared_ptr 构造桩） | **是** | NChBi 包装层 `0x10012b37`；CHBI 包装层 `0x1000f692`；内部调 `0x1001c940`（shared_count ctor） |
| `0x10001cc0`（事件对象 ctor） | **是** | NChBi `0x10012af4`；CHBI `0x1000f656`（同一 ctor，0x30B 事件对象） |
| `0x1003eba0`（CHBI/CHDUAN 共用 m[2] 拆表） | **否** | 包装层调用表无（见下）；chlib 只导入 MSVCR80/MSVCP80/KERNEL32，无法回调 TAFLib |
| `0x10053540`（CHDUAN prep） | **否** | 同上 |
| `0x1003ef00`（方向标注） | **否** | 同上 |
| `0x1002c1d0`（CHBI 真工作函数） | **否** | NChBi 走 chlib `vt[+0x34]`，路径与 CHBI 完全不同 |

**NChBi 包装层完整调用表**（`0x10012a50`–`0x10012c38`）[A]：

| 目标 | 定性 |
| --- | --- |
| `0x1006bc70` | `_ftol2`（double→int） |
| `0x10014e60` | `Authorize(this, code)` |
| `0x1006bd22` | `memset` |
| `0x1006b32c` | `operator new` |
| `0x10001cc0` | 事件对象 ctor（与 CHBI 同） |
| `[0x1006f07c]` | `MSVCP80!std::string::operator=` |
| **`0x1001c110`** | **boost::shared_ptr 构造桩（复用）** |
| `[0x1006f220]` | `RDM_C!DmcApi::PushEvent(shared_ptr<evtbase> const&)` |
| `0x10006cc0` | 取 6 个行情缓冲指针（H/O/L/C/V/A） |
| **chlib `ch_api::vt[+0x34]`** | **真工作函数** |

⇒ 无 `0x1003eba0` / `0x10053540` / `0x1003ef00` / `0x1002c1d0`（探针：`tools/re-inventory/nchbi/reuse_probe.txt`）。

---

## 六、可复现命令

```bash
PY="C:/Users/Administrator/Documents/a_conda/python.exe"
CHLIB="D:/a_ronglide/clone-ronglide/ronglide-app/chlib.dll"

# 1) NChBi 入口 + 事件段 + P 短路表（TAFLib, 默认 DLL）
$PY tools/re-inventory/disasm_func.py 0x10012a50 --max 0x200 -o tools/re-inventory/nchbi/nchbi_entry.txt

# 2) 同族兄弟包装层（授权码 / 虚表槽）
$PY tools/re-inventory/disasm_func.py 0x10012c40 --max 0x400 --dll "$CHLIB"   # (同族用 TAFLib 即可, 见下注)
for a in 0x10012d20 0x10012e00 0x10012e70 0x10012f50; do
  $PY tools/re-inventory/disasm_func.py $a --max 0x120; done

# 3) chlib 工厂 + ch_api 虚表槽映射（含 TAFLib 绑定标注）
$PY tools/re-inventory/nchbi/dump_chlib_vtable.py -o tools/re-inventory/nchbi/chlib_vtable_and_factory.txt

# 4) chlib 工作函数 0x10002340 + x87 条件表
$PY tools/re-inventory/disasm_func.py 0x10002340 --max 0x440 --dll "$CHLIB" \
      -o tools/re-inventory/nchbi/chlib_worker_10002340.txt
$PY tools/re-inventory/x87_sim.py tools/re-inventory/nchbi/chlib_worker_10002340.txt \
      -o tools/re-inventory/nchbi/cond_chlib_10002340.txt

# 5) 成员偏移扫描（this+0xbc 的写入点 = ctor 0x10001f6a）
$PY tools/re-inventory/nchbi/scan_member.py 0xbc --only-write

# 6) 复用探针
$PY tools/re-inventory/nchbi/scan_member.py 0xbc   # 读取点全家族
```
> 注：`disasm_func.py` 自本批起支持 `--dll <path>`（默认仍为 `缠中说禅\TAFLib.dll`）。

---

## 七、勘误与待仲裁

| # | 项 | 状态 |
| --- | --- | --- |
| 1 | `0x1006bc70` 曾被描述为"P 转码器" | **勘误 [A]**：实为 `_ftol2` |
| 2 | NChBi 与 ChBi「共用工作函数」的早期假定 | **否定 [A]**：仅共用包装层辅助（`0x1001c110`/`0x10001cc0`），算法分属两模块 |
| 3 | 缠论组绑定函数数量 | **修正 [B]**：非 7 个，槽位覆盖 +0x18…+0xc4（36+ 处） |
| 4 | 未列入给定清单的槽（+0x40/+0x48/+0x50/+0x54/+0x5c/+0x64）对应的导出名 | **待仲裁 [C]**：需按 `0x10013000`–`0x10013c00` 的函数入口逐个对 registry |
| 5 | `chlib 0x10002340` 的 `[esp+0xc]`（计数）来源与 `[esp+0x18]` 比较语义 | **待仲裁 [C]**：需读 `0x10009930` / `0x10006670` |
| 6 | `NCHBISTA` 返回码 −3/+3/0 的确切判定 | **待仲裁 [C]**：第二批解剖 `0x10002770` |
| 7 | `NChBi` 与 `NChBiSta` 在 chlib 内是否共享同一"内部容器"（`[this+0x10]` 子对象） | **待仲裁 [C]**：需读 `0x10002770` 与 `[this+0x10]->vt` |
| 8 | 本批未做动态验证 | 需 frida（挂 `0x10012a50` 与 chlib 基址 + 0x10002340） |

---

## 八、下一步（建议）

**NChBi 第二批：算法解剖（chlib 侧）** — 优先级最高，理由：

1. NChBi 的**算法全在 chlib**，本批只做到"入口 + 分派 + 定位"，`out[]` 与 `-3/+3` 语义仍未落地；
2. `0x10002770`（NChBiSta）是用户公式的实际使用点（`SELECT(VAR2=-3)`，底分型），闭环价值最高；
3. 静态可做（反汇编已在手），不依赖 frida；
4. 与 `0x10002340` 共享 `[this+0x10]` 子对象的可能性大，一次解剖可覆盖多槽。

备选：CHDUAN frida 对拍（`tools/re-inventory/chduan/frida_chduan4.md`，需用户启动软件配合）。
