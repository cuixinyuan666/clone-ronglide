# ChFxbi（缠论分型笔）逆向 · 第一批 —— 入口链与骨架

> 日期：2026-10-28  
> 目标：公式 `CHFXBI` / 导出 `ChFxbi @ 0x1000f740`（分型笔，auth code `0xEA62`）  
> 证据：`tools/re-inventory/fxbi/wrapper_ChFxbi_1000f740.txt`、`tools/re-inventory/chbi/`（`wrapper_ChBi_1000f580.txt`、`core_1002c1d0.txt`、`pseudocode/chbi.c`）、`tools/re-inventory/chduan/wrapper_ChDuan_1000f850.txt`  
> 方法：`tools/re-inventory/disasm_func.py`（capstone）静态反汇编，仅读 PE；未运行注入脚本。  
> 置信度：`[A]`=字节/直接证据 ` [B]`=高交叉 ` [C]`=推断/待验证

## 一、结论（先行）

- `ChFxbi` 包装层极为简短：**直接复用 P=51 硬编码工作函数 `sub_1002c4b0`**，而非 `ChBi` 的 `shared_ptr(obj)+0x1001c110+0x1002c1d0` 长链。
- **EA62 授权门**出现在 wrapper 入口（`push 0xEA62; call 0x10014e60; test al,al; jne fail`）。失败走 `memset(arg2*8)->return 0`；通过后构造轻量 iface 对象（`new(4)`, vtable `0x1006f708`），经一次**间接调用** `call dword ptr [0x1006f190]`，再以 `__usercall` 方式调用 `0x1002c4b0`。
- 与 `ChBi` 对比：`ChBi` 在 `P==51` 时在包装层和 `0x1002c1d0` 内部都检查 `EA62`（双重门），且走 `0x1002c1d0` 链；`ChFxbi` **仅在包装层做 EA62 门**，且**跳过 P 判定直接走 `0x1002c4b0`**（`0x1002c4b0` 内部同样有 EA62 门，见 `pseudocode/chbi.c:147-156`）。
- `0x1002c4b0` 已在 `chbi/` 证据中被大量引用（`core_1002c1d0.txt` 内含其序言），且 `pseudocode/chbi.c` 已将其定性为「硬编码 P=51 版入口」：链路 `db40→e200→a040→eba0→ef00→EA62门(iface)→输出环`，输出编码与 `sub_1002c1d0` 相同（`+1/-1`，`+0x98==1` 倍增为 `-2`）。

## 二、入口参数与签名推断

### 2.1 Wrapper 调用约定（实测）

`wrapper_ChFxbi_1000f740`（`thiscall`，ECX=this，栈 `[ebp+8]=arg1, [ebp+0xC]=arg2, [ebp+0x10]=arg3`，`ret 0xC`）:

| 步骤 | 汇编 | 备注 |
| --- | --- | --- |
| lazy init | `[edi+0xB0]==0` → `malloc(4); call 0x1002c160` 填充 W* 到 `[edi+0xB0]` `[A]` | 与 `ChBi` 完全同型（`chduan` 也用此模式） |
| auth gate | `push 0xEA62; mov ecx,edi; call 0x10014e60; test al,al; jne 0x1000f7e8` `[A]` | EA62 门。失败跳转到「置零返回」路径 |
| fail path | `lea ecx,[eax*8]; push ecx; push 0; push edx; call 0x1006bd22; xor al,al; ... ret 0xC` `[A]` | `arg2*8` 字节清零后返回 `0` |
| iface 构造 | `malloc(4); [eax]=0x1006f708; esi=eax`（失败则 `esi=0`）`[A]` | 轻量对象，传给引擎/授权接口 |
| 预调用 | `call dword ptr [0x1006f190]` `[A]` | 间接调用（未 dump 出函数体；见 §三） |
| 转调引擎 | `EAX = [ebp+0x10]; push esi; push [ebp+0xC]; push [ebp+8]; push [edi+0xB0](ctx); call 0x1002c4b0` `[A]` | `__usercall`，`ret 0x14`（按 `pseudocode/chbi.c:187`） |
| 收尾 | 若 `esi!=0` 调用 `vtbl[0]`（`push 1; call edx`）释放，返回 `al=1` `[A]` | 与 `ChBi` 尾部对象释放模式相似 |

推断 `ChFxbi` 对外签名（参数语义需结合 `ChBi`/引擎约定）：`(this, H/L/P数组或引擎参数, count, outD)`，与 `ChBi` 包装层参数槽位相同（`[ebp+8]/[ebp+0xC]/[ebp+0x10]`）。具体 `series` 结构沿用 `pseudocode/chbi.c:191` 的 `={double*H; double*L; ...}` 假设 `[B]`。

## 三、包装链地址清单

| 地址 | 类型 | 归属 | 备注 |
| --- | --- | --- | --- |
| `0x1000f740` | Wrapper（导出 `ChFxbi`） | 本批主角 `[A]` | 新 dump：`tools/re-inventory/fxbi/wrapper_ChFxbi_1000f740.txt` |
| `0x1002c160` | ctx/W 构造（`new(0xC8)+W ctor`） | 已有（多处复用） `[A]` | `ChBi`/`ChDuan`/多族共用 |
| `0x10014e60` | 授权校验（vtable `[ecx]->vtbl[4]`, push `0xEA62`） | 已有 `[A]` | `summary.md §2.3` 已述 vtable 模式；多族调用 |
| `0x1006b32c` | `malloc`/分配包装 | 已有 `[A]` | 通用 |
| `0x1006bd22` | 内存填充/操作（fail 路径用） | 已有 `[A]` | 通用 |
| `0x1006f190` | **间接函数指针**（`call dword ptr [0x1006f190]`） | `[B]`（未导出函数体） | `ChDuan` 包装也存在同类间接调用。尝试用 `disasm_func.py` 从 `0x1006f190` dump 进入数据/垃圾，判定为**指针槽位而非函数起始**，不强行转录为 worker 函数体。 |
| `0x1002c4b0` | P=51 硬编码工作函数（`__usercall`） | 已有（chbi 证据） `[A]` | `core_1002c1d0.txt` 含序言；`pseudocode/chbi.c:184-191` 定义。被 `ChFxbi` 直接调用。 |
| `0x1006f708` | iface vtable（设置到 `[eax]`） | 已知 `[A]` | 与 `ChBi` 包装层构造对象的 vtable 相同 |

## 四、与 ChBi 的对比

| 项目 | `ChBi @0x1000f580` | `ChFxbi @0x1000f740` |
| --- | --- | --- |
| P 判定 | 读取 `param_array[+8]`，仅 `P==51` 触发双重 EA62 门并走特殊路径；其他 P 走分派链 `[A]` | **无 P 读取**，直接走 `0x1002c4b0` `[A]` |
| 授权门时机 | 包装层 `P==51` 时检查一次；`0x1002c1d0` 内部 `P==51` 时再检查一次 `[A]` | **仅包装层**检查 EA62，失败直接置零返回 `[A]` |
| 核心调用 | `0x1001c110(shared_ptr)+0x1002c1d0` `[A]` | **直接 `0x1002c4b0`** `[A]` |
| 对象构造 | 构造 0x30 对象 + shared_ptr 链（`0x10001cc0`, `0x1001c110/940/d9f0`） `[A]` | 构造 4 字节 iface 对象（`[eax]=0x1006f708`）并传入 `[A]` |
| 复用引擎 | 同一套容器/W 状态机，最终走相同的 `db40/e200/a040/eba0/ef00` 家族 `[A]` | **同上**，由 `0x1002c4b0` 固定调度 `[A]` |

结论：`ChFxbi` 更像是**「分型笔」的精简包装**，省去了 `ChBi` 面向多 P 的分派逻辑，直接复用「P=51 路径」的引擎。两者共享大量 worker（`db40/e200/a040/eba0/ef00/0x1003f0d0/0x1006a720` 等），符合「重用 CHBI 知识」预期。

## 五、工作函数链（基于既有证据）

`0x1002c4b0` 的内部链路已由 `pseudocode/chbi.c` 固化（`[A]`）：

```
sub_1002c4b0(series(EAX), ctx, count, outD, iface)
  ├─ bufA/bufB = new[](count*4)（降精度 float）
  ├─ outD 清零（fldz）
  ├─ sub_1003db40(w,count,bufA,bufB)        // 候选端点生成
  ├─ sub_1003e200(w)                        // 严格分型标注
  ├─ sub_1006a040(w)                        // 分型笔记录生成（m[5]）
  ├─ sub_1003eba0(w)                        // 拆分 ContA/ContB，戳 m0.biDir
  ├─ sub_1003ef00(w)                        // 复制 ContC，戳 m0.biDir
  ├─ EA62 门(iface->vtbl[1](0xEA62))        // 失败返回 -1
  └─ 输出环：遍历 m0，按 barIndex 写出D，candBot==1 → ×2（-2），空档补0
```

具体字段语义、容器布局、状态机细节参见 `docs/18-CHBI-第一批-入口链与工作函数.md` 和 `pseudocode/chbi.c`，本批不重复推导。

## 六、已 dump / 待 dump 清单

| 地址 | 产物 | 状态 |
| --- | --- | --- |
| `0x1000f740` | `tools/re-inventory/fxbi/wrapper_ChFxbi_1000f740.txt` | **已完成** `[A]` |
| `0x1002c4b0` | 已存在于 `chbi/core_1002c1d0.txt`（含序言）+ `pseudocode/chbi.c` | **复用，不重 dump** `[A]` |
| `0x1006f190` | 尝试 dump 失败（落入数据）→ 视为间接指针槽位 | **跳过** `[B]` |
| 其他 worker（`db40/e200/a040/eba0/ef00`） | `tools/re-inventory/chbi/` 全部已存在 | **复用** `[A]` |

## 七、待办（[C] 项）

- [C] **确认 `ChFxbi` 参数语义**：需结合实际调用（或对比 `ChBi`/`ChDuan` 注册表用法）确认 `[ebp+8]/[ebp+0xC]/[ebp+0x10]` 对应 `H/L/P` 还是引擎句柄序列；当前按 `ChBi` 包装层惯用推断。
- [C] **厘清 `0x1006f190`**：找出其初始化点（xref/重定位表）确认是否为 nop/thunk/回调注册；若有实质逻辑需再补 dump。
- [C] **双重授权门影响**：`ChFxbi` 仅包装层做 EA62，`0x1002c4b0` 内部也做一次。需确认两处门的 `iface` 对象是否同一（当前 wrapper 构造并传入，`0x1002c4b0` 接收 `arg4=iface` 并调用 `iface->vtbl[1](0xEA62)`）——字节证据显示**同一对象传递**，但语义细节待验证。
- [C] **与 `ChBi` 输出差异**：仅入口/授权路径不同，算法主体应大同小异；需后续用小样本对拍验证。

## 八、参考

- `docs/18-CHBI-第一批-入口链与工作函数.md`
- `pseudocode/chbi.c`（§2.5 输出环、§2.4 P 分派、§6 a040）
- `tools/re-inventory/chbi/wrapper_ChBi_1000f580.txt`
- `summary.md §2.2/2.3、§3.8`
