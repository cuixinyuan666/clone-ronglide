# ZouShiBi（走势笔）逆向 · 第一批 —— 入口链与骨架

> 日期：2026-10-28 ｜ 分支 `old1`  
> 目标：导出函数 `ZouShiBi`（走势笔，注册信息中 auth code `0xEA62`），识别其 wrapper 链路与首层 worker  
> 证据：`tools/re-inventory/zoushi/`（`wrapper_ZouShiBi_10010010.txt`、`wrapper_ZouShiZsAll_10010110.txt`、`wrapper_ZouShimmd_10010210.txt`、`auth_10014e60.txt`）

---

## 一、结论

- **入口（VA）**：`TAFLib.dll` 导出 `?CalcProc_ZouShiBi@TAF_Calculator@@IAE_NIPANQAPAN@Z` @ `0x10010010`，`ZouShiZsAll` @ `0x10010110`，`ZouShimmd` @ `0x10010210`。  
- **授权门（已确权）**：`ZouShiBi` 在初始化容器（`[edi+0xb0]`）后调用 `sub_10014e60`（`thiscall`，`ecx=edi`）并传入 **`0xEA62`**（`push 0xEA62` @ `0x10010079`）。授权不通过时清零输出缓冲并返回 `AL=0`；通过后继续执行。  
- **wrapper 模式（高度同构）**：三者序言、异常处理、容器懒初始化、授权调用、失败清零返回、成功后构造临时对象并调用不同 worker、最后释放临时对象的流程几乎一致，仅 **worker 地址不同**。  
- **首层 worker（静态识别）**：`ZouShiBi` → `sub_1002fbf0`；`ZouShiZsAll` → `sub_10030b50`；`ZouShimmd` → `sub_10033760`。后三者参数传递方式相似但 **栈参数顺序/个数细节不同**（见 §二），需进一步静态/动态确认语义归属。  
- **容器布局线索**：`ZouShiBi` 首次访问 `[edi+0xb0]` 并在为 0 时通过 `operator new`（`call 0x1006b32c`）分配 4 字节对象、调用 `sub_1002c160` 初始化并写回 `[edi+0xb0]`，与既有结论中 `ctx 句柄构造（new(0xC8)+W ctor）` 模式相关 [A]。

> 说明：`rea.exe` 的 decompile/xrefs 仅作参考，不作为地址级证据（summary 既有勘误）。

---

## 二、入口链与参数传递

### 2.1 ZouShiBi @ `0x10010010`（thiscall，ret 0xC）
序言：MSVC SEH、栈对齐、canary、保存 `edi/esi`。`edi = this`（公式对象）。

| 地址 | 指令 | 说明 |
| --- | --- | --- |
| `0x1001003d-0x10010079` | `cmp [edi+0xb0],0` → 若零：`malloc(4)`（`0x1006b32c`）→ `call 0x1002c160` 初始化 → 写 `[edi+0xb0]=eax` | 容器懒初始化（首次调用） [A] |
| `0x10010079-0x10010087` | `push 0xEA62`; `mov ecx,edi`; `call 0x10014e60`; `test al,al`; `jne 0x100100b8` | **授权门**（代码 `0xEA62`）[A] |
| `0x10010089-0x100100b5` | 授权失败：取 `[ebp+8]=arg0`, `[ebp+0xc]=arg1`；`lea ecx,[eax*8]`; `push ecx,0,edx`; `call 0x1006bd22`（memset/清零类）；`xor al,al`; 恢复并 `ret 0xc` | 失败路径：按 arg1 长度*8 清零，返回 false [A] |
| `0x100100b8-0x100100d2` | 授权通过：`malloc(4)`；若成功设 vtable `0x1006f708` 并 `esi=eax`，否则 `esi=0` | 构造临时对象 [A] |
| `0x100100d2-0x100100e5` | 取栈参：`eax=[ebp+0xc]`, `ecx=[ebp+8]`, `edx=[edi+0xb0]`；`mov eax,[ebp+0x10]`；压栈 `esi,eax,ecx,edx` | 准备参数 [A] |
| `0x100100e5` | `call 0x1002fbf0` | **首层 worker** [A] |
| `0x100100ea-0x100100f8` | 若 `esi!=0`：取 vtable+0，`push 1`, `call edx`（析构/释放） | 清理临时对象 [A] |
| `0x100100f8-0x1001010b` | `mov al,1`；SEH epilogue；`ret 0xc` | 成功返回 true [A] |

**栈参数布局（cdecl/fastcall thiscall 混合，ret 0xc）**：
- `[ebp+8]` = arg1（count/长度相关）
- `[ebp+0xc]` = arg2（输出/数组指针相关）
- `[ebp+0x10]` = arg3（第三参数）
- `ecx = this (edi)`
- worker 调用压栈顺序：`push esi (tmp)`、`push [ebp+0x10] (arg3)`、`push [ebp+8] (arg1)`、`push [edi+0xb0] (ctx/W句柄)`，共 4 个栈参数 [A]

### 2.2 ZouShiZsAll @ `0x10010110`（同构）
结构与上完全同构，唯一区别：`call 0x10030b50` 替代 `0x1002fbf0` [A]。栈参数传递序列相同。

### 2.3 ZouShimmd @ `0x10010210`（同构，参数顺序略有差异）
结构同构。差异点：
- `0x100102de-0x100102e5`：压栈顺序为 `push esi, push eax([ebp+0xc]), push ecx([ebp+8]), push ecx2([ebp+0x10]), push edx([edi+0xb0])` —— 相比前两者，**arg1/arg3 压栈顺序不同**（`[ebp+0xc]` 先于 `[ebp+8]` 压入，`[ebp+0x10]` 也被压入）[A]。
- 调用 `0x10033760` [A]。
其余（授权门 `0xEA62`、懒初始化、失败清零、对象生命周期）完全一致。

---

## 三、授权门 `sub_10014e60`（auth，代码 `0xEA62`）

函数 @ `0x10014e60`（thiscall，`ecx=this`，`ret 4`）。序言 SEH。

| 地址 | 指令 | 说明 |
| --- | --- | --- |
| `0x10014e87-0x10014e8d` | `mov edi,ecx; mov [esp+0x14],edi; xor ebx,ebx` | 保存 this [A] |
| `0x10014e8f-0x10014ea6` | 调用 `GetTickCount/GetCurrentThreadId/GetCurrentProcessId`（导入）生成随机/种子；模 100 循环直到找到值 | 初始化流程 [A] |
| `0x10014ebc-0x10014f12` | 若种子路径失败，分配对象（`malloc(0x30)`）、设置 vtable `0x1006f700`、初始化成员，构造 shared_ptr 样式控制块（经 `0x1001d9f0`） | 对象构造链（复用既有 `shared_ptr` 模式，见 docs/18 §1.1）[A] |
| `0x10014f21-0x10014f5c` | `eax = [esp+0x34] + 0xFFFF15A0`；写 `[esi+8]=1, [esi+0xc]=eax`；从 `this+0xc` 取字符串（`push [ecx+4]` 经 `call [0x1006f07c]`）；构造 control block 对 | 与 docs/18 中 `T[+0x0C]=code`、`T[+0x08]=1`、`T[+0x14]=string` 的模式**高度吻合** [A][B] |
| `0x10014f5c-0x10014f9f` | 调用 `0x1001d9f0` 构造控制块，原子增减引用计数（`lock xadd`）处理旧控制块 | 原子引用计数（MSVC shared_ptr）[A] |
| `0x10014f9f-0x10014fc2` | 调用 `0x1001e780`、清理栈帧 | 收尾 [A] |
| `0x10014fc6-0x10014ff3` | 原子减计数，若归零调用析构（vtable+4, vtable+8） | 引用计数析构 [A] |
| `0x10014ff3-0x10015012` | 写 `[ecx+0xb4] = 0`（`this+0xb4`）；`xor al,al`？等成功路径见上：`0x10014f07` 设置 `al=1` 并跳转 `0x10014fff` 返回。授权通过时最终返回 `AL=1`，失败返回 `AL=0`（并在失败分支 `0x10014fff` 有不同路径）[A] |

**要点**：
- 调用约定：`mov ecx,[esp+0x4c]`（iface/this）→ `call [vtbl+4]` 的模式在本函数内**未直接看到**，但 wrapper 按「`push code; mov ecx,this; call auth`」方式调用，且 `auth ret 4`。总结中描述的「vtable+4 调用」可能是另一条授权实现路径，或在不同上下文使用；本批直接跟踪 wrapper+本函数的调用链，确认 wrapper 层的调用方式符合预期 [A][B]。
- 代码值 `0xEA62` 由 wrapper 传入（`push 0xEA62`）；在 `auth` 内部如何使用该值需进一步追踪（当前 dump 未见直接 `cmp` `0xEA62`，可能存入对象后由后续逻辑或 vtable 调用校验）[C]。

---

## 四、worker 骨架（首层）

### 4.1 `sub_1002fbf0`（ZouShiBi worker）
从 wrapper 调用点 `0x100100e5` 进入。需后续用 `disasm_func.py` dump 全函数以获取完整流程 [C]。

### 4.2 `sub_10030b50`（ZouShiZsAll worker）
调用点 `0x100101e5` [C]。

### 4.3 `sub_10033760`（ZouShimmd worker）
调用点 `0x100102e5`，栈参数顺序与前两者不同（见 §2.3）[C]。

> 建议后续：`python tools/re-inventory/disasm_func.py 1002fbf0 -o tools/re-inventory/zoushi/w_1002fbf0.txt` 等，按同样方式产出首层 worker dump 并补充到本文档。

---

## 五、与既有 CHBI 链路对比

| 项目 | CHBI（docs/18） | ZouShiBi（本批） |
| --- | --- | --- |
| 导出 | `CalcProc_ChBi @0x1000f580` | `CalcProc_ZouShiBi @0x10010010` |
| 授权 | `0xEA62`（P==51 时触发） | `0xEA62`（wrapper 直接 `push 0xEA62` 调用 `sub_10014e60`） |
| 容器懒初始化 | `0x1002c160`（ctx/W ctor）多处使用 | `0x1001003d+`：`[edi+0xb0]==0` 时 `malloc(4)` → `call 0x1002c160` → 写回 [A][B] |
| 共享_ptr 封装 | `0x1001c110/0x1001c940`（pair+控制块） | `auth` 内部 `0x1001d9f0/0x1001e780` 等共享同一套控制块逻辑 [A][B] |
| 首层工作函数 | `0x1002c1d0`（443 指令，双段同构处理） | `0x1002fbf0`（待 dump） [C] |

---

## 六、置信度标记与待办

**置信度**：
- `[A]` = 原始指令证据（wrapper/auth dump 中直接可见）
- `[B]` = 多处一致（与 docs/18/summary 中既有模式对比）
- `[C]` = 需进一步验证（worker 全函数、参数语义、运行时行为）

**待办**：
- [ ] 用 `disasm_func.py` 分别 dump `0x1002fbf0`、`0x10030b50`、`0x10033760` 到 `tools/re-inventory/zoushi/`，梳理首层调用链
- [ ] 追踪 `sub_10014e60` 如何使用传入的 `0xEA62`（存储位置/校验逻辑），确认是否走 vtable+4 路径
- [ ] 对比 `ZouShiBi/ZouShiZsAll/ZouShimmd` 的 worker 参数传递差异，结合公式族推断语义（走势笔/走势中枢相关？）
- [ ] 若能获取最小调用上下文，尝试静态识别 worker 内的容器读写（W/m[0]/m[2] 等），参考 CHBI 的 0xA0 步长模式
- [ ] （可选）原生 frida 跟踪验证授权失败清零路径（仅在已有宿主可用时，且不得 inject_*_bypass）

---

## 附录：文件清单
- `tools/re-inventory/zoushi/wrapper_ZouShiBi_10010010.txt`
- `tools/re-inventory/zoushi/wrapper_ZouShiZsAll_10010110.txt`
- `tools/re-inventory/zoushi/wrapper_ZouShimmd_10010210.txt`
- `tools/re-inventory/zoushi/auth_10014e60.txt`
