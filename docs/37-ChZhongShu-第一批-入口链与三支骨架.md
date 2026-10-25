# ChZhongShu 族第一批 — 入口链与三支骨架

> 批次：ChZhongShu 族第一批（2026-10-25）
> 优先级：P9（依 `docs/14-付费功能与指标总览.md` 排序）
> 目标：ChZhongShu (0x1000f910, BIZHONGSHU, 笔中枢, 0xEA61, 被引用10次)
> 证据目录：`tools/re-inventory/chzhongshu/`
> 置信度：[A] 字节级实证 | [B] 多路交叉 | [C] 待仲裁

---

## 〇、摘要

| # | 结论 | 置信 |
|---|------|------|
| 1 | ChZhongShu 族包含 3 支核心函数：`ChZhongShu`(0x1000f910)、`ChZhongShuG`(0x1000fb10)、`ChZhongShuD`(0x1000fc10)，均为 `ret 0xc`（3 参数：this + n + out） | [A] |
| 2 | 三支函数**共享相同入口框架**：检查 `this[+0xb0]` → 分配内存 → 初始化 → 授权检查（`Authorize(0xEA61)`）→ memset → 调用核心 worker | [A] |
| 3 | 核心工作函数：ChZhongShu→`0x1002ca30`、ChZhongShuG→`0x1002cd00`、ChZhongShuD→`0x1002cee0` | [A] |
| 4 | ChZhongShuG/D 的核心 worker **逐字节同构**，仅 `fld` 操作数偏移不同（G: +0x50, D: +0x54） | [A] |
| 5 | 三支函数均包含 x87 比较：`fldz` → `fld [mem]` → `fcom st(1)` → `fnstsw ax` → `test ah, 0x41` → `jne`，语义为 **ST0 > ST1** | [A] |
| 6 | 容器依赖：`this[+0xb0]` 作为计数器/状态，`0x1006b32c` 为内存分配器，`0x1002c160` 为初始化器 | [A] |

---

## 一、族内成员总览

### 1.1 受保护函数信息（来自 docs/14）

| 导出函数 | 公式名 | 中文名 | 授权码 | 被引用次数 | 地址 |
|---|---|---|---|---|---|
| `ChZhongShu` | BIZHONGSHU | 笔中枢 | 0xEA61 | 10 | 0x1000f910 |
| `ChZhongShuG` | BIZHONGSHUG | 笔中枢高点 | 0xEA61 | 5 | 0x1000fb10 |
| `ChZhongShuD` | BIZHONGSHUD | 笔中枢低点 | 0xEA61 | 5 | 0x1000fc10 |

### 1.2 相关公式指标（来自 docs/14）

依赖 ChZhongShu 的付费指标：
- `CHBZS` (自动画出缠论笔中枢及买卖点)
- `CHDZS` (自动画出缠论线段中枢及买卖点)
- `CH一买/二买/三买` (缠论笔买点)
- `CH一卖/二卖/三卖` (缠论笔卖点)
- `CHBZS_GD` (笔中枢震荡中的高点和低点提示)
- 等 42 个缠论扩展组指标

---

## 二、入口框架分析

### 2.1 共同序言（0x1000f910 / 0x1000fb10 / 0x1000fc10）

三支函数的入口代码**逐字节同构**：

```asm
1000f910  push     ebp
1000f911  mov      ebp, esp
1000f913  and      esp, 0xfffffff8
1000f916  push     -1
1000f918  push     0x1006ceeb      ; SEH 处理程序
1000f91d  mov      eax, dword ptr fs:[0]
1000f923  push     eax
1000f924  sub      esp, 0xc
1000f927  push     esi
1000f928  push     edi
1000f929  mov      eax, dword ptr [0x1007c018]
1000f92e  xor      eax, esp
1000f930  push     eax
1000f931  lea      eax, [esp + 0x18]
1000f935  mov      dword ptr fs:[0], eax
1000f93b  mov      edi, ecx          ; edi = this
```

**框架特征：**
- 标准 MSVC SEH 帧
- `ret 0xc`（3 个 dword 参数：this + n + out）
- `this` 寄存器：edi

### 2.2 状态检查与初始化

```asm
1000f93d  cmp      dword ptr [edi + 0xb0], 0   ; 检查 this[+0xb0]
1000f944  jne      0x1000f979                ; 非零则跳过初始化
1000f946  push     4
1000f948  call     0x1006b32c                ; 内存分配(4 字节)
1000f94d  add      esp, 4
1000f950  mov      dword ptr [esp + 0x10], eax
1000f954  test     eax, eax
1000f956  mov      dword ptr [esp + 0x20], 0
1000f95e  je       0x1000f969
1000f960  mov      esi, eax
1000f962  call     0x1002c160                ; 初始化函数
1000f967  jmp      0x1000f96b
1000f969  xor      eax, eax
1000f96b  mov      dword ptr [esp + 0x20], 0xffffffff
1000f973  mov      dword ptr [edi + 0xb0], eax   ; this[+0xb0] = 分配的内存/0
```

**语义：**
- `this[+0xb0]` 作为**状态计数器/内存指针**
- 首次调用时分配内存并初始化
- `0x1006b32c` = 内存分配器（4 字节）
- `0x1002c160` = 初始化器

### 2.3 授权检查

```asm
1000f979  push     0xea61                  ; 授权码 0xEA61
1000f97e  mov      ecx, edi                ; ecx = this
1000f980  call     0x10014e60              ; Authorize(0xEA61)
1000f985  test     al, al
1000f987  jne      0x1000f9b8              ; 授权通过则继续
```

**授权失败处理：**
```asm
1000f989  mov      eax, dword ptr [ebp + 8]    ; arg1 = n
1000f98c  mov      edx, dword ptr [ebp + 0xc]  ; arg2 = out
1000f98f  lea      ecx, [eax*8]              ; n * 8
1000f996  push     ecx                        ; size
1000f997  push     0                          ; value = 0
1000f999  push     edx                        ; out
1000f99a  call     0x1006bd22                ; memset(out, 0, n*8)
1000f99f  add      esp, 0xc
1000f9a2  xor      al, al                    ; 返回 0（失败）
1000f9a4  ; ... 恢复帧并 ret 0xc
```

### 2.4 核心工作调用

**ChZhongShu (0x1000f910):**
```asm
1000f9b8  push     4
1000f9ba  call     0x1006b32c                ; 再次分配内存
1000f9bf  add      esp, 4
1000f9c2  test     eax, eax
1000f9c4  je       0x1000f9d0
1000f9c6  mov      dword ptr [eax], 0x1006f708  ; 设置 vt[0]
1000f9cc  mov      esi, eax
1000f9ce  jmp      0x1000f9d2
1000f9d0  xor      esi, esi
1000f9d2  mov      eax, dword ptr [ebp + 0x10]  ; arg1 = n
1000f9d5  mov      ecx, dword ptr [ebp + 0xc]   ; arg2 = out
1000f9d8  mov      edx, dword ptr [edi + 0xb0]  ; this[+0xb0]
1000f9de  push     eax                        ; arg1 = n
1000f9df  push     ecx                        ; arg2 = out
1000f9e0  mov      ecx, dword ptr [ebp + 8]    ; arg3 = ?
1000f9e3  push     edx                        ; arg4 = this[+0xb0]
1000f9e4  mov      eax, esi                  ; arg0 = 分配的内存
1000f9e6  call     0x1002ca30                ; 核心工作函数
```

**ChZhongShuG (0x1000fb10) / ChZhongShuD (0x1000fc10):**
```asm
; ... 授权通过后
1000fbd2  mov      ecx, dword ptr [ebp + 8]    ; arg1 = n
1000fbd5  test     ecx, ecx
1000fbd7  jle      0x1000fbe9                ; n <= 0 则跳过
1000fbd9  mov      eax, dword ptr [ebp + 0xc]  ; arg2 = out
1000fbdc  mov      edx, dword ptr [edi + 0xb0]  ; this[+0xb0]
1000fbe2  push     eax                        ; arg1 = out
1000fbe3  push     edx                        ; arg2 = this[+0xb0]
1000fbe4  mov      edx, esi                  ; arg0 = 分配的内存
1000fbe6  call     0x1002cd00                ; ChZhongShuG 核心
; 或 call     0x1002cee0                ; ChZhongShuD 核心
```

---

## 三、核心工作函数分析

### 3.1 ChZhongShu 核心 (0x1002ca30)

**函数签名：** `sub_1002ca30(n, out, this_b0, ?)` → 无返回值（通过 out 输出）

**关键特征：**
- 109 条指令
- 无 x87 条件比较（0 conditions）
- 调用 `0x1003f150`（与 CHBI 族共享的核心引擎）
- 使用 `0x1006f194` 作为回调函数

**核心逻辑：**
```asm
1002ca91  mov      ecx, edi
1002ca93  xor      ebx, ebx
1002ca95  call     0x1003f150    ; 调用 CHBI 族的核心引擎
```

**观察：** ChZhongShu **复用 CHBI 族的核心引擎**（`0x1003f150`），这与 NChBi 族的架构一致。

### 3.2 ChZhongShuG 核心 (0x1002cd00)

**函数签名：** `sub_1002cd00(out, this_b0, ?)` → 无返回值

**关键特征：**
- 157 条指令
- 1 个 x87 条件比较
- 同样调用 `0x1003f150`（CHBI 核心引擎）

**x87 比较站点（0x1002ce68-0x1002ce77）：**
```asm
1002ce68  fldz                          ; ST0 = 0.0
1002ce6a  fld      qword ptr [esp + 0x1c]  ; ST0 = [esp+0x1c], ST1 = 0.0
1002ce6e  fcom     st(1)                  ; 比较 ST0 与 ST1
1002ce70  fnstsw   ax                    ; 状态字 → AX
1002ce72  fstp     st(1)                  ; 弹出 ST1
1002ce74  test     ah, 0x41               ; 检查 C0 和 C3
1002ce77  jne      0x1002ce8a            ; 如果 ST0 > ST1 则跳转
```

**语义：** `if ([esp+0x1c] > 0.0) goto 0x1002ce8a`

**数据偏移：**
- ChZhongShuG: `fld dword ptr [ebx + 0x50]` @ 0x1002cfdd
- ChZhongShuD: `fld dword ptr [ebx + 0x54]` @ 0x1002cfdd

### 3.3 ChZhongShuD 核心 (0x1002cee0)

**函数签名：** 与 ChZhongShuG 同构

**关键特征：**
- 157 条指令（与 ChZhongShuG 完全相同长度）
- 1 个 x87 条件比较（与 ChZhongShuG 相同模式）
- 同样调用 `0x1003f150`

**唯一差别：**
- ChZhongShuG: `fld dword ptr [ebx + 0x50]`
- ChZhongShuD: `fld dword ptr [ebx + 0x54]`

---

## 四、族内对比

### 4.1 架构对比表

| 特征 | ChZhongShu | ChZhongShuG | ChZhongShuD |
|---|---|---|---|
| 入口地址 | 0x1000f910 | 0x1000fb10 | 0x1000fc10 |
| 公式名 | BIZHONGSHU | BIZHONGSHUG | BIZHONGSHUD |
| 中文名 | 笔中枢 | 笔中枢高点 | 笔中枢低点 |
| 授权码 | 0xEA61 | 0xEA61 | 0xEA61 |
| 被引用次数 | 10 | 5 | 5 |
| 核心 worker | 0x1002ca30 | 0x1002cd00 | 0x1002cee0 |
| worker 长度 | 109 insn | 157 insn | 157 insn |
| x87 条件数 | 0 | 1 | 1 |
| 数据偏移 | N/A | +0x50 | +0x54 |

### 4.2 共享基础设施

**共享组件：**
1. **入口框架**：三支函数使用**完全相同的序言、SEH 设置、状态检查**
2. **授权机制**：统一使用 `Authorize(0xEA61)`
3. **内存管理**：`0x1006b32c`（分配器）、`0x1006bd22`（memset）
4. **核心引擎**：`0x1003f150`（CHBI 族的核心引擎，被复用）
5. **回调函数**：`0x1006f194`（用于迭代过程中的回调）

**差异点：**
1. **核心 worker**：ChZhongShu 使用 0x1002ca30，ChZhongShuG/D 使用各自的 worker
2. **数据偏移**：ChZhongShuG 读取 +0x50，ChZhongShuD 读取 +0x54
3. **参数传递**：ChZhongShu 有额外的参数处理

### 4.3 与 CHBI 族的关系

**发现：** ChZhongShu 族**复用 CHBI 族的核心引擎**（`0x1003f150`），这表明：
- 笔中枢的计算**依赖于笔的划分**（CHBI）
- ChZhongShu 可能是在 CHBI 基础上进行中枢识别
- 这与缠论理论一致：中枢由笔构成

---

## 五、勘误与待仲裁

### 5.1 勘误

1. **初始假设修正**：最初认为 ChZhongShu 族可能完全独立，但发现其**复用 CHBI 族的核心引擎**，说明两者关系密切。

### 5.2 待仲裁项 [C]

1. **`this[+0xb0]` 的精确语义**：目前观察到它作为状态计数器，但具体含义需要进一步分析
2. **`0x1002ca30` 的具体算法**：需要逐条展开分析
3. **`0x1003f150` 的调用语义**：在 CHBI 族中是核心引擎，在 ChZhongShu 中的参数含义需要确认
4. **数据偏移 +0x50/+0x54 的结构**：需要对照容器布局确定具体字段
5. **x87 比较的上下文**：`[esp+0x1c]` 的值来源需要追踪

---

## 六、下一步建议

### 第二批目标

1. **逐条展开 `0x1002ca30`**：这是 ChZhongShu 的核心实现
2. **分析 `0x1003f150` 的调用参数**：确定 ChZhongShu 如何使用 CHBI 引擎
3. **对比 ChZhongShuG/D 的差异**：确定 +0x50/+0x54 字段的含义
4. **容器布局分析**：确定 `this[+0xb0]` 所指向的结构

### 建议工具链

```bash
# 反汇编核心函数
python disasm_func.py 0x1002ca30 --max 0x1000 --dll "D:\a_ronglide\缠中说禅\TAFLib.dll" -o chzhongshu/chlib_worker_1002ca30.txt

# 提取 x87 条件
python extract_x87_conditions.py 0x1002ca30 0x1002cb72 -o chzhongshu/cond_chlib_1002ca30.txt

# 分析 CHBI 引擎调用
python disasm_func.py 0x1003f150 --max 0x2000 --dll "D:\a_ronglide\缠中说禅\TAFLib.dll" -o chzhongshu/chlib_worker_1003f150.txt
```

---

## 七、复现命令

```bash
cd tools/re-inventory

# 反汇编三支入口函数
python disasm_func.py 0x1000f910 --max 0x700 --dll "D:\a_ronglide\缠中说禅\TAFLib.dll" -o chzhongshu/chlib_worker_1000f910.txt
python disasm_func.py 0x1000fb10 --max 0x700 --dll "D:\a_ronglide\缠中说禅\TAFLib.dll" -o chzhongshu/chlib_worker_1000fb10.txt
python disasm_func.py 0x1000fc10 --max 0x700 --dll "D:\a_ronglide\缠中说禅\TAFLib.dll" -o chzhongshu/chlib_worker_1000fc10.txt

# 反汇编核心工作函数
python disasm_func.py 0x1002ca30 --max 0x1000 --dll "D:\a_ronglide\缠中说禅\TAFLib.dll" -o chzhongshu/chlib_worker_1002ca30.txt
python disasm_func.py 0x1002cd00 --max 0x1000 --dll "D:\a_ronglide\缠中说禅\TAFLib.dll" -o chzhongshu/chlib_worker_1002cd00.txt
python disasm_func.py 0x1002cee0 --max 0x1000 --dll "D:\a_ronglide\缠中说禅\TAFLib.dll" -o chzhongshu/chlib_worker_1002cee0.txt

# 提取 x87 条件
python extract_x87_conditions.py 0x1002cd00 0x1002cecb -o chzhongshu/cond_chlib_1002cd00.txt
python extract_x87_conditions.py 0x1002cee0 0x1002d0ab -o chzhongshu/cond_chlib_1002cee0.txt
```

---

*文档生成时间：2026-10-25*
*下一批：ChZhongShu-第二批-核心算法解剖*