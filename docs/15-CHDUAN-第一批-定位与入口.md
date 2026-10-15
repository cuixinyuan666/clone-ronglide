# CHDUAN（缠论线段）逆向 · 第一批 —— 定位与入口

> 日期：2026-10-16 ｜ 分支 `old1`
> 目标：公式函数 `CHDUAN`（缠论线段，白皮书：「返回值=-1 特征序列底分型 / 1 特征序列顶分型，调用前必须先调用 CHBI」）
> 方法：注册表定位 → 包装层反汇编 → 调用图归属 → 引擎体结构解析
> 证据文件：`tools/re-inventory/chduan/`（wrapper/ctx/engine/snapshot 反汇编 + 消费者清单）

---

## 一、定位链（三层证据）

| 层 | 证据 | 结果 |
| --- | --- | --- |
| 公式名 | `.data` 名字表记录（name@0x80fd0） | `CHDUAN` → id `0x4A0` |
| 指针表 | `[seq][fn_ptr]` 对（seq = id+1 = `0x4A1`） | → fn_ptr `0x1000F850` |
| 导出表 | `?CalcProc_ChDuan@TAF_Calculator@@IAE_NIPANQAPAN@Z` | VA `0x1000f850` ✓ |

- 注册表 seq = **1185**，位于缠论函数段（`CHBI`=1183、`FXBI`=1184、`CHDUAN`=1185、`BIZHONGSHU`=1186…）。
- `CalcProc_ChDuan` 在授权扫描中**无任何 `Authorize` 调用点**（权威结论，见第四节）。

---

## 二、包装层（`0x1000f850`，共 50 条指令）

关键结构（完整注释版见 `chduan/wrapper_ChDuan_1000f850.txt`）：

```asm
1000f873  mov  edi, ecx              ; edi = TAF_Calculator* this
1000f875  cmp  dword ptr [edi+0xb0], 0
1000f87c  jne  0x1000f8b1            ; 惰性初始化 [this+0xB0] 上下文句柄
1000f87e  push 4 / call new          ; 4 字节句柄对象
1000f89a  call 0x1002c160            ; 句柄构造: new(0xC8) + W 构造(0x1003d910) → 句柄[0]=W*
1000f8ab  mov  dword ptr [edi+0xb0], eax
...
1000f8b1  push 4 / call new          ; 4 字节参数包装对象 {vtable=0x1006f708}
1000f8cb  call dword ptr [0x1006f190]; 运行库间接调用(辅助)
1000f8d9  push esi                   ; 参数包装对象
1000f8da  push eax                   ; 函数第 3 参数
1000f8db  mov  eax, [edi+0xb0]       ; eax = 上下文句柄
1000f8e1  call 0x1002c710            ; ★ CHDUAN 引擎体 (唯一调用者)
1000f8e6..  虚析构 esi
1000f8f4  mov  al, 1                 ; 返回 true
```

**要点**：

1. `[this+0xB0]` = 惰性创建的**通道上下文句柄**（4 字节；`句柄[0] = W*`）。所有 `CalcProc_Ch*` 包装层共用此模式（46 处调用 `0x1002c160`）。
2. `0x1002c160`（句柄构造）：`new(0xC8)` → `call 0x1003d910`（**W 的构造函数**，文档 06/07 已还原：零化 8 个 vector 成员）→ `句柄[0]=W*`。
3. CHDUAN 包装层**不构建任何输入对象**、不做 `Authorize`、不做数据准备——它只做「取上下文 → 调引擎」。

---

## 三、引擎体 `sub_1002c710`（唯一调用者 = CHDUAN 包装层 @`1000f8e1`）

体量 113 条指令（`chduan/engine_1002c710.txt`），流程：

```
sub_1002c710(ecx=count, eax=上下文句柄, [ebp+8]=out 数组, [ebp+0xc]=包装对象)
  if (count <= 0) return;  if ([ebp+0xc] == 0) return
  W = 句柄[0]                              ; mov edi,[eax]
  call 0x10053540(W)                       ; ★ 准备阶段（见 §3.2）
  快照 = 拷贝构造(W)                        ; 0x1003f150 → 0x1006a4e0(vector 拷贝构造)
                                           ;   因 m[0] 位于 W+0x00，按 W 指针拷贝 = 拷贝 W->m[0]
  memset(out, 0, count*8)                  ; rep stosd：out 为 double 数组
  for (it = 快照.begin; it != 快照.end; it += 0xA0)      ; 步长 160 = sizeof(级别对象)
      pos   = it->[0x00] - 1               ; 1 基 → 0 基      （与文档 11「+0x00 为 1 基」吻合）
      value = it->[0x24]                    ; ★ 新字段：分型/线段标记值（int）
      if (cursor < pos) memset(out+cursor, 0, (pos-cursor)*8)
      out[cursor++] = (double)value         ; fild + fstp qword（x87 转换）
  释放快照; return 0
```

### 3.1 输出语义

- **输出 = 按 bar 展开的 double 数组**：`out[item[+0x00]-1] = (double)item[+0x24]`，空隙填 0。
- 这解释了公式侧 `VAR2:=CHDUAN;` 直接得到逐 K 线的 ±1 序列。
- **新字段发现**：`级别对象 +0x24` 在 CHDUAN 引擎中作为**标记值**被读取（文档 12 曾结论「+0x24 在 wnwr 引擎从不出现」——现已证明该字段存在且另有用途：**CHDUAN 专用**）。

### 3.2 准备阶段 `sub_10053540`（待深挖，第二批主题）

- `[ebx+8]-[ebx+4]`（= `W->m[0]._Mylast - _Myfirst`）**÷160**（魔数 `0x66666667 sar 6`）得元素数；`<= 0x15`（21）时直接返回 —— 即「级别对象数不足 21 → 什么都不做」。
- 体量 >0x1B8 栈空间，含大量安全 STL 检查（`_invalid_parameter_noinfo` @ `ds:[0x1006F194]`），为**特征序列/线段状态的主要加工点**。
- **判定**：`sub_1002c710` = 「准备(0x10053540) + 按 bar 展开输出」两段式；线段划分的**增量状态**在 `0x10053540` 内维护。

---

## 四、授权结论（重要修正）

### 4.1 CHDUAN 自身免疫授权检查

- 87 个 `Authorize` 调用点中**没有 `CalcProc_ChDuan` 的任何调用点**。
- CHDUAN 包装层与引擎体（`0x1002c710`）中均无 `push code; call 0x10014e60` 模式。

### 4.2 真正的门在 CHBI（且仅 P=51 才查）

`CalcProc_ChBi`（`0x1000f580`）包装层实测：

```asm
1000f5ec  mov  ecx, [eax+8]        ; 第 3 参数(级别对象)
1000f5ef  fld  qword ptr [ecx]     ; 取 P
1000f5f1  call 0x1006bc70          ; 转 int
1000f5f6  cmp  eax, 0x33           ; P == 51 (分型笔) ?
1000f5f9  jne  0x1000f63b          ; P≠51 → 直接放行（不查授权）
1000f5fb  push 0xea62              ; P==51 → Authorize(0xEA62)
1000f600  mov  ecx, edi
1000f602  call 0x10014e60
1000f607  test al, al
1000f609  jne  0x1000f63b          ; 已授权 → 继续
1000f60b  ...                      ; 未授权 → 清空输出并 return false
```

> **结论**：`CHBI(..., P=51)`（分型笔，白皮书标注「高级版以上支持」）才需要 EA62 授权；
> `P=11/12`（老笔/新笔）不需要。而 **CHDUAN 完全无鉴权，但依赖 CHBI 运行后产生的 `W` 状态**——
> 未授权时 CHBI(P=51) 产出空状态，CHDUAN 输出全 0，构成「**状态依赖式间接保护**」。
> 这是一条对「付费功能清单」的重要细化：**按参数分流鉴权**（同一导出，不同参数授权口径不同）。

---

## 五、公式消费者（23 个，来自 inventory）

`CHDZS`、`走势分解_线段`、`分型笔段`、`CHD一买/二买/三买`、`CHD一卖/二卖/三卖`、`FBFD`、
`FBFD_TZXL`、`FBFD_薛斯通道`、`MACD段面积`、`段中枢统计`、`WNMR_走势类型`、`WNMR_线段`、
`走势分解_5F_SR/S/R`、`走势分解_1F_W/S`、`线段标注`、`走势分解标注`

> 其中 `WNMR_线段`（已逆向的「无脑买入线段」）的输入 `VAR2:=CHDUAN` —— 本函数即它的**直接上游**。

---

## 六、交叉验证（与既有文档）

| 既有结论 | 本次吻合点 |
| --- | --- |
| 文档 06/07：W = 8 个内嵌 vector 的容器，W 构造器 `0x1003d910` | 句柄构造 `0x1002c160` = `new(0xC8)+0x1003d910` ✓ |
| 文档 11：级别对象 `+0x00` 为 **1 基** | 引擎 `sub [ebx],1` 转 0 基 ✓ |
| 文档 12：`+0x24` 在 wnwr 引擎从不出现 | 本引擎读取 `+0x24` → 字段用途补全 ✓ |
| 文档 06：`sub_1003f150` = 容器快照 | 引擎经 `0x1003f150→0x1006a4e0` 拷贝 W->m[0] ✓ |

---

## 七、第二批计划（下一 commit）

1. **解剖 `sub_10053540`**（>400 行）：定位 `W->m[0]`/`W->m[4]`/`W->m[5]` 的读写点，还原「特征序列 → 线段终点」状态机。
2. 追踪 `+0x24` 的**写入方**（应为 `0x10053540` 或其子调用），闭环「谁写标记 → 谁读标记」。
3. 输出 `pseudocode/chduan.c`（第三批），并对照 `CHD` 系列公式（CHD一买/二买/三买）做语义校验。

> 免责声明：仅供技术学习与安全研究，分析对象为本人合法安装软件；未涉及破解或授权绕过。
