# REA（Reverse Engineering Assistant）使用记录与交叉验证

> 工具：`D:\1\a_rea\`（Rust 源码 v4.0.0；本地构建产物
> `D:\1\a_rea\target\x86_64-pc-windows-gnu\release\rea.exe`，另有 `releases\rea-v1.0.0-x86_64-windows.exe`）
> 环境：2026-10-16，分析目标 `TAFLib.dll`（32位 PE，SHA-256 `d277f1b6…ef9b588`）

## 一、可用命令（实测）

| 命令 | 结果 | 留档 |
| --- | --- | --- |
| `rea info TAFLib.dll` | ✅ 正常（格式/熵/哈希/缓解措施；SHA-256 与 README 一致） | 本文 §二 |
| `rea strings TAFLib.dll` | ✅ 正常（3306 条字符串 + 4 条 indicator） | `rea_strings.txt` |
| `rea xrefs TAFLib.dll 0x1002c710` | ⚠️ **误报**（见 §三） | — |
| `rea decompile TAFLib.dll <sym|addr>` | ⚠️ 地址映射异常（"Address: 0x1000"） | — |

## 二、关键发现（rea strings 摘取）

```
[Windows path] d:\RLD\pro\RNF_X\release\TAFLib.pdb
```

—— **原厂构建机 PDB 路径**：`d:\RLD\pro\RNF_X\release\`。
证实 TAFLib.dll 由融立德（RLD）自建工程 `RNF_X` 编译，调试符号未随发布（仅路径残留）。

## 三、交叉验证与勘误（重要）

对 `sub_1002c710`（CHDUAN 引擎体）查 xrefs：

- **rea 结果**：`0x1006b798 -> call 0x1002c710`（仅 1 条）
- **capstone 全文本扫描**：唯一调用点 = `0x1000f8e1`（ChDUAN 包装层，docs/15 已证）
- **仲裁**：逐字节未对齐复核——
  - `0x1006b798` 实为 CRT 入口，指令序列为 `cmp [esp+8],1 / jne / call 0x1006bbb4 / …`
    **并无对 0x1002c710 的调用** → rea 误报；
  - `0x1000f8e1: call 0x1002c710` 逐字节确证 ✅

结论：**本版 rea（GNU 构建）对 32 位 PE 的 VA 处理存在缺陷**（xrefs 误报、
decompile 地址落回 `0x1000`）。本项目逆向仍以自建 capstone 工具链为基准；
rea 用于 `info`/`strings` 层面的快速侦察与哈希比对。

## 四、复现命令

```bash
REA="D:/1/a_rea/target/x86_64-pc-windows-gnu/release/rea.exe"
"$REA" info    "D:\a_ronglide\缠中说禅\TAFLib.dll"
"$REA" strings "D:\a_ronglide\缠中说禅\TAFLib.dll"
```
