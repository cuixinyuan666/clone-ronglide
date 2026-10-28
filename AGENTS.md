# AGENTS.md — 任务前必读入口

> **任何新会话/新任务开始前，必须先读 [summary.md](summary.md)**（错误与经验教训 + 已验证技术事实 + 当前状态 + 下一步）。`Agent.md` 与本文件是同一文件（Windows 大小写不敏感）。

## 必读顺序

1. `summary.md` —— 全量背景与教训（§2 已验证事实、§3 错误教训、§4 状态、§5 下一步）。
2. 与任务相关的证据文件（反汇编在 `tools/re-inventory/chbi/`）。
3. 客户端逆向文档（GBK，先转码）：`D:\a_ronglide\缠中说禅\re-MainApp.md`、`re-TAFLib.md`。

## 仓库结构

- `ronglide-app/` —— 客户端应用分析
- `tools/wnmr_py/` —— **当前主战场**：x86 模拟器、frida 脚本、对拍工具
- `tools/re-inventory/` —— 反汇编证据与提取产物
- `docs/`、`pseudocode/` —— 文档与伪代码
- `summary.md` —— 错误与经验教训日志（**随时更新**）

## 环境速查

- Python：`C:\Users\Administrator\Documents\a_conda\python.exe`（长跑加 `-u`；PowerShell 用 `& "..."` 调用）
- frida 17.23.3；32 位客户端需 32 位 agent
- 客户端：`D:\a_ronglide\缠中说禅`（32 位、GBK、**离线**，服务器 TCP 拒连）
- 临时目录：`C:\Users\Administrator\AppData\Local\Temp\opencode\`
- 数据集：`D:\a_ronglide\缠中说禅\Dat\His\02\1\600000.1`（58560 根）

## 常用命令

```powershell
# 模拟器全量/限量重放
& "C:\Users\Administrator\Documents\a_conda\python.exe" -u chbi51.py --replay "D:\a_ronglide\缠中说禅\Dat\His\02\1\600000.1" [--max-bars 200] [--use-c1d0] [--dump-json out.json]

# 对拍（自测）
& "C:\Users\Administrator\Documents\a_conda\python.exe" -u dupai.py

# 原生执行（须先确认无 MainApp 实例）
& "C:\Users\Administrator\Documents\a_conda\python.exe" -u frida_native_run.py ...
& "C:\Users\Administrator\Documents\a_conda\python.exe" -u frida_native_host.py ...

# 全量验证（对拍）——当前已全通：58560 双入口 0 diff
#   注意：验证必须零插桩（frida_native_call.js 顶部 QUIET=true，勿开 attach 探针）
#   结果 dump：tools\wnmr_py\dumps\chbi_native_{c1d0,c4b0}_{N}.json
```

> 工作目录均为 `tools\wnmr_py\`。

## 更新规约（强制）

1. 任务中出现**任何错误、踩坑、教训、新事实** → 立即追加到 `summary.md` §3 / §2，不要等任务结束。
2. 任务结束 → 更新 `summary.md` §4（状态）、§5（下一步）。
3. 条目要具体：路径、地址、字节、命令、错误原文。

## 禁止事项

- 勿杀进程：1304/16724（mul-agent orchestrator，用户自用）、9112/11388/12408/16792（freellmapi 系统服务）。
- 勿在客户端 GUI 上点击"删除"（1410,469）；GUI 数据路径已证实死路，非必要不碰。
- 未获用户明确要求不提交 git。
