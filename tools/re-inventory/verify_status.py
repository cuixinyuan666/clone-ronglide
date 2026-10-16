# -*- coding: utf-8 -*-
"""
逆向任务进度自动监控 / 看板生成器

检查三类事实:
  ① 产物完整性: 每个逆向目标的分批文档 / 伪码 / 证据文件是否存在
  ② 仓库状态: 工作树是否干净, 本地 HEAD 是否已推送到远端
  ③ 清单覆盖度: 85 个受保护函数中已启动/已完成的逆向覆盖

输出: 控制台报告 + docs/19-逆向进度看板.md
用法: python verify_status.py
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))

if hasattr(sys.stdout, "reconfigure"):          # 控制台 GBK 环境下安全输出
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ---- 目标登记表: 每目标的检查项 ----
TARGETS = [
    {
        "id": "CHDUAN",
        "name": "CHDUAN 缠论线段 (EA无/借道CHBI)",
        "export": "ChDuan",
        "va": "0x1000f850",
        "batches": [
            ("第一批-定位与入口", "docs/15-CHDUAN-第一批-定位与入口.md"),
            ("第二批-准备与标记", "docs/16-CHDUAN-第二批-准备阶段与标记解码.md"),
            ("第三批-条件与决策格", "docs/17-CHDUAN-第三批-条件全表与决策格.md"),
        ],
        "artifacts": [
            "pseudocode/chduan.c",
            "tools/re-inventory/chduan/wrapper_ChDuan_1000f850.txt",
            "tools/re-inventory/chduan/engine_1002c710.txt",
            "tools/re-inventory/chduan/prepare_10053540_full.txt",
            "tools/re-inventory/chduan/conditions_10053540.txt",
        ],
        "next": "第四批: 实例②/③展开 + 标志生命周期 + 0x10053db2 深层分支",
    },
    {
        "id": "CHBI",
        "name": "CHBI 缠论笔 (EA62, P=51 门控)",
        "export": "ChBi",
        "va": "0x1000f580",
        "batches": [
            ("第一批-入口链与工作函数", "docs/18-CHBI-第一批-入口链与工作函数.md"),
            ("第二批-四函数解剖与条件格", "docs/20-CHBI-第二批-四函数解剖与条件格.md"),
            ("第三批-P51分型笔与共用后处理", "docs/21-CHBI-第三批-P51分型笔与共用后处理.md"),
            ("第四批-db40状态机与元素模板对账", "docs/22-CHBI-第四批-db40状态机与元素模板对账.md"),
            ("第五批-f170衔接与P51全链重放骨架", "docs/23-CHBI-第五批-f170衔接与P51全链重放骨架.md"),
        ],
        "artifacts": [
            "tools/re-inventory/chbi/core_1001c110.txt",
            "tools/re-inventory/chbi/core_1001c940.txt",
            "tools/re-inventory/chbi/core_1002c1d0.txt",
            "tools/re-inventory/chbi/wrapper_ChBi_1000f580.txt",
            "tools/re-inventory/chbi/f_1003db40.txt",
            "tools/re-inventory/chbi/f_1003e200.txt",
            "tools/re-inventory/chbi/f_1003eba0.txt",
            "tools/re-inventory/chbi/f_1003ef00.txt",
            "tools/re-inventory/chbi/f_1003f0d0.txt",
            "tools/re-inventory/chbi/f_1003f150.txt",
            "tools/re-inventory/chbi/f_1003f170.txt",
            "tools/re-inventory/chbi/f_1004b1e0.txt",
            "tools/re-inventory/chbi/f_1004f430.txt",
            "tools/re-inventory/chbi/f_1006a040.txt",
            "tools/re-inventory/chbi/f_1006a5e0.txt",
            "tools/re-inventory/chbi/f_1006a720.txt",
            "tools/re-inventory/chbi/f_1006b050.txt",
            "tools/re-inventory/chbi/f_1003d780.txt",
            "tools/re-inventory/chbi/f_1003d8a0.txt",
            "tools/re-inventory/chbi/cond_1003db40.txt",
            "tools/re-inventory/chbi/cond_1003e200.txt",
            "tools/re-inventory/chbi/cond_1003f170.txt",
            "tools/re-inventory/chbi/cond_1004b1e0.txt",
            "tools/re-inventory/chbi/cond_1004f430.txt",
            "tools/re-inventory/chbi/cond_1006a040.txt",
            "tools/re-inventory/chbi/db40_minij_wip.md",
            "tools/re-inventory/chbi/f170_wip.md",
            "tools/re-inventory/chbi/test_db40.py",
            "tools/re-inventory/x87_sim.py",
            "tools/re-inventory/disasm_func.py",
            "tools/wnmr_py/chbi.py",
            "tools/wnmr_py/duipai.md",
            "pseudocode/chbi.c",
        ],
        "next": "第六批(推荐): CHDUAN 第四批 — ContA/ContB 顺序敏感性 + prep 0x10053540 尾块; 备选 NChBi 启动",
    },
]

# 清单覆盖: 优先级代表函数（来自 docs/14）
PRIORITY = [
    ("ChBi", "CHBI", "EA62", "已交付(五批)"),
    ("ChDuan", "CHDUAN", "-", "已交付(三批)"),
    ("NChBi", "NCHBI", "EA62", "未启动"),
    ("NChZs", "NCHZS", "EA63", "未启动"),
    ("NChZsG", "NCHZSG", "EA61", "未启动"),
    ("NChZsBs12", "NCHZSBS12", "EA61", "未启动"),
    ("ChZhongShu", "BIZHONGSHU", "EA61", "未启动"),
    ("zsdg", "CHZSDG", "EA63", "未启动"),
    ("ZouShiBi", "ZOUSHIBI", "EA62", "未启动"),
    ("RLDOrder", "RLD_ORDER", "EA63", "未启动"),
]


def sh(cmd):
    p = subprocess.run(cmd, cwd=REPO, capture_output=True, shell=False)
    out = (p.stdout or b"").decode("utf-8", errors="replace")
    return out.strip(), p.returncode


def main():
    lines = []
    problems = []
    ok = lambda b: "✅" if b else "❌"

    lines.append("# 逆向进度看板（自动生成）\n")
    lines.append("> 生成: `tools/re-inventory/verify_status.py` ｜ 每次运行会覆盖本文件\n")

    # ① 产物检查
    lines.append("\n## 一、目标产物完整性\n")
    total_batches, done_batches = 0, 0
    for t in TARGETS:
        lines.append("\n### %s (`%s` @ `%s`)\n" % (t["name"], t["export"], t["va"]))
        lines.append("| 批次 | 文档 | 状态 |")
        lines.append("| --- | --- | --- |")
        for label, path in t["batches"]:
            total_batches += 1
            exists = os.path.exists(os.path.join(REPO, path))
            done_batches += 1 if exists else 0
            lines.append("| %s | `%s` | %s |" % (label, path, ok(exists)))
            if not exists:
                problems.append("缺少文档: " + path)
        for a in t["artifacts"]:
            exists = os.path.exists(os.path.join(REPO, a))
            lines.append("| 证据/伪码 | `%s` | %s |" % (a, ok(exists)))
            if not exists:
                problems.append("缺少证据: " + a)
        lines.append("\n> 下一步: %s\n" % t["next"])

    # ② git 状态（区分「本任务范围」与「外部/并行会话改动」）
    lines.append("\n## 二、仓库与推送状态\n")
    status, _ = sh(["git", "status", "--porcelain"])
    branch, _ = sh(["git", "rev-parse", "--abbrev-ref", "HEAD"])
    local, _ = sh(["git", "rev-parse", "HEAD"])
    remote, rc = sh(["git", "rev-parse", "origin/" + branch])
    log, _ = sh(["git", "log", "--oneline", "-8"])
    MY_SCOPE = ("docs/15-", "docs/16-", "docs/17-", "docs/18-", "docs/19-", "docs/20-", "docs/21-", "docs/22-", "docs/23-",
                "tools/re-inventory", "tools/wnmr_py",
                "pseudocode/chduan", "pseudocode/chbi", "README.md")
    tracked_mod = [l for l in status.splitlines() if not l.startswith("??")]
    untracked = [l for l in status.splitlines() if l.startswith("??")]
    mine = [l for l in tracked_mod if any(s in l for s in MY_SCOPE)]
    foreign = [l for l in tracked_mod if l not in mine]
    clean = len(mine) == 0
    pushed = local == remote
    lines.append("- 本任务范围改动: %s %s" % (ok(clean), "无" if clean else "有"))
    for m in mine:
        lines.append("    - ⚠️ %s" % m)
    lines.append("- 外部/并行改动(不参与判定): %d 个" % len(foreign))
    for m in foreign[:8]:
        lines.append("    - ℹ️ %s" % m)
    lines.append("- 未跟踪文件: %d 个（仅供参考）" % len(untracked))
    lines.append("- 本地/远端: %s %s vs origin/%s %s" % (ok(pushed), local[:8], branch, remote[:8]))
    lines.append("\n最近提交:\n```\n%s\n```\n" % log)
    if not clean:
        problems.append("本任务范围有未提交改动")
    if not pushed:
        problems.append("本地提交未推送")

    # ③ 清单覆盖
    lines.append("\n## 三、付费函数逆向覆盖（优先级 Top10）\n")
    lines.append("| 导出 | 公式名 | 授权码 | 逆向状态 |")
    lines.append("| --- | --- | --- | --- |")
    for exp, fn, code, st in PRIORITY:
        lines.append("| `%s` | %s | %s | %s |" % (exp, fn, code, st))

    # ④ 统计
    try:
        inv = json.load(open(os.path.join(HERE, "inventory.json"), encoding="utf-8"))
        n_prot = len(inv["protected"])
        n_f = len(inv["formulas"])
        n_pf = sum(1 for f in inv["formulas"] if f.get("used_prot"))
    except Exception:
        n_prot, n_f, n_pf = "?", "?", "?"
    lines.append("\n## 四、总量统计\n")
    lines.append("- 公式: **%s** 个（其中受保护 %s 个）" % (n_f, n_pf))
    lines.append("- 受保护函数: **%s** 个" % n_prot)
    lines.append("- 已交付批次: **%d/%d**" % (done_batches, total_batches))

    # 结论
    lines.append("\n## 五、监控结论\n")
    if problems:
        lines.append("**发现 %d 个问题:**\n" % len(problems))
        for p in problems:
            lines.append("- ❌ %s" % p)
    else:
        lines.append("**全部检查通过** —— 产物齐全、工作树干净、提交已推送。")

    text = "\n".join(lines)
    print(text)
    if "--write" in sys.argv:
        out = os.path.join(REPO, "docs", "19-逆向进度看板.md")
        open(out, "w", encoding="utf-8").write(text + "\n")
        print("\n[written] " + out)
    else:
        print("\n[提示] 未写文件；如需刷新看板请加 --write")
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
