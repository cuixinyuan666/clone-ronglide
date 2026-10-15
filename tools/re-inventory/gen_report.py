# -*- coding: utf-8 -*-
"""
生成 docs/14-付费功能与指标总览.md
输入: inventory.json / registry.json / auth_codes.json / taf_formulas.json
"""
import json
import re

HERE = __file__.rsplit("\\", 1)[0]
DOCS = HERE.rsplit("\\", 2)[0] + r"\docs"
TAFUNC = r"D:\a_ronglide\缠中说禅\Sys\TAFunc.xml"

inv = json.load(open(HERE + r"\inventory.json", encoding="utf-8"))
reg = inv["registry"]
tafunc = inv["tafunc"]
prot = inv["protected"]
formulas = inv["formulas"]
used_cnt = inv["used_cnt"]

# 导出 -> 公式名(可能有多个)
exp2names = {}
for k, v in reg.items():
    exp2names.setdefault(v["export"], []).append(k)

# 导出 -> 中文名 (经注册名查 TAFunc)
def cn_of(exp):
    for n in exp2names.get(exp, []):
        if n in tafunc:
            return tafunc[n]["cn"]
        # 大小写不敏感回退
        for tn, tv in tafunc.items():
            if tn.upper() == n.upper():
                return tv["cn"]
    return ""


CODE_DESC = {
    "0xEA61": "缠论扩展组(中枢/买卖点/MACD面积/区间套/各类统计)",
    "0xEA62": "缠论基础组(笔/分型/走势)",
    "0xEA63": "中枢走势与量化组(NChZs*/指数/RLDOrder/wnmr*/走势段)",
    "0xEA6B": "独立扩展器 __KZQ__",
}

lines = []
A = lines.append

A("# 融立德《缠中说禅》付费功能与指标总览（初始清单）")
A("")
A("> 生成时间：2026-10-16 ｜ 生成工具：`tools/re-inventory/`（extract_taf + scan_auth_codes + scan_registry + build_inventory）")
A("> 本文回答两件事：**① 哪些指标受授权保护（付费功能）**；**② 全部 274 个公式指标及其依赖函数**。")
A("")
A("---")
A("")
A("## 〇、方法摘要（三层交叉，全部可复现）")
A("")
A("| 层 | 数据源 | 工具 | 产物 |")
A("| --- | --- | --- | --- |")
A("| ① 公式层 | `TAF/SysTA.taf`（二进制公式库） | `extract_taf.py` | `taf_formulas.json`（**274 个公式全解**） |")
A("| ② 授权层 | `TAFLib.dll` 全部 `Authorize(code)` 调用点 | `scan_auth_codes.py`（capstone） | `auth_codes.json`（**87 调用点 / 85 函数 / 4 个授权码**） |")
A("| ③ 映射层 | `.data` 注册表（指针表+名字表） | `scan_registry.py` | `registry.json`（**274 个公式名 → 268 个实现导出** 权威映射） |")
A("")
A("> 关键突破：在 `TAFLib.dll` 的 `.data` 段找到公式引擎的**函数注册表**——")
A("> 名字表（`name` 32B 字段）与指针表（`[seq][fn_ptr]`）以 `name.id + 1 == ptr.seq` 关联，")
A("> 从而拿到公式名（如 `BIZHONGSHU`）→ 实现导出（`CalcProc_ChZhongShu`）的权威对应关系，")
A("> 再与授权扫码交叉，得出**逐函数的付费属性**。")
A("")
A("---")
A("")
A("## 一、授权体系与授权码目录")
A("")
A("保护模式（实测某函数入口）：")
A("```asm")
A("push  0xEA63            ; 授权码")
A("mov   ecx, <this>")
A("call  0x10014e60        ; ?Authorize@TAF_Calculator@@IAE_NI@Z")
A("test  al, al")
A("jne   <继续执行>        ; 未授权 → 直接返回空/0（指标无输出）")
A("```")
A("")
bycode = inv["bycode"]
A("| 授权码 | 受保护函数数 | 组语义（依函数集归纳） | 典型函数 |")
A("| --- | --- | --- | --- |")
for c in ("0xEA61", "0xEA62", "0xEA63", "0xEA6B"):
    ks = bycode.get(c, [])
    sample = "、".join(f"`{k}`" for k in ks[:6])
    A("| `%s` | %d | %s | %s |" % (c, len(ks), CODE_DESC.get(c, ""), sample))
A("")
A("> 另有 5 个函数一函数多码：`NChZs_L2`（EA62+EA63）、`dzstj`（EA61+EA63）、`kxqj`（EA61×3）、`Zstj`/`kxqjg`（EA61×2）。")
A("")
A("### 受保护函数全表（85 个）")
A("")
A("| # | 导出函数 | 公式名 | 中文名(白皮书) | 授权码 | 被公式引用次数 | 地址 |")
A("| --- | --- | --- | --- | --- | --- | --- |")
for i, (exp, info) in enumerate(
    sorted(prot.items(), key=lambda x: (x[1]["codes"], -used_cnt.get(x[0], 0))), 1
):
    names = "/".join(exp2names.get(exp, [])) or "?"
    cn = cn_of(exp) or "—"
    A(
        "| %d | `%s` | %s | %s | %s | %d | `%s` |"
        % (
            i,
            exp,
            names,
            cn,
            ",".join(info["codes"]),
            used_cnt.get(exp, 0),
            info["va"],
        )
    )
A("")
A("> **28 个受保护函数在系统公式库中无任何公式引用**（多为旧版或被 UI 直调）：")
A("> " + "、".join(
    f"`{k}`" for k in sorted(set(prot) - {u for f in formulas for u in f.get('used_prot', [])})
))
A("")
A("---")
A("")
A("## 二、全部指标（公式）清单：274 个")
A("")
n_prot = sum(1 for f in formulas if f["used_prot"])
A("其中 **%d 个公式依赖受保护函数**（即实际意义上的付费指标）。按分类统计：" % n_prot)
A("")
from collections import Counter

cat_cnt = Counter(f["category"] for f in formulas)
cat_prot = Counter(f["category"] for f in formulas if f["used_prot"])
A("| 分类 | 公式数 | 其中受保护 |")
A("| --- | --- | --- |")
for c, n in sorted(cat_cnt.items(), key=lambda x: -x[1]):
    A("| %s | %d | %d |" % (c, n, cat_prot.get(c, 0)))
A("")
A("### 逐公式明细（274）")
A("")
A("| # | 公式名 | 标题 | 分类 | 受保护 | 授权码 | 关键依赖函数 |")
A("| --- | --- | --- | --- | --- | --- | --- |")
for i, f in enumerate(formulas, 1):
    dep = "、".join(f"`{u}`" for u in f["used_prot"][:8]) or "—"
    if len(f["used_prot"]) > 8:
        dep += " …"
    A(
        "| %d | `%s` | %s | %s | %s | %s | %s |"
        % (
            i,
            f["name"],
            f["title"].replace("|", "/"),
            f["category"],
            "✅" if f["used_prot"] else "",
            ",".join(f["codes"]),
            dep,
        )
    )
A("")
A("---")
A("")
A("## 三、缠论菜单 ↔ 公式 对照（推断）")
A("")
A("`Sys/Mainmenu.xml` 缠论菜单 16 项。命令号→公式的硬编码表在主程序内（待后续逆向确认），")
A("下表为按语义与既有结论的推断：")
A("")
A("| CmdId | 菜单 | 对应公式/功能 | 相关受保护函数 |")
A("| --- | --- | --- | --- |")
menu = [
    ("4421", "分笔", "`分型笔与老笔`/`CHBI` 系", "ChBi, ChFxbi"),
    ("4410", "分段", "`走势分解_线段` 系", "ChDuan"),
    ("4414", "动力共振", "`CHFB`/`动能轨迹`", "—"),
    ("4411", "笔中枢", "`CHBZS`/`笔中枢`", "ChZhongShu*"),
    ("4412", "段中枢", "`CHDZS`", "Chdzhongshu*"),
    ("4418", "3级别MACD", "`MACD1/2/3`", "Macdnum"),
    ("4424", "3周期联动", "—", "—"),
    ("4427", "多级联立", "`RLD_BS_多级联立BS`", "NChZs*, RLDOrder"),
    ("4429", "一根筋", "`RLD_BS_一根筋`", "NChZs*, RLDOrder"),
    ("4432", "走势分解笔", "`走势分解_笔`/`N走势分解_笔`", "ChBi, ZouShiBi"),
    ("4415", "走势分解线段", "`走势分解_线段`/`N走势分解_线段`", "ChDuan, ZouShiBi"),
    ("4430", "无脑买入笔", "`WNMR_笔`", "wnmrnew"),
    ("4431", "无脑买入线段", "`WNMR_线段`（已逆向）", "wnmrnew"),
    ("4441", "磨刀系统", "`RLD_BS策略A-3/B-3/C-3/E-3`", "NChZs*, RLDOrder"),
    ("4445", "龙系战法", "`困龙得水/蛟龙出海/盘龙再起(A/B)`", "NChZs*, NChBi*"),
]
for cmd, cap, form, fn in menu:
    A("| %s | %s | %s | %s |" % (cmd, cap, form, fn))
A("")
A("---")
A("")
A("## 四、下一步：逐指标逆向候选顺序")
A("")
A("依「被引用次数 × 基础性」排序，建议逆向顺序：")
A("")
top = sorted(prot.items(), key=lambda x: -used_cnt.get(x[0], 0))[:15]
A("| 优先级 | 函数 | 公式名 | 中文名 | 被引用 | 授权码 |")
A("| --- | --- | --- | --- | --- | --- |")
for i, (exp, info) in enumerate(top, 1):
    A(
        "| P%d | `%s` | %s | %s | %d | %s |"
        % (i, exp, "/".join(exp2names.get(exp, [])), cn_of(exp) or "—", used_cnt.get(exp, 0), ",".join(info["codes"]))
    )
A("")
A("> 其中 `ChBi`(→`CHBI`) 已有前期产物（docs/04、05），可作为模板；")
A("> 建议首个新目标 = **`ChDuan`（`CHDUAN` 线段划分）**，它是「无脑买入线段」「走势分解线段」的直接上游。")
A("")
A("---")
A("")
A("## 五、复现命令")
A("")
A("```bash")
A("cd tools/re-inventory")
A("python extract_taf.py -o taf_formulas.json        # 274 公式")
A("python scan_auth_codes.py -o auth_codes.json      # 87 授权调用点")
A("python scan_registry.py -o registry.json          # 274 名字->实现映射")
A("python build_inventory.py                         # 合并 inventory.json")
A("python gen_report.py                              # 生成本文档")
A("```")
A("")
A("> 免责声明：本仓库仅用于技术学习与安全研究，分析对象为本人合法安装的软件；")
A("> 所有内容为静态分析结果，未涉及软件破解、绕过授权或任何商业用途。")

out = DOCS + r"\14-付费功能与指标总览.md"
open(out, "w", encoding="utf-8").write("\n".join(lines))
print("written", out, len(lines), "lines")
