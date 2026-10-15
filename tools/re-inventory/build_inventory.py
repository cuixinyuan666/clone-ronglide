# -*- coding: utf-8 -*-
"""
付费功能与指标总清单构建器

输入:
  - TAFLib.dll 导出表 (pefile)
  - auth_codes.json   (scan_auth_codes.py 产物)
  - taf_formulas.json (extract_taf.py 产物)
  - Sys/TAFunc.xml    (函数白皮书)
输出:
  - inventory.json    合并清单
  - 控制台统计 + 生成 docs/14-付费功能与指标总览.md 的数据段(由调用方拼装)
"""
import json
import re
import sys

import pefile

DLL = r"D:\a_ronglide\缠中说禅\TAFLib.dll"
TAFUNC = r"D:\a_ronglide\缠中说禅\Sys\TAFunc.xml"
HERE = __file__.rsplit("\\", 1)[0]


def load_exports():
    pe = pefile.PE(DLL, fast_load=True)
    pe.parse_data_directories(
        [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
    )
    base = pe.OPTIONAL_HEADER.ImageBase
    out = {}
    for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if not e.name:
            continue
        n = e.name.decode()
        m = re.match(r"\?(_?)CalcProc_(\w+)@", n)
        if m:
            out[m.group(2)] = {  # 原始大小写名
                "underscore": bool(m.group(1)),
                "va": "0x%x" % (base + e.address),
            }
    return out


def parse_tafunc():
    src = open(TAFUNC, encoding="utf-8", errors="replace").read()
    reg = {}
    # 按 Category 切分
    cur_cat = None
    for m in re.finditer(r'<Category N="([^"]+)"|<Func\s+F="([^"]+)"\s+N="([^"]*)"\s+P="([^"]*)"', src):
        if m.group(1):
            cur_cat = m.group(1)
        else:
            reg[m.group(2)] = {"cn": m.group(3), "p": m.group(4), "cat": cur_cat}
    return reg


def tokenize(src: str):
    # 去注释 {..} 与 /*..*/
    s = re.sub(r"\{[^}]*\}", " ", src)
    s = re.sub(r"/\*.*?\*/", " ", s, flags=re.S)
    return set(t.upper() for t in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", s))


def main():
    exports = load_exports()
    auth = json.load(open(HERE + r"\auth_codes.json", encoding="utf-8"))
    formulas = json.load(open(HERE + r"\taf_formulas.json", encoding="utf-8"))
    tafunc = parse_tafunc()
    registry = json.load(open(HERE + r"\registry.json", encoding="utf-8"))  # 公式名->导出

    # 保护函数表: 导出名 -> codes
    prot = {}
    for full, info in auth.items():
        m = re.match(r"\?(_?)CalcProc_(\w+)@", full)
        if not m:
            continue
        codes = sorted(set(a["code"] for a in info["auth"] if a["code"]))
        prot[m.group(2)] = {"codes": codes, "va": info["va"]}

    # 公式名(大写) -> 导出名;  导出名(原样) -> 公式名列表
    up2exp = {k.upper(): v["export"] for k, v in registry.items()}
    exp2up = {}
    for k, v in registry.items():
        exp2up.setdefault(v["export"], []).append(k)
    # 未被登记但存在的导出(兜底 token 匹配)
    all_exports_up = {k.upper(): k for k in exports}

    def resolve(tok):
        """token(大写) -> 导出名 或 None"""
        if tok in up2exp:
            return up2exp[tok]
        if tok in all_exports_up:
            return all_exports_up[tok]
        return None

    # 公式 -> 使用函数
    used_cnt = {}
    for f in formulas:
        toks = tokenize(f["source"])
        used = sorted(set(r for r in (resolve(t) for t in toks) if r))
        used_prot = sorted(set(u for u in used if u in prot))
        f["used"] = used
        f["used_prot"] = used_prot
        f["codes"] = sorted(set(c for u in used_prot for c in prot[u]["codes"]))
        for u in used:
            used_cnt[u] = used_cnt.get(u, 0) + 1

    # 统计
    n_prot_f = sum(1 for f in formulas if f["used_prot"])
    print("formulas:", len(formulas), " protected:", n_prot_f)
    print("protected exports:", len(prot))
    never = [k for k in prot if used_cnt.get(k, 0) == 0]
    print("protected exports never used by any formula:", len(never))
    for k in sorted(never):
        print("   -", k, prot[k]["codes"])

    # 全保护函数按 code 分组(带中文名/被引次数)
    from collections import defaultdict

    bycode = defaultdict(list)
    for k, v in prot.items():
        for c in v["codes"]:
            bycode[c].append(k)
    for c in sorted(bycode):
        ks = bycode[c]
        print("code %s: %d funcs" % (c, len(ks)))

    inv = {
        "exports": exports,
        "protected": prot,
        "formulas": formulas,
        "tafunc": tafunc,
        "registry": registry,
        "used_cnt": used_cnt,
        "bycode": {c: sorted(v) for c, v in bycode.items()},
    }
    json.dump(inv, open(HERE + r"\inventory.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("written inventory.json")

    # 受保护函数使用频次 top
    print("\nTop protected used by formulas:")
    for k, c in sorted(
        ((k, used_cnt.get(k, 0)) for k in prot), key=lambda x: -x[1]
    )[:25]:
        print("  %-14s %-6s %d" % (k, ",".join(prot[k]["codes"]), c))


if __name__ == "__main__":
    main()
