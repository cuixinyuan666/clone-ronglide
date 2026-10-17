# -*- coding: utf-8 -*-
"""x87_sites.py — 站点级 x87 比较抽取（配合 extract_x87_conditions 的补充：
本工具不做 fld 配对猜测，只按 "fcom/fcomp 站点 + 后续 test ah,MASK + jcc" 出表，
由人工按 Intel 语义解码，避免 fild/fstp 干扰）。"""
import re, sys
FILES = [("Fj 0x10005020", "chlib_10005020.txt", 0x10005020, 0x1000515d),
         ("Dg 0x10005160", "chlib_10005160.txt", 0x10005160, 0x10005467),
         ("HLTurn 0x10005480", "chlib_10005480.txt", 0x10005480, 0x100057fe)]
MASK = {0x41: "C3|C0", 0x05: "C2|C0", 0x01: "C0", 0x45: "C3|C2|C0", 0x44: "C3|C2"}
for name, fn, lo, hi in FILES:
    rows = []
    for line in open(fn, encoding="utf-8", errors="replace"):
        m = re.match(r"^([0-9a-f]{8})\s+(.*)$", line.rstrip("\n"))
        if not m: continue
        a = int(m.group(1), 16)
        if not (lo <= a <= hi): continue
        rows.append((a, m.group(2).strip()))
    print("=" * 76)
    print("## %s  (%d 行)" % (name, len(rows)))
    sites = [(i, a, b) for i, (a, b) in enumerate(rows) if re.match(r"^fcom", b)]
    if not sites:
        print("   **无任何 fcom/fcomp 站点** ⇒ 该函数不需要浮点比较（只有整数↔double 转换）")
    for i, a, b in sites:
        print("-- 站点 0x%08x : %s" % (a, b))
        for j in range(max(0, i - 3), min(len(rows), i + 4)):
            pre = "  >>" if j == i else "    "
            print("%s %08x  %s" % (pre, rows[j][0], rows[j][1]))
