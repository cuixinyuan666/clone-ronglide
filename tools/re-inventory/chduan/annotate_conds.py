#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""annotate_conds.py — 给 conditions_10053540.txt 加「实例区域 + 缓存槽」标注

把每条 x87 条件按**地址区间**归入实例 ①/②/③/④/标记阶段，并把 operand 里的
`[esp+0xNN]` 翻译成命名缓存槽（见 §栈缓存槽图：A/0x68、B/0x90、C/0xd0、D/0xf8）。

用法：python annotate_conds.py <conditions.txt> [-o out.txt]
"""
import re
import sys

# 实例区域（起, 止, 名称）
REGIONS = [
    (0x100535d2, 0x10053e17, "①(m[2])"),
    (0x10053e18, 0x1005467b, "②(m[3])"),
    (0x1005467c, 0x10055098, "③"),
    (0x10055099, 0x10055b8b, "④"),
    (0x10055b8c, 0x10055fff, "标记/tail"),
]

# esp 槽 → 语义名
SLOTS = {
    0x68: "cacheA", 0x74: "cacheA.H", 0x78: "cacheA.L",
    0x90: "cacheB", 0x9c: "cacheB.H", 0xa0: "cacheB.L",
    0xd0: "cacheC", 0xdc: "cacheC.H", 0xe0: "cacheC.L",
    0xf8: "cacheD", 0x104: "cacheD.H", 0x108: "cacheD.L",
    0x14c: "n", 0x58: "n_save", 0x5c: "idx_lo", 0x14: "cur_iter",
    0x18: "cur_m2", 0x1cc: "W", 0x128: "price_tmp", 0x158: "price_tmp2",
    0x64: "price_tmp3", 0x34: "iterpair.lo", 0x38: "iterpair.hi",
    0x120: "inner_iter", 0x54: "sgn", 0x40: "pub_idxA?",
}


def region(addr):
    for lo, hi, name in REGIONS:
        if lo <= addr < hi:
            return name
    return "?"


def annotate_esp(text):
    def rep(m):
        off = int(m.group(1), 16)
        nm = SLOTS.get(off)
        return "[%s]" % (nm if nm else "esp+0x%x" % off)
    return re.sub(r"\[esp \+ (0x[0-9a-f]+)\]", rep, text)


def main():
    src = sys.argv[1]
    out = None
    dis = None
    if "-o" in sys.argv:
        out = sys.argv[sys.argv.index("-o") + 1]
    if "--dis" in sys.argv:
        dis = sys.argv[sys.argv.index("--dis") + 1]
    # 建「下一条指令地址」表（用于推算落空目标）
    nxt = {}
    if dis:
        addrs = []
        for ln in open(dis, encoding="utf-8", errors="replace"):
            m = re.match(r"^([0-9a-f]{6,8})\s", ln)
            if m:
                addrs.append(int(m.group(1), 16))
        for i, a in enumerate(addrs[:-1]):
            nxt[a] = addrs[i + 1]
    lines = []
    for ln in open(src, encoding="utf-8", errors="replace"):
        ln = ln.rstrip("\n")
        if not ln.strip():
            continue
        m = re.match(r"^([0-9a-f]{6,8})\s+(.*)$", ln)
        if not m:
            continue
        addr = int(m.group(1), 16)
        body = annotate_esp(m.group(2))
        tail = ""
        jt = re.search(r";\s*j[a-z]+\s+(0x[0-9a-f]+)", body)
        if jt and nxt.get(addr) is not None:
            tail = "   落空→0x%08x" % nxt[addr]
        lines.append("%s  [%s]  %s%s" % (m.group(1), region(addr), body, tail))
    text = "\n".join(lines) + "\n"
    if out:
        open(out, "w", encoding="utf-8").write(text)
        print("wrote %s (%d conds)" % (out, len(lines)))
    else:
        print(text)


if __name__ == "__main__":
    main()
