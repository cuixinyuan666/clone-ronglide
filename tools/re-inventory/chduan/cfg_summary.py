#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""cfg_summary.py — 从反汇编文本构建基本块 CFG 摘要（CHDUAN 第四批工具）

用途：快速给出「基本块 + 出边（含条件）」清单，辅助实例边界划分与语义串整理。
输入：disasm_func.py / 线性反汇编产出的文本，格式 `<8位hex>  <mnemonic>  <operands>`。
仅解析「块内最后一条为分支」的边；call 不打断基本块（与 x87_sim.py 口径一致）。

用法：
    python cfg_summary.py <file.txt> [--entry 0x10053540] [--out out.txt] [--limit N]
"""
import re
import sys

LINE = re.compile(r"^([0-9a-fA-F]{6,8})\s+(\S+)\s*(.*)$")
JCC = re.compile(r"^j(?!mp$)[a-z]+$")


def parse(path):
    insns = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for ln in f:
            m = LINE.match(ln.strip())
            if not m:
                continue
            addr = int(m.group(1), 16)
            op = m.group(2).lower()
            arg = m.group(3).strip()
            insns.append((addr, op, arg))
    return insns


def target(arg):
    m = re.match(r"^(0x[0-9a-fA-F]+)", arg.strip())
    return int(m.group(1), 16) if m else None


def blocks(insns, entry):
    idx = {a: i for i, (a, _, _) in enumerate(insns)}
    leaders = {entry}
    for i, (a, op, arg) in enumerate(insns):
        last = (i == len(insns) - 1)
        if op == "ret" or op.startswith("ret"):
            if not last:
                leaders.add(insns[i + 1][0])
            continue
        if op == "jmp":
            t = target(arg)
            if t is not None:
                leaders.add(t)
            if not last:
                leaders.add(insns[i + 1][0])
            continue
        if JCC.match(op):
            t = target(arg)
            if t is not None:
                leaders.add(t)
            if not last:
                leaders.add(insns[i + 1][0])
    starts = sorted(a for a in leaders if a in idx)
    out = []
    for si, s in enumerate(starts):
        e = idx[s]
        # 块尾 = 下一个 leader 或函数末尾
        nxt = idx[starts[si + 1]] if si + 1 < len(starts) else len(insns)
        body = insns[e:nxt]
        last = body[-1]
        edges = []
        if last[1] == "jmp":
            t = target(last[2])
            if t is not None:
                edges.append(("jmp", t))
        elif JCC.match(last[1]):
            t = target(last[2])
            fall = nxt
            if fall < len(insns):
                edges.append(("fall", insns[fall][0]))
            if t is not None:
                edges.append((last[1], t))
        elif last[1].startswith("ret"):
            pass
        else:
            if nxt < len(insns):
                edges.append(("fall", insns[nxt][0]))
        out.append((body[0][0], last[0], nxt - e, last[1], edges))
    return out


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    path = sys.argv[1]
    entry = 0x10053540
    out = None
    limit = 0
    a = sys.argv[2:]
    i = 0
    while i < len(a):
        if a[i] == "--entry":
            entry = int(a[i + 1], 16); i += 2
        elif a[i] == "--out":
            out = a[i + 1]; i += 2
        elif a[i] == "--limit":
            limit = int(a[i + 1]); i += 2
        else:
            i += 1
    insns = parse(path)
    blks = blocks(insns, entry)
    lines = []
    lines.append("# CFG 摘要 %s  entry=0x%08x  指令=%d  基本块=%d" % (path, entry, len(insns), len(blks)))
    for (s, e, n, lop, edges) in blks:
        es = " ".join("%s->0x%08x" % (k, t) for k, t in edges) or "-"
        lines.append("0x%08x-0x%08x (%3d insn) last=%s   %s" % (s, e, n, lop, es))
    if limit:
        lines = lines[:limit + 1]
    text = "\n".join(lines) + "\n"
    if out:
        with open(out, "w", encoding="utf-8") as f:
            f.write(text)
        print("wrote %s (%d blocks)" % (out, len(blks)))
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
