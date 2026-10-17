# -*- coding: utf-8 -*-
"""cfg_blocks.py — 从 disasm_func.py 产出的文本重建基本块 / CFG / 支配树 / 环。

用法:
    python cfg_blocks.py <disasm.txt> [-o out.txt] [--func 0x100048a0]

背景: NChZsL2M(0x100048a0) 有 189 个基本块，手工读会有遗漏；本工具把控制结构
先摊开成支配树，让人可以按"必经块"顺序读，避免线性扫读造成的语义错配。

输出包含:
  1. 基本信息（指令数 / 块数 / 调用数 / 返回点）
  2. 基本块清单（leader 原因、后继、跳转到本块的边数）
  3. 支配树（idom 缩进）
  4. 回边集合（自然环 -> while/for 位置）
  5. 每块的摘要首行（便于快速定位）
"""
import argparse
import re
import sys

LINE = re.compile(r"^([0-9a-f]{8})\s+(.*)$")
FLOW = ("jmp", "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle", "ja", "jae",
        "jb", "jbe", "js", "jns", "jo", "jno", "jp", "jnp", "jpe", "jpo",
        "jecxz", "jcxz", "loop")
RET = ("ret", "retn", "retf")


def parse(path):
    ins = []
    for line in open(path, encoding="utf-8", errors="replace"):
        m = LINE.match(line.rstrip("\n"))
        if not m:
            continue
        ins.append([int(m.group(1), 16), m.group(2).strip(), None, None])
    return ins


def mnemonic(body):
    return body.split()[0] if body else ""


def target_of(body):
    """返回绝对跳转目标（本函数内的 0x1xxxxxxx 操作数），否则 None。"""
    parts = body.split(None, 1)
    if len(parts) < 2:
        return None
    op = parts[1].strip()
    m = re.fullmatch(r"0x1[0-9a-f]{7}", op)
    return int(op, 16) if m else None


def build(ins):
    addr2idx = {a: i for i, (a, _, _, _) in enumerate(ins)}
    leaders = {0}                                    # 入口
    for i, (a, body, _, _) in enumerate(ins):
        mn = mnemonic(body)
        t = target_of(body)
        if mn in FLOW and t is not None:
            leaders.add(i)
            if t in addr2idx:
                leaders.add(addr2idx[t])
            if mn != "jmp" and i + 1 < len(ins):
                leaders.add(i + 1)
        elif mn.startswith("j"):
            # 间接跳转 / 短跳写成 hex 之外的形态，保守处理
            leaders.add(i)
            if i + 1 < len(ins):
                leaders.add(i + 1)
        elif mn in RET and i + 1 < len(ins):
            leaders.add(i + 1)
        elif mn.startswith("call") and i + 1 < len(ins):
            # 调用之后通常被当作 leader 便于阅读
            leaders.add(i + 1)
    starts = sorted(leaders)
    blocks = []          # (start_idx, end_idx_inclusive)
    for k, s in enumerate(starts):
        e = starts[k + 1] - 1 if k + 1 < len(starts) else len(ins) - 1
        blocks.append((s, e))
    bidx_of = {}
    for bi, (s, e) in enumerate(blocks):
        for i in range(s, e + 1):
            bidx_of[i] = bi
    succ = [[] for _ in blocks]
    pred = [[] for _ in blocks]
    for bi, (s, e) in enumerate(blocks):
        last_i = e
        while last_i > s and mnemonic(ins[last_i][1]) in ("nop",):
            last_i -= 1
        a, body, _, _ = ins[last_i]
        mn = mnemonic(body)
        t = target_of(body) if mn in FLOW else None
        outs = []
        if mn in RET:
            outs = []
        elif mn == "jmp" and t is not None and t in addr2idx:
            outs = [bidx_of[addr2idx[t]]]
        elif mn == "jmp":
            outs = []
        elif mn in FLOW:
            if t is not None and t in addr2idx:
                outs.append(bidx_of[addr2idx[t]])
            if last_i + 1 < len(ins):
                outs.append(bidx_of[last_i + 1])
        elif last_i + 1 < len(ins):
            outs.append(bidx_of[last_i + 1])
        for o in outs:
            if o not in succ[bi]:
                succ[bi].append(o)
                pred[o].append(bi)
    return ins, blocks, succ, pred, bidx_of


def dominators(n, succ, pred, entry=0):
    """迭代式求 idom（Cooper-Harvey-Kennedy 算法），返回 idom 数组，不可达为 -2。"""
    order = []
    seen = [False] * n
    stack = [entry]
    seen[entry] = True
    while stack:
        b = stack.pop()
        order.append(b)
        for s in succ[b]:
            if not seen[s]:
                seen[s] = True
                stack.append(s)
    rpo = []
    # 反向后序需要真实的 DFS 后序：重做一次递归式 DFS
    order2 = []
    seen2 = [False] * n
    sys.setrecursionlimit(10000)

    def dfs(b):
        seen2[b] = True
        for s in sorted(succ[b]):
            if not seen2[s]:
                dfs(s)
        order2.append(b)

    dfs(entry)
    rpo = order2[::-1]
    pon = {b: i for i, b in enumerate(rpo)}
    idom = [-2] * n
    idom[entry] = entry
    changed = True
    while changed:
        changed = False
        for b in rpo:
            if b == entry:
                continue
            new = None
            for p in pred[b]:
                if idom[p] == -2:
                    continue
                new = p if new is None else intersect(new, p, idom, pon)
            if new is not None and idom[b] != new:
                idom[b] = new
                changed = True
    return idom, [b for b in rpo]


def intersect(a, b, idom, pon):
    while a != b:
        while pon[a] > pon[b]:
            a = idom[a]
        while pon[b] > pon[a]:
            b = idom[b]
    return a


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("-o", "--out")
    ap.add_argument("--func", default=None, help="限制分析范围的函数起始地址(hex)")
    a = ap.parse_args()
    ins = parse(a.src)
    if a.func:
        lo = int(a.func, 16)
        hi = None
        # 到第一个 ret 后 8 字节为止（保守：取全部但标记）
        ins = [x for x in ins if x[0] >= lo]
    ins, blocks, succ, pred, bidx_of = build(ins)
    n = len(blocks)
    idom, rpo = dominators(n, succ, pred, 0)
    out = []

    def w(s=""):
        out.append(s)

    calls = sum(1 for _, b, _, _ in ins if mnemonic(b).startswith("call"))
    rets = [ins[i][0] for i, (ad, b, _, _) in enumerate(ins) if mnemonic(b) in RET]
    w("# CFG / 支配树报告  src=%s" % a.src)
    w("  insns=%d  blocks=%d  calls=%d  ret@%s" % (len(ins), n, calls,
                                                   ", ".join("0x%08x" % r for r in rets[:6])))
    # 回边
    back = []
    for bi in range(n):
        for s in succ[bi]:
            if idom[s] != -2 and s in rpo and bi in rpo:
                # 若 s 支配 bi，则 bi->s 是回边
                x = bi
                dom = False
                while True:
                    if idom[x] == -2:
                        break
                    if x == s:
                        dom = True
                        break
                    if x == idom[x]:
                        break
                    x = idom[x]
                if dom:
                    back.append((s, bi))
    w("  自然环(while/for) 头部: %s" % ", ".join("0x%08x" % ins[blocks[h][0]][0]
                                                for h, _ in sorted(set(back))) or "无")
    w()
    w("## 支配树（缩进=被支配深度；[Lx] 为环头）")
    heads = {h for h, _ in back}
    children = {}
    for b in range(n):
        if idom[b] == -2 or b == 0:
            continue
        children.setdefault(idom[b], []).append(b)
    for c in children.values():
        c.sort(key=lambda b: ins[blocks[b][0]][0])

    def walk(b, depth):
        s, e = blocks[b]
        a0 = ins[s][0]
        tag = " [L]" if b in heads else ""
        nin = len(pred[b])
        outd = ",".join("0x%08x" % ins[blocks[o][0]][0] for o in succ[b]) or "-"
        first = ins[s][1]
        w("%sB%-3d 0x%08x-0x%08x  n=%-3d in=%-2d out=%s%s   | %s" % (
            "  " * depth, b, a0, ins[e][0], e - s + 1, nin, outd, tag, first))
        for c in children.get(b, []):
            walk(c, depth + 1)

    walk(0, 0)
    w()
    w("## 块清单（按地址序；in=前驱数, out=后继）")
    for b in range(n):
        s, e = blocks[b]
        fb = [ins[blocks[p][0]][0] for p in pred[b]]
        w("B%-3d 0x%08x-0x%08x n=%-3d in=%-2d <-%s -> %s   | %s" % (
            b, ins[s][0], ins[e][0], e - s + 1, len(fb),
            ",".join("0x%08x" % x for x in fb[:6]),
            ",".join("0x%08x" % ins[blocks[o][0]][0] for o in succ[b]) or "-",
            ins[s][1]))
    txt = "\n".join(out)
    if a.out:
        open(a.out, "w", encoding="utf-8", newline="\n").write(txt + "\n")
        print("written %s  (%d lines)" % (a.out, len(out)))
    else:
        print(txt)


if __name__ == "__main__":
    main()
