# -*- coding: utf-8 -*-
"""x87_path.py — 带分支路径探索的符号化 x87 栈模拟（针对单寄存器轮转形态）

用途: 当一段 x87 代码大量使用 fxch/fstp st(i)/fld st(i) 做「三值轮转」时,
      x87_sim.py(v2, 块级传播) 会在分支汇合处失去精度(conflict)。本工具改为
      **在指定地址区间内做路径 DFS**, 每条路径都是直线, 于是栈内容完全确定。

用法:
    python x87_path.py <disasm.txt> --start 0x10004aac --end 0x10004c90 \
           --init "1.0,0.0,0.0,0.0" [--max-paths 400]

输出:
    - 每个 `fst/fstp qword ptr [reg...]` 站点: 该路径下被写入的符号表达式 + 路径上的分支选择
    - 每条路径结束时(到达 --end) 的栈态
符号命名: 内存装载记为 m[地址偏移] (可再映射为语义名), 常量记 1.0/0.0。
"""
import argparse
import re
import sys

LINE = re.compile(r"^([0-9a-f]{8})\s+(.*)$")
JCC = {"je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle", "ja", "jae", "jb", "jbe",
       "js", "jns", "jp", "jnp", "jpe", "jpo", "jo", "jno"}


def load(path):
    code = {}
    order = []
    for line in open(path, encoding="utf-8", errors="replace"):
        m = LINE.match(line.rstrip("\n"))
        if not m:
            continue
        a = int(m.group(1), 16)
        body = m.group(2).strip()
        mn, _, ops = body.partition(" ")
        code[a] = (mn, ops.strip(), body)
        order.append(a)
    return code, order


def tgt(ops):
    m = re.search(r"0x1[0-9a-f]{7}", ops)
    return int(m.group(0), 16) if m else None


class Sim:
    def __init__(self, code, start, end, init, max_paths=400, max_steps=4000, order=None):
        self.code = code
        self._order = order or sorted(code)
        self.start = start
        self.end = end
        self.init = init
        self.max_paths = max_paths
        self.max_steps = max_steps
        self.stores = []      # (addr, value, decisions)
        self.ends = []        # (stack, decisions)
        self.paths = 0

    def run(self):
        self.dfs(self.start, list(self.init), [], set())

    def dfs(self, a, st, decisions, seen):
        steps = 0
        while True:
            steps += 1
            if steps > self.max_steps or self.paths >= self.max_paths:
                return
            if a == self.end or a not in self.code:
                self.paths += 1
                self.ends.append((list(st), list(decisions)))
                return
            if a in seen and steps > 0 and len(st) == 0:
                return
            mn, ops, body = self.code[a]
            nxt = a
            # ---- x87 语义 ----
            if mn == "fld":
                m = re.match(r"st\((\d+)\)", ops)
                if m:
                    i = int(m.group(1))
                    if i < len(st):
                        st.insert(0, st[i])
                elif "ptr" in ops:
                    mem = re.search(r"\[(.*)\]", ops)
                    st.insert(0, "m[%s]" % (mem.group(1) if mem else ops))
                else:
                    st.insert(0, ops)
            elif mn == "fldz":
                st.insert(0, "0")
            elif mn == "fld1":
                st.insert(0, "1")
            elif mn in ("fst", "fstp"):
                m = re.match(r"st\((\d+)\)", ops)
                if m:
                    i = int(m.group(1))
                    if i < len(st):
                        st[i] = st[0]
                    if mn == "fstp":
                        st.pop(0)
                else:
                    self.stores.append((a, st[1] if len(st) > 1 else st[0], list(decisions)))
                    if mn == "fstp":
                        st.pop(0)
            elif mn == "fxch":
                m = re.match(r"st\((\d+)\)", ops)
                i = int(m.group(1)) if m else 1
                if i < len(st) and i > 0:
                    st[0], st[i] = st[i], st[0]
            elif mn in ("fcom", "fcomp", "fucom", "fucomp"):
                pass      # 比较不改栈(除 xxp 形态)
            elif mn in ("fcompp", "fucompp"):
                if len(st) >= 2:
                    st.pop(0)
                    st.pop(0)
            elif mn in ("fadd", "fsub", "fsubr", "fmul", "fdiv", "fdivr",
                        "faddp", "fsubp", "fsubrp", "fmulp", "fdivp", "fdivrp"):
                self.arith(mn, ops, st)
            # ---- 控制流 ----
            if mn == "jmp":
                t = tgt(ops)
                if t is None:
                    return
                a = t
                continue
            if mn in JCC:
                t = tgt(ops)
                if t is None:
                    a = a + 1
                    continue
                # 分支: 两路都探索
                self.dfs(t, list(st), decisions + [("T@" + hex(a))], set())
                self.dfs(self.next_addr(a), list(st), decisions + [("F@" + hex(a))], set())
                return
            if mn in ("ret", "retn"):
                self.paths += 1
                self.ends.append((list(st), list(decisions)))
                return
            nxt = self.next_addr(a)
            if nxt is None:
                return
            a = nxt

    def arith(self, mn, ops, st):
        if not st:
            return
        st[0] = "%s(%s)" % (mn, ",".join(st[:2]))

    def next_addr(self, a):
        import bisect
        i = bisect.bisect_right(self._order, a)
        return self._order[i] if i < len(self._order) else None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("--start", required=True)
    ap.add_argument("--end", required=True)
    ap.add_argument("--init", default="")
    ap.add_argument("--max-paths", type=int, default=200)
    a = ap.parse_args()
    code, order = load(a.src)
    init = [x.strip() for x in a.init.split(",") if x.strip()]
    print("# x87 路径模拟 %s  0x%x..0x%x  init=%s" % (a.src, int(a.start, 16), int(a.end, 16), init))
    print("# 注意: fld st(i) 形态本工具保守跳过(返回 None), 若关键路径依赖它请人工核对。")
    sim = Sim(code, int(a.start, 16), int(a.end, 16), init, a.max_paths, order=order)
    sim.run()
    print("\n## 写入站点（st 值 = 被写入的符号）— 共 %d 条路径样本" % sim.paths)
    uniq = {}
    for addr, val, dec in sim.stores:
        uniq.setdefault((addr, val), []).append(dec)
    for (addr, val), decs in sorted(uniq.items()):
        print("  0x%08x  <- %-28s  paths=%d  eg=%s" % (addr, val, len(decs), decs[0][-3:]))
    print("\n## 出口栈态分布")
    cnt = {}
    for st, dec in sim.ends:
        k = " | ".join(st[:4])
        cnt[k] = cnt.get(k, 0) + 1
    for k, v in sorted(cnt.items(), key=lambda x: -x[1])[:12]:
        print("  [%s]  x%d" % (k, v))


if __name__ == "__main__":
    main()
