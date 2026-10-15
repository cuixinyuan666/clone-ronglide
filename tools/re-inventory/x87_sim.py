# -*- coding: utf-8 -*-
"""
x87 条件提取器 v2 —— 基本块级 x87 栈数据流模拟（通用逆向工具）

与 v1 (extract_x87_conditions.py) 的差别:
  v1 只认 "fld;fld;fcompp;fnstsw;test ah,M; jcc" 直线三元组, 操作数记成"最近两次 fld",
     不处理 fxch / fcom st(n) / fstp st(n) 的栈重排, 遇到分支汇合会串味。
  v2 把函数切成 **基本块**(跳转目标/跳转后一条为块首), 对每个块做 x87 寄存器栈模拟,
     再把出块栈态传播给后继块 (worklist)。块被多个前驱以不同栈态到达时标记 conflict。
  于是每个比较点能给出 **真实的两个操作数来源**, 并标注置信度。

x87 栈语义 (ST0 = 栈顶, 由 capstone 的最终 x87 语义处理):
  fld m / fld st(i) / fldz / fld1                 -> push
  fst m (存不弹) / fstp m (存并弹)
  fst st(i) / fstp st(i)                          -> 复制 ST0 到 ST(i) 槽 (fstp 再弹)
  fxch st(i)                                      -> 交换 ST0 与 ST(i)
  fcom/fcomp/fucom/fucomp [st(i)|m]               -> 比较 ST0 vs ST(i) 或 m
  fcompp/fucompp                                  -> 比较 ST0 vs ST1 并弹两次
  fadd/fsub/fsubr/fmul/fdiv/fdivr [st(i),st(0)|m]  -> 更新槽标签

Intel 比较结果编码 (FNSTSW 后 AH: C0=b0, C2=b2, C3=b6):
    ST0 > ST1: C0=0 C2=0 C3=0      ST0 < ST1: C0=1 C2=0 C3=0
    ST0 = ST1: C0=0 C2=0 C3=1      Unordered: C0=1 C2=2 C3=1
本文件的四态真值表由该编码 + Jcc(PF/ZF) 语义机械推导, 可用 --selftest 自检。

用法:
  python x87_sim.py <f_*.txt> [-o out.txt]
  python x87_sim.py --selftest
"""
import re
import sys
from collections import Counter

# ---------------------------------------------------------------- 真值解码
def _flags(mask, c0, c2, c3):
    """按四态取值组装 AH&mask 的结果字节"""
    return ((c0 << 0) & mask) | ((c2 << 2) & mask) | ((c3 << 6) & mask)


def _jcc_taken(jcc, res):
    """给定 test 结果字节, 该 Jcc 是否跳转 (只涉及 ZF/PF, 与 C 标志无关)"""
    zf = 1 if res == 0 else 0
    pf = 1 if bin(res & 0xFF).count("1") % 2 == 0 else 0   # PF=1 当低字节偶校验
    return {"je": zf, "jz": zf, "jne": 1 - zf, "jnz": 1 - zf,
            "jp": pf, "jpe": pf, "jnp": 1 - pf, "jpo": 1 - pf}.get(jcc)


def decode(mask, jcc):
    """返回 (跳转时成立的条件串, 落空时成立的条件串); 四态: > < = U(unordered)"""
    cases = {
        ">": _flags(mask, 0, 0, 0),
        "<": _flags(mask, 1, 0, 0),
        "=": _flags(mask, 0, 0, 1),
        "U": _flags(mask, 1, 1, 1),
    }
    jmp_on, fall = [], []
    for k, v in cases.items():
        t = _jcc_taken(jcc, v)
        if t is None:
            return ("?", "?")
        (jmp_on if t else fall).append(k)
    return ("|".join(jmp_on) or "-", "|".join(fall) or "-")


# ---------------------------------------------------------------- 解析
LINE_RE = re.compile(r"^([0-9a-f]+)\s+(\S+)\s*(.*)$")
MEM_RE = re.compile(r"(?:dword|qword|word|byte)\s+ptr\s+(\[[^\]]*\]|\S+)")
STI_RE = re.compile(r"st\((\d+)\)")

ARITH = {"fadd", "fsub", "fsubr", "fmul", "fdiv", "fdivr",
         "faddp", "fsubp", "fsubrp", "fmulp", "fdivp"}
UNARY = {"fchs", "fabs", "fsqrt", "frndint"}
CMP2 = {"fcom", "fcomp", "fucom", "fucomp"}
CMPP = {"fcompp", "fucompp"}
NOOP = {"fnstsw", "fwait", "fnclex", "fnstcw", "fldcw", "fninit", "nop", "lea",
        "mov", "movzx", "movsx", "push", "pop", "add", "sub", "and", "or", "xor",
        "cmp", "test", "imul", "mul", "setne", "sete", "seta", "setb", "neg",
        "inc", "dec", "shl", "shr", "sar", "rep", "xchg", "not", "cdq", "idiv",
        "div", "sbb", "adc", "seto"}

JCC = re.compile(r"^j(mp|e|z|ne|nz|p|pe|np|po|s|ns|b|c|nae|ae|nb|nc|be|na|a|nbe|l|nge|ge|nl|le|ng|g|nle|o|no|cxz|ecxz)$")
JCC_PREFIX = re.compile(r"^j[a-z]+$")


def norm_mem(op):
    m = MEM_RE.search(op)
    return re.sub(r"\s+", "", m.group(1)) if m else None


def clean_lines(text):
    out = []
    for ln in text.splitlines():
        m = LINE_RE.match(ln.strip())
        if m:
            out.append([int(m.group(1), 16), m.group(2), m.group(3).replace(", ", ",")])
    return out


# ---------------------------------------------------------------- 基本块
def build_blocks(insns):
    idx_of = {ins[0]: i for i, ins in enumerate(insns)}
    leaders = {0}
    for i, (addr, mn, ops) in enumerate(insns):
        if JCC_PREFIX.match(mn):
            try:
                t = int(ops, 16)
            except ValueError:
                t = None
            if t in idx_of:
                leaders.add(idx_of[t])
            if i + 1 < len(insns):
                leaders.add(i + 1)
        elif mn in ("ret", "retf"):
            if i + 1 < len(insns):
                leaders.add(i + 1)
    starts = sorted(leaders)
    blocks = []
    for k, s in enumerate(starts):
        e = starts[k + 1] if k + 1 < len(starts) else len(insns)
        blocks.append((s, e))
    return blocks, idx_of


def succs(insns, s, e, idx_of):
    """返回 [(后继块起点索引, 类型)]; 由块尾决定"""
    last = insns[e - 1]
    mn, ops = last[1], last[2]
    out = []
    if mn in ("ret", "retf"):
        return out
    if mn == "jmp":
        try:
            t = int(ops, 16)
        except ValueError:
            return out                      # 间接跳转: 无静态后继
        if t in idx_of:
            out.append(("jmp", idx_of[t]))
        return out
    if JCC_PREFIX.match(mn):
        try:
            t = int(ops, 16)
        except ValueError:
            t = None
        if t in idx_of:
            out.append(("jcc", idx_of[t]))
        if e < len(insns):
            out.append(("fall", e))
        return out
    if e < len(insns):
        out.append(("fall", e))
    return out


# ---------------------------------------------------------------- 块内模拟
def run_block(insns, s, e, in_state, idx_of):
    """从 in_state 起模拟块 [s,e); 返回 (out_state, cmps, invalid)"""
    stack = list(in_state)
    cmps = []
    invalid = False

    def push(lbl):
        stack.insert(0, lbl)

    for i in range(s, e):
        addr, mn, ops = insns[i]
        sti = STI_RE.search(ops)
        if mn == "fld":
            mem = norm_mem(ops)
            if mem:
                push(mem)
            elif sti:
                k = int(sti.group(1))
                push(stack[k] if k < len(stack) else "ST%d" % k)
            else:
                push(ops)
        elif mn == "fldz":
            push("0.0")
        elif mn == "fld1":
            push("1.0")
        elif mn in ("fldpi", "fldl2e", "fldln2", "fldl2t", "fldlg2"):
            push(mn[3:])
        elif mn in ("fst", "fstp"):
            if sti:
                k = int(sti.group(1))
                if stack and 0 < k < len(stack):
                    stack[k] = stack[0]
                if mn == "fstp" and stack:
                    stack.pop(0)
            elif mn == "fstp" and stack:
                stack.pop(0)
        elif mn == "fxch":
            k = int(sti.group(1)) if sti else 1
            if 0 < k < len(stack):
                stack[0], stack[k] = stack[k], stack[0]
        elif mn in CMP2 or mn in CMPP:
            if not stack:
                invalid = True
            if mn in CMPP:
                a = stack[0] if stack else "?"
                b = stack[1] if len(stack) > 1 else "?"
                kk = 1
            elif sti:
                kk = int(sti.group(1))
                a = stack[0]
                b = stack[kk] if kk < len(stack) else "ST%d" % kk
            else:
                mem = norm_mem(ops)          # fcom/fcomp qword ptr [mem] : 与内存比较
                a = stack[0] if stack else "?"
                if mem:
                    b, kk = mem, "m"
                else:
                    b, kk = (stack[1] if len(stack) > 1 else "?"), 1
            mask, jcc, tgt = None, None, None
            for j in range(i + 1, min(i + 8, len(insns))):
                nj = insns[j]
                if nj[1] == "test" and "ah" in nj[2] and "," in nj[2]:
                    try:
                        mask = int(nj[2].split(",")[1], 16)
                    except ValueError:
                        mask = None
                elif mask is not None and JCC_PREFIX.match(nj[1]):
                    jcc, tgt = nj[1], nj[2]
                    break
            jmpc, fallc = decode(mask, jcc) if (mask is not None and jcc) else ("?", "?")
            cmps.append({"addr": addr, "a": a, "b": b, "k": kk, "mask": mask, "jcc": jcc,
                         "tgt": tgt, "jmp": jmpc, "fall": fallc,
                         "pp": mn in CMPP, "op": mn, "idx": i})
            if mn in CMPP:
                if stack:
                    stack.pop(0)
                if stack:
                    stack.pop(0)
            elif mn in ("fcomp", "fucomp"):
                if stack:
                    stack.pop(0)
        elif mn in ARITH:
            parts = [p.strip() for p in ops.split(",")]
            if len(parts) == 2:
                d = STI_RE.search(parts[0])
                if d:
                    k = int(d.group(1))
                    if k == 0 and stack:
                        stack[0] = "%s(...)" % mn
                    elif k < len(stack):
                        stack[k] = "%s(%s,%s)" % (mn, stack[k], parts[1])
                else:
                    mem = norm_mem(parts[0]) or norm_mem(ops)
                    if stack and mem:
                        stack[0] = "%s(%s,%s)" % (mn, stack[0], mem)
            else:
                mem = norm_mem(ops)
                if stack and mem:
                    stack[0] = "%s(%s,%s)" % (mn, stack[0], mem)
        elif mn in UNARY:
            if stack:
                stack[0] = "%s(%s)" % (mn, stack[0])
    return stack, cmps, invalid


def simulate(insns):
    blocks, idx_of = build_blocks(insns)
    start_of = {s: (s, e) for s, e in blocks}
    in_state = {}
    out_state = {}
    all_cmps = []
    conflict = set()
    work = [0]
    seen = set()
    while work:
        s = work.pop(0)
        if s in seen:
            continue
        seen.add(s)
        st = in_state.get(s, [])
        out, cmps, invalid = run_block(insns, s, start_of[s][1], st, idx_of)
        out_state[s] = out
        all_cmps.extend(cmps)
        for kind, t in succs(insns, s, start_of[s][1], idx_of):
            if t not in in_state:
                in_state[t] = list(out)
            else:
                # 合并: 深度或标签不一致 -> 分歧
                if len(in_state[t]) != len(out) or in_state[t] != out:
                    conflict.add(t)
            if t not in seen:
                work.append(t)
    all_cmps.sort(key=lambda c: c["addr"])
    return all_cmps, blocks, conflict


# ---------------------------------------------------------------- 附加扫描
STORE_RE = re.compile(r"mov\s+(dword|byte|word)\s+ptr\s+\[(\w+)\s*\+\s*(0x[0-9a-f]+|\d+)\],\s*(\S+)$")
ZEROY = {"0", "0x0", "ecx", "eax", "edx", "ebx", "esi", "edi", "ebp"}


def scan_stores(insns):
    out = []
    for addr, mn, ops in insns:
        m = STORE_RE.match("%s %s" % (mn, ops))
        if m:
            out.append((addr, m.group(2), int(m.group(3), 16), m.group(4)))
    return out


def main():
    if "--selftest" in sys.argv:
        checks = [
            (0x41, "jne", "<|=|U", ">"),
            (0x41, "je", ">", "<|=|U"),
            (0x05, "jp", ">|=|U", "<"),
            (0x05, "jnp", "<", ">|=|U"),
            (0x01, "jne", "<|U", ">|="),
            (0x01, "je", ">|=", "<|U"),
            (0x41, "jp", ">|U", "<|="),
            (0x41, "jnp", "<|=", ">|U"),
            (0x44, "jnp", "=", ">|<|U"),
            (0x44, "jp", ">|<|U", "="),
        ]
        for mask, jcc, exp_j, exp_f in checks:
            j, f = decode(mask, jcc)
            assert j == exp_j and f == exp_f, (hex(mask), jcc, j, f, exp_j, exp_f)
        print("selftest OK (%d cases)" % len(checks))
        return

    src = sys.argv[1]
    out = None
    if "-o" in sys.argv:
        out = sys.argv[sys.argv.index("-o") + 1]

    insns = clean_lines(open(src, encoding="utf-8").read())
    cmps, blocks, conflict = simulate(insns)
    stores = scan_stores(insns)
    calls = Counter(ops for _, mn, ops in insns if mn == "call")

    L = []
    L.append("### [A] x87 条件表   src=%s   insns=%d   blocks=%d   conflicts=%d   conds=%d"
             % (src, len(insns), len(blocks), len(conflict), len(cmps)))
    L.append("%-10s %-8s %-18s %-22s %-6s %-5s %-12s %-10s %-10s" %
             ("地址", "op", "ST0", "ST(k)", "test", "jcc", "目标", "跳转成立", "落空成立"))
    for c in cmps:
        mask = "0x%02x" % c["mask"] if c["mask"] is not None else "?"
        klab = ("mem:" + c["b"]) if c["k"] == "m" else ("ST%d=%s" % (c["k"], c["b"]))
        L.append("%-10x %-8s %-18s %-22s %-6s %-5s %-12s %-10s %-10s" %
                 (c["addr"], c["op"], c["a"], klab,
                  "ah,%s" % mask, c["jcc"] or "?", c["tgt"] or "-", c["jmp"], c["fall"]))
    L.append("\n### [B] 非零立即数写入 (标记字段写点)")
    for addr, reg, off, val in stores:
        if val not in ZEROY:
            L.append("%-10x mov [%s+0x%x], %s" % (addr, reg, off, val))
    L.append("\n### [C] 调用目标统计")
    for t, n in calls.most_common():
        L.append("  %-24s x%d" % (t, n))

    txt = "\n".join(L)
    print(txt)
    if out:
        open(out, "w", encoding="utf-8").write(txt + "\n")
        print("\n[written] %s  (%d conditions, %d stores)" % (out, len(cmps), len(stores)))


if __name__ == "__main__":
    main()
