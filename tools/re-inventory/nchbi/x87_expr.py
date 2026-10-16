#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
x87_expr.py — 符号化 x87 栈模拟器（用于把 fld/fmul/fdivrp/... 链还原成公式）

用途: disasm_func.py 的输出（形如 "10003c65  fsubr st(1)"）喂进来,
     工具按 Intel 语义逐条模拟 x87 栈（栈元素为符号字符串），
     最后打印栈内容 -> 即公式。

支持的指令（Intel 语义）:
  fld mem / fild mem / fldz / fld1 / fld st(i)
  fxch st(i)
  fadd/fsub/fsubr/fmul/fdiv/fdivr  (寄存器形态: b/w 决定 pop)
  faddp/fsubp/fsubrp/fmulp/fdivp/fdivrp st(i)  (恒 pop)
  fabs / fchs / fsqrt / frndint / fidiv mem / fimul mem / fiadd mem / fisub mem
  fstp mem / fst mem / fstp st(i)
  fucomp/fcompp/fucompp/fcomp  (比较后 pop)
  fnstsw (忽略)

用法:
  python x87_expr.py <dump.txt> [--from 0xADDR] [--to 0xADDR] [--stack "1000.0,0.0"]

注意: 本工具只做「栈平衡 + 符号代数」，不做具体数值求值。
"""
import re
import sys

def parse_ops(opstr):
    """返回操作数 token 列表，去空格，保留 st(0)/mem[...] 形态"""
    opstr = opstr.strip()
    if not opstr:
        return []
    # 用逗号切（操作数内不含逗号）
    return [t.strip() for t in opstr.split(',')]

def reg_index(tok):
    m = re.match(r'^st\((\d+)\)$', tok)
    return int(m.group(1)) if m else None

def is_st(tok):
    return reg_index(tok) is not None

def simp(s):
    """极简符号化简: 0*X -> 0, X/0? 不处理; 纯数字可约"""
    if isinstance(s, tuple):
        return s
    return s

class Stack:
    def __init__(self, init):
        self.s = list(init)          # s[0] = st(0)
    def push(self, v):
        self.s.insert(0, v)
    def pop(self):
        return self.s.pop(0)
    def top(self, i):
        return self.s[i] if i < len(self.s) else '<u%d>' % i
    def set(self, i, v):
        while len(self.s) <= i:
            self.s.append('<u%d>' % len(self.s))
        self.s[i] = v
    def dump(self):
        return ' , '.join('st%d=%s' % (i, v) for i, v in enumerate(self.s))

def mul(a, b):
    if a in ('0.0', '0') or b in ('0.0', '0'):
        return '0.0'
    if a == '1.0':
        return b
    if b == '1.0':
        return a
    return '(%s * %s)' % (a, b)

def div(a, b):
    if a == '0.0':
        return '0.0'
    if b == '1.0':
        return a
    return '(%s / %s)' % (a, b)

def add(a, b):
    return '(%s + %s)' % (a, b)

def sub(a, b):
    return '(%s - %s)' % (a, b)

def simulate(lines, st, verbose=False):
    for (addr, mn, ops) in lines:
        argv = parse_ops(ops)
        out = None
        if mn in ('fld', 'fild'):
            src = argv[0]
            if is_st(src):
                v = st.top(reg_index(src))
            else:
                v = src
            st.push(v); out = 'push %s' % v
        elif mn in ('fldz',):
            st.push('0.0'); out = 'push 0.0'
        elif mn in ('fld1',):
            st.push('1.0'); out = 'push 1.0'
        elif mn == 'fxch':
            i = reg_index(argv[0]); a = st.top(0); b = st.top(i)
            st.set(0, b); st.set(i, a); out = 'swap st0<->st%d' % i
        elif mn in ('fadd', 'fsub', 'fsubr', 'fmul', 'fdiv', 'fdivr'):
            # 两形态:
            #   D8/DC + 单寄存器操作数 => ST(0) = ST(0) op ST(i)  **不弹栈**
            #     (经典例子 D8 C0 = fadd st(0),st(0) 原地加倍, 显然不弹)
            #   显式两操作数 "op st(i), st(0)" => ST(i) = ... 不弹栈
            if len(argv) == 1 and is_st(argv[0]):
                i = reg_index(argv[0])
                a0, ai = st.top(0), st.top(i)
                if mn == 'fadd':   r = add(a0, ai)
                elif mn == 'fsub': r = sub(a0, ai)
                elif mn == 'fsubr':r = sub(ai, a0)
                elif mn == 'fmul': r = mul(a0, ai)
                elif mn == 'fdiv': r = div(a0, ai)
                else:              r = div(ai, a0)
                st.set(0, r); out = 'st0 = %s (no-pop)' % r
            else:
                # 显式两操作数
                d, s = argv[0], argv[1]
                di = reg_index(d)
                si = reg_index(s)
                if di is None:
                    out = 'skip'
                else:
                    a, b = st.top(di), st.top(si)
                    r = {'fadd': add(a, b), 'fsub': sub(a, b), 'fsubr': sub(b, a),
                         'fmul': mul(a, b), 'fdiv': div(a, b), 'fdivr': div(b, a)}[mn]
                    st.set(di, r); out = 'st%d = %s' % (di, r)
        elif mn in ('faddp', 'fsubp', 'fsubrp', 'fmulp', 'fdivp', 'fdivrp'):
            # "P" 形态: ST(i) = ST(0) op ST(i)  (subr/divr 为反向), 然后弹栈
            #   FSUBP  ST(i),ST(0): ST(i) = ST(i) - ST(0)
            #   FSUBRP ST(i),ST(0): ST(i) = ST(0) - ST(i)
            #   FDIVP  ST(i),ST(0): ST(i) = ST(i) / ST(0)
            #   FDIVRP ST(i),ST(0): ST(i) = ST(0) / ST(i)
            i = reg_index(argv[0]) if argv else 1
            a0, ai = st.top(0), st.top(i)
            if mn == 'faddp':   r = add(ai, a0)
            elif mn == 'fsubp': r = sub(ai, a0)
            elif mn == 'fsubrp':r = sub(a0, ai)
            elif mn == 'fmulp': r = mul(ai, a0)
            elif mn == 'fdivp': r = div(ai, a0)
            else:               r = div(a0, ai)
            st.pop()
            v = st.pop(); st.push(r)
            out = 'st%d = %s' % (i - 1, r)
        elif mn in ('fabs',):
            st.set(0, '|%s|' % st.top(0)); out = 'st0 = |st0|'
        elif mn == 'fchs':
            st.set(0, '-(%s)' % st.top(0)); out = 'st0 = -st0'
        elif mn == 'fsqrt':
            st.set(0, 'sqrt(%s)' % st.top(0)); out = 'st0 = sqrt'
        elif mn == 'frndint':
            st.set(0, 'round(%s)' % st.top(0)); out = 'st0 = round'
        elif mn in ('fidiv', 'fimul', 'fiadd', 'fisub', 'fisubr'):
            m = argv[0]
            if mn == 'fidiv':
                a0 = st.top(0); st.set(0, div(a0, m)); out = 'st0 = st0 / %s' % m
            elif mn == 'fimul':
                a0 = st.top(0); st.set(0, mul(a0, m)); out = 'st0 = st0 * %s' % m
            elif mn == 'fiadd':
                st.set(0, add(st.top(0), m)); out = 'st0 += %s' % m
            else:
                st.set(0, sub(st.top(0), m)); out = 'st0 -= %s' % m
        elif mn == 'fstp':
            v = st.pop()
            if argv and is_st(argv[0]):
                i = reg_index(argv[0])
                st.set(i, v); st.push(v)   # FSTP ST(i): 写入后 pop
                st.pop()
                out = 'st%d <= %s (pop)' % (i, v)
            else:
                out = 'mem <= %s (pop)' % v
        elif mn == 'fst':
            out = 'mem <= %s' % st.top(0)
        elif mn in ('fucomp', 'fcompp', 'fucompp'):
            if mn == 'fcompp' or mn == 'fucompp':
                st.pop(); st.pop(); out = 'cmp+pop2'
            else:
                st.pop(); out = 'cmp+pop'
        elif mn == 'fcomp':
            st.pop(); out = 'cmp+pop'
        elif mn == 'fnstsw':
            out = 'flags'
        else:
            out = '(ignored)'
        if verbose:
            print('  %08x %-10s %-24s -> %-28s | %s' % (addr, mn, ops, out, st.dump()))

def main():
    path = sys.argv[1]
    lo = hi = None
    init = ['1000.0', '0.0']
    args = sys.argv[2:]
    i = 0
    while i < len(args):
        if args[i] == '--from': lo = int(args[i+1], 16); i += 2
        elif args[i] == '--to': hi = int(args[i+1], 16); i += 2
        elif args[i] == '--stack': init = args[i+1].split(','); i += 2
        else: i += 1
    lines = []
    for ln in open(path, encoding='utf-8'):
        m = re.match(r'^([0-9a-f]{8})\s+(\S+)\s*(.*)$', ln.strip())
        if not m:
            continue
        a = int(m.group(1), 16)
        if lo is not None and a < lo: continue
        if hi is not None and a > hi: continue
        lines.append((a, m.group(2), m.group(3)))
    st = Stack(init)
    print('# 初始栈: %s' % init)
    simulate(lines, st, verbose=True)
    print('\n>>> 最终栈: %s' % st.dump())
    if st.s:
        print('>>> st0 (公式) = %s' % st.s[0])

if __name__ == '__main__':
    main()
