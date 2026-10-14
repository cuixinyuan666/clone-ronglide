#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""栈跟踪漂移修正（高效版）：预解码 -> 递归下降 + delta 传播 + 出口校验"""
import struct, sys
from collections import defaultdict, deque, Counter
from capstone import *
from capstone.x86 import *

DLL = r"D:\a_ronglide\缠中说禅\TAFLib.dll"
BASE = 0x10000000

def load_pe(path):
    d = open(path, 'rb').read()
    e = struct.unpack_from('<I', d, 0x3C)[0]
    ns = struct.unpack_from('<H', d, e + 6)[0]
    op = struct.unpack_from('<H', d, e + 20)[0]
    sh = e + 24 + op
    secs = []
    for i in range(ns):
        o = sh + i * 40
        nm = d[o:o+8].rstrip(b'\0').decode('latin1')
        vs, va, rs, rp = struct.unpack_from('<IIII', d, o + 8)
        secs.append((nm, va, vs, rp, rs))
    return d, secs

data, secs = load_pe(DLL)
_, tva, tvs, trp, trs = next(s for s in secs if s[0] == '.text')
TSTART, TEND = BASE + tva, BASE + tva + max(tvs, trs)
code = data[trp:trp + max(tvs, trs)]

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True
md.skipdata = True

# ── 预解码全 .text ──
INS = {}
for ins in md.disasm(code, TSTART):
    if ins.id == 0:
        continue
    imm = None
    if ins.operands and ins.operands[0].type == X86_OP_IMM:
        imm = ins.operands[0].imm
    esp_disp = None
    for op in ins.operands:
        if op.type == X86_OP_MEM and op.mem.base == X86_REG_ESP:
            esp_disp = op.mem.disp
            break
    isw = bool(ins.operands) and ins.operands[0].type == X86_OP_MEM \
        and ins.operands[0].mem.base == X86_REG_ESP
    INS[ins.address] = (ins.mnemonic, ins.op_str, ins.size, imm, esp_disp, isw)
print("预解码指令数: %d" % len(INS))

def in_text(va): return TSTART <= va < TEND

_retN = {}
def callee_retN(t):
    if t in _retN: return _retN[t]
    _retN[t] = None
    if not in_text(t): return None
    seen, wl, rets = set(), deque([t]), []
    while wl and len(seen) < 3000:
        va = wl.popleft()
        if va in seen or not in_text(va): continue
        seen.add(va)
        r = INS.get(va)
        if r is None: continue
        mn, ops, sz, imm, ed, isw = r
        if mn == 'ret':
            rets.append(imm if imm is not None else 0); continue
        if mn in ('int3','hlt','ud2'): continue
        if mn == 'jmp' and imm is not None: wl.append(imm); continue
        if mn.startswith('j') and imm is not None: wl.append(imm)
        if mn == 'call' and imm is not None: wl.append(imm)
        wl.append(va + sz)
    v = Counter(rets).most_common(1)[0][0] if rets else None
    _retN[t] = v
    return v

def trace(start, end, fret):
    rows, wl, seen, exits = {}, deque([(start, 0)]), set(), []
    CAP = 200000
    while wl and len(seen) < CAP:
        va, d = wl.popleft()
        if (va, d) in seen or not in_text(va) or va >= end: continue
        seen.add((va, d))
        r = INS.get(va)
        if r is None: continue
        mn, ops, sz, imm, ed, isw = r
        rows[(va, d)] = r
        eff = 0
        if mn == 'push': eff = -4
        elif mn == 'pop': eff = 4
        elif mn == 'sub' and ops.startswith('esp, '):
            eff = -int(ops.split(', ')[1], 0)
        elif mn == 'add' and ops.startswith('esp, '):
            eff = int(ops.split(', ')[1], 0)
        elif mn == 'call':
            if imm is not None:
                n = callee_retN(imm)
                eff = (n if n is not None else 0)   # ★ 修正：ret N 相对 call 指令处的 esp
            else:
                eff = 0
        nx, nd = va + sz, d + eff
        if mn == 'ret':
            exits.append((va, d, imm if imm is not None else 0)); continue
        if mn in ('int3','hlt','ud2'): continue
        if mn == 'jmp':
            if imm is not None: wl.append((imm, nd))
            continue
        if mn.startswith('j') and imm is not None:
            wl.append((imm, nd))
        # 注意：call 不进入被调者（其 delta 独立），仅用 callee_retN 计算清理字节
        wl.append((nx, nd))
    return rows, exits

if __name__ == '__main__':
    start, end, fret = 0x10056190, 0x1005cc00, 4
    rows, exits = trace(start, end, fret)
    globals()['ROWS'] = rows
    print("sub_10056190: %d 个 (va,delta) 状态" % len(rows))
    print("\n=== 出口 ret 校验（期望 delta + 4 + N == %d）===" % (4 + fret))
    for va, d, n in sorted(exits):
        print("   0x%08x  ret %d  delta=%+d  %s" % (va, n, d, 'OK' if d + 4 + n == 4 + fret else '!! 偏差 %d' % (d + 4 + n - 4 - fret)))
    W, R = defaultdict(list), defaultdict(list)
    for (va, d), (mn, ops, sz, imm, ed, isw) in rows.items():
        if ed is None: continue
        eo = ed + d
        (W if isw else R)[eo].append(va)
    print("\n=== 关键帧偏移写入点 ===")
    for key in (-808, -804, -772, -768, -648):
        print("  [E%+d] 写 %d: %s" % (key, len(W[key]), ' '.join('0x%x' % v for v in sorted(W[key])[:10])))
