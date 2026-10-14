#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""用自建反汇编核对 sub_10056190 的 [esp+40h]/[esp+44h] 槽位。"""
import struct
from capstone import *
from capstone.x86 import *

DLL = r"D:\a_ronglide\缠中说禅\TAFLib.dll"
BASE = 0x10000000
FUNC_VA = 0x10056190
FUNC_END = 0x1005cc00

def load_pe(path):
    data = open(path, 'rb').read()
    e = struct.unpack_from('<I', data, 0x3C)[0]
    nsec = struct.unpack_from('<H', data, e + 6)[0]
    opt = struct.unpack_from('<H', data, e + 20)[0]
    sh = e + 24 + opt
    secs = []
    for i in range(nsec):
        o = sh + i * 40
        nm = data[o:o+8].rstrip(b'\0').decode('latin1')
        vs, va, rs, rp = struct.unpack_from('<IIII', data, o + 8)
        secs.append((nm, va, vs, rp, rs))
    return data, secs

data, secs = load_pe(DLL)
def va2off(va):
    rva = va - BASE
    for nm, va_, vs, rp, rs in secs:
        if va_ <= rva < va_ + max(vs, rs):
            return rp + (rva - va_)
    return None

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True
_rc = {}
def retN(t):
    if t in _rc: return _rc[t]
    o = va2off(t); r = 0
    if o is not None:
        for ins in md.disasm(data[o:o+0x1000], t):
            if ins.mnemonic == 'ret':
                r = ins.operands[0].imm if ins.operands else 0; break
            if ins.mnemonic == 'int3': break
    _rc[t] = r; return r

code = data[va2off(FUNC_VA):va2off(FUNC_END)]
delta = 0
rows = []
for ins in md.disasm(code, FUNC_VA):
    d = delta
    eo = None
    for op in ins.operands:
        if op.type == X86_OP_MEM and op.mem.base == X86_REG_ESP:
            eo = op.mem.disp + d; break
    isw = bool(ins.operands) and ins.operands[0].type == X86_OP_MEM \
        and ins.operands[0].mem.base == X86_REG_ESP
    rows.append((ins.address, ins.mnemonic + ' ' + ins.op_str, eo, isw, d))
    if ins.mnemonic == 'push': delta -= 4
    elif ins.mnemonic == 'pop': delta += 4
    elif ins.mnemonic in ('sub',) and ins.operands and ins.operands[0].type == X86_OP_REG \
            and ins.operands[0].reg == X86_REG_ESP: delta -= ins.operands[1].imm
    elif ins.mnemonic in ('add',) and ins.operands and ins.operands[0].type == X86_OP_REG \
            and ins.operands[0].reg == X86_REG_ESP: delta += ins.operands[1].imm
    elif ins.mnemonic == 'call' and ins.operands and ins.operands[0].type == X86_OP_IMM:
        delta += 4 + retN(ins.operands[0].imm)

# 报告里 [esp+40h] 首次出现处
print("=== 报告中标为 [esp+40h] 的地址，在我方反汇编中的帧偏移 ===")
for target in (0x100561d1, 0x100561d5, 0x10056fd7, 0x1005a15c, 0x1005a165, 0x1005a169, 0x1005a174):
    for va, t, eo, isw, d in rows:
        if va == target:
            print("  0x%08x  %-26s  esp_delta=%+d  帧偏移=%s  %s" %
                  (va, t, d, ('%+d' % eo) if eo is not None else '-', '写' if isw else '读'))
            break

# 统计某个帧偏移的全部写/读
import collections
W = collections.defaultdict(list); R = collections.defaultdict(list)
for va, t, eo, isw, d in rows:
    if eo is None: continue
    (W if isw else R)[eo].append((va, t))

print("\n=== 报告 [esp+40h] 对应的帧偏移（-0x3F8）统计 ===")
KEY = -0x3F8
print("  写入点 %d 个:" % len(W[KEY]))
for va, t in W[KEY][:20]: print("     0x%08x  %s" % (va, t))
print("  读取点 %d 个" % len(R[KEY]))
for va, t in R[KEY][:8]: print("     0x%08x  %s" % (va, t))
