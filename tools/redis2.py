#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""重新反汇编 TAFLib.dll 的 sub_10056190，精确跟踪 esp（含被调者 ret N 清理）。"""
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
        name = data[o:o+8].rstrip(b'\0').decode('latin1')
        vs, va, rs, rp = struct.unpack_from('<IIII', data, o + 8)
        secs.append((name, va, vs, rp, rs))
    return data, secs

data, secs = load_pe(DLL)
def va2off(va):
    rva = va - BASE
    for name, va_, vs, rp, rs in secs:
        if va_ <= rva < va_ + max(vs, rs):
            return rp + (rva - va_)
    return None

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

_retN_cache = {}
def callee_retN(target):
    if target in _retN_cache:
        return _retN_cache[target]
    o = va2off(target)
    res = 0
    if o is not None:
        chunk = data[o:o+0x1000]
        for ins in md.disasm(chunk, target):
            if ins.mnemonic == 'ret':
                res = ins.operands[0].imm if ins.operands else 0
                break
            if ins.mnemonic == 'int3':
                break
    _retN_cache[target] = res
    return res

code = data[va2off(FUNC_VA):va2off(FUNC_END)]
rows = []
delta = 0
for ins in md.disasm(code, FUNC_VA):
    d_before = delta
    esp_off = None
    for op in ins.operands:
        if op.type == X86_OP_MEM and op.mem.base == X86_REG_ESP:
            esp_off = op.mem.disp + d_before
            break
    is_write = False
    if esp_off is not None and ins.operands:
        o0 = ins.operands[0]
        if o0.type == X86_OP_MEM and o0.mem.base == X86_REG_ESP:
            is_write = True
    rows.append((ins.address, ins.mnemonic, ins.op_str, d_before, esp_off, is_write))
    if ins.mnemonic == 'push':
        delta -= 4
    elif ins.mnemonic == 'pop':
        delta += 4
    elif ins.mnemonic == 'sub' and ins.operands and ins.operands[0].type == X86_OP_REG \
            and ins.operands[0].reg == X86_REG_ESP:
        delta -= ins.operands[1].imm
    elif ins.mnemonic == 'add' and ins.operands and ins.operands[0].type == X86_OP_REG \
            and ins.operands[0].reg == X86_REG_ESP:
        delta += ins.operands[1].imm
    elif ins.mnemonic == 'call' and ins.operands and ins.operands[0].type == X86_OP_IMM:
        delta += 4 + callee_retN(ins.operands[0].imm)

print("指令数 %d, 结束 esp 偏移 %d" % (len(rows), delta))

W, R = {}, {}
for va, mn, ops, d, eo, isw in rows:
    if eo is None:
        continue
    if isw:
        W[eo] = W.get(eo, 0) + 1
    else:
        R[eo] = R.get(eo, 0) + 1

print("\n=== 帧相对偏移 写入/读取 (负=局部变量) ===")
for o in sorted(set(list(W) + list(R))):
    w = W.get(o, 0); r = R.get(o, 0)
    tag = '   <== 只读不写!' if (w == 0 and r > 50) else ''
    print("  [E%+d]  写=%-3d 读=%-3d%s" % (o, w, r, tag))
