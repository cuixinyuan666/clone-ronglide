#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从二进制直接反汇编指定 VA 范围。"""
import struct, sys
from capstone import *
from capstone.x86 import *

DLL = r"D:\a_ronglide\缠中说禅\TAFLib.dll"
BASE = 0x10000000

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

def dump(start, end, label=''):
    print("=" * 70)
    print("%s  0x%08x .. 0x%08x" % (label, start, end))
    code = data[va2off(start):va2off(end)]
    for ins in md.disasm(code, start):
        b = ins.bytes.hex()
        print("0x%08x: %-28s ; %s" % (ins.address, ins.mnemonic + ' ' + ins.op_str, b))

if __name__ == '__main__':
    args = sys.argv[1:]
    if len(args) >= 2:
        dump(int(args[0], 16), int(args[1], 16), args[2] if len(args) > 2 else '')
    else:
        dump(0x1003d910, 0x1003d9e0, 'sub_1003d910')
