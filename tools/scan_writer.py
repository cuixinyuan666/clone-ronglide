#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""全 .text 扫描：找出同时写 LevelObj 的 {+4/+8} 与 {+0x90/+0x94} 的函数。"""
import struct, re, bisect
from capstone import *
from capstone.x86 import *

DLL = r"D:\a_ronglide\缠中说禅\TAFLib.dll"
REP = r"D:\a_ronglide\缠中说禅\re-TAFLib.md"
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

# 解析函数表
funcs = []
for m in re.finditer(r'^### (\w+) at (0x[0-9a-f]+) \((\d+) instructions\)', open(REP, encoding='utf-8', errors='ignore').read(), re.M):
    funcs.append((int(m.group(2), 16), m.group(1), int(m.group(3))))
funcs.sort()
faddrs = [f[0] for f in funcs]
print("函数表 %d 项" % len(funcs))

def func_of(va):
    i = bisect.bisect_right(faddrs, va) - 1
    if i < 0:
        return None
    a, name, n = funcs[i]
    return name, a, n

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True
md.skipdata = True

# 反汇编 .text
text = next(s for s in secs if s[0] == '.text')
name, tva, tvs, trp, trs = text
code = data[trp:trp + max(tvs, trs)]
print(".text VA=%08x 大小=%d" % (tva + BASE, len(code)))

# 收集每函数的偏移写入集合
from collections import defaultdict
offsets = defaultdict(set)      # func -> set(disp)
stores = defaultdict(list)      # func -> [(va, disp, ops)]

cnt = 0
for ins in md.disasm(code, tva + BASE):
    cnt += 1
    if ins.id == 0:          # skipdata 伪指令
        continue
    if not ins.operands:
        continue
    o0 = ins.operands[0]
    if o0.type != X86_OP_MEM:
        continue
    if o0.mem.base in (0, X86_REG_ESP, X86_REG_EBP):
        continue
    if ins.mnemonic not in ('mov', 'movzx', 'movsx', 'fstp', 'fst', 'fild', 'fistp'):
        continue
    disp = o0.mem.disp
    if disp <= 0 or disp > 0x200:
        continue
    f = func_of(ins.address)
    if not f:
        continue
    fn = f[0]
    offsets[fn].add(disp)
    stores[fn].append((ins.address, disp, ins.mnemonic + ' ' + ins.op_str))

print("反汇编指令数 %d" % cnt)

print("\n=== 写 +0x94 的全部函数 ===")
for fn, s2 in offsets.items():
    if 0x94 in s2:
        print("  %-24s  %s" % (fn, [(hex(v),t) for v,d,t in stores[fn] if d==0x94]))
print("\n=== 同时写 {+4 或 +8} 与 {+0x90 或 +0x94} 的函数 ===")
hits = 0
for fn, s in offsets.items():
    has_idx = (4 in s) or (8 in s)
    has_st = (0x90 in s) or (0x94 in s)
    if has_idx and has_st:
        hits += 1
        print("\n%s  偏移集=%s" % (fn, sorted(hex(x) for x in s)))
        for va, d, t in stores[fn]:
            if d in (4, 8, 0x90, 0x94):
                print("   0x%08x  +0x%02X  %s" % (va, d, t))
print("\n命中 %d 个函数" % hits)
