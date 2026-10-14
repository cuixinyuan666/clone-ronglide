#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""递归下降反汇编 TAFLib.dll 全 .text，并统计各函数对结构体偏移的写入。
   目的：消除线性扫描的指令边界错位，检查是否漏检 +0x04/+0x08 的写入。"""
import struct, re, bisect, sys
from collections import defaultdict, deque
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
        nm = data[o:o+8].rstrip(b'\0').decode('latin1')
        vs, va, rs, rp = struct.unpack_from('<IIII', data, o + 8)
        secs.append((nm, va, vs, rp, rs))
    return data, secs

data, secs = load_pe(DLL)
TEXT = next(s for s in secs if s[0] == '.text')
_, tva, tvs, trp, trs = TEXT
text_start = BASE + tva
text_end = text_start + max(tvs, trs)
code = data[trp:trp + max(tvs, trs)]

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

def in_text(va):
    return text_start <= va < text_end
def off(va):
    return va - text_start

# ── 函数表 ──
funcs = []
for m in re.finditer(r'^### (\w+) at (0x[0-9a-f]+) \((\d+) instructions\)',
                     open(REP, encoding='utf-8', errors='ignore').read(), re.M):
    funcs.append((int(m.group(2), 16), m.group(1)))
funcs.sort()
faddrs = [f[0] for f in funcs]
def func_of(va):
    i = bisect.bisect_right(faddrs, va) - 1
    return funcs[i][1] if i >= 0 else None

# ── 递归下降 ──
decoded = {}                       # va -> (mnemonic, op_str, size)
work = deque()
for va, _ in funcs:
    if in_text(va):
        work.append(va)
# 也把 .text 起点作为种子
work.append(text_start)

guard = 0
while work and guard < 4000000:
    guard += 1
    va = work.popleft()
    if va in decoded or not in_text(va):
        continue
    ins = next(md.disasm(code[off(va):off(va)+15], va), None)
    if ins is None:
        decoded[va] = ('db', '?', 1)
        continue
    decoded[va] = (ins.mnemonic, ins.op_str, ins.size)
    nxt = va + ins.size
    mn = ins.mnemonic
    # 直接跳转目标
    tgt = None
    if ins.operands and ins.operands[0].type == X86_OP_IMM and mn[0] == 'j':
        tgt = ins.operands[0].imm
    if mn == 'jmp':
        if tgt is not None:
            work.append(tgt)
        continue
    if mn.startswith('j'):          # 条件跳转
        if tgt is not None:
            work.append(tgt)
        work.append(nxt)
        continue
    if mn == 'call':
        if tgt is not None and in_text(tgt):
            work.append(tgt)
        work.append(nxt)
        continue
    if mn in ('ret', 'int3', 'hlt', 'ud2'):
        continue
    work.append(nxt)

print("递归下降指令数: %d（线性扫描为 142,887）" % len(decoded))

# ── 统计各函数写入的结构体偏移 ──
stores = defaultdict(list)
for va, (mn, ops, sz) in decoded.items():
    if mn not in ('mov', 'movzx', 'movsx', 'fstp', 'fst', 'fild', 'fistp', 'or', 'and', 'add'):
        continue
    # 解析目标操作数
    if not ops:
        continue
    first = ops.split(',')[0].strip()
    m = re.match(r'(?:dword ptr |word ptr |byte ptr |qword ptr )?\[([a-z0-9]+)(?:\s*\+\s*(0x[0-9a-f]+|\d+))?\]$', first)
    if not m:
        continue
    reg, disp = m.group(1), m.group(2)
    if reg in ('esp', 'ebp'):
        continue
    d = int(disp, 16) if (disp and disp.startswith('0x')) else (int(disp) if disp else 0)
    if d <= 0 or d > 0x200:
        continue
    fn = func_of(va) or '?'
    stores[fn].append((va, d, mn + ' ' + ops))

print("\n=== 写 +0x04 或 +0x08 的函数（递归下降结果）===")
cnt = 0
for fn, lst in sorted(stores.items()):
    hits = [x for x in lst if x[1] in (4, 8)]
    if hits:
        cnt += 1
        print("\n%s  (%d 处)" % (fn, len(hits)))
        for va, d, t in hits[:12]:
            print("   0x%08x  +0x%02X  %s" % (va, d, t))
print("\n共 %d 个函数写 +4/+8" % cnt)

# ── 专门看 sub_1003f170 ──
print("\n=== sub_1003f170 的全部存储指令（偏移 <=0x200）===")
lst = stores.get('sub_1003f170', [])
print("  共 %d 条" % len(lst))
seen = defaultdict(int)
for va, d, t in lst:
    seen[d] += 1
print("  偏移分布:", sorted((hex(k), v) for k, v in seen.items()))
for va, d, t in lst:
    if d in (4, 8, 0x0C, 0x10, 0x90, 0x94):
        print("   0x%08x  +0x%02X  %s" % (va, d, t))
