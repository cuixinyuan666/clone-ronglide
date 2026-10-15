import pefile, capstone, os, struct, sys

APP = r'D:\a_ronglide\缠中说禅'
TARGET = os.path.join(APP, 'rquo.dll')

pe = pefile.PE(TARGET, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
data = open(TARGET, 'rb').read()
print('base', hex(base), 'entry', hex(base + pe.OPTIONAL_HEADER.AddressOfEntryPoint))

secs = [(s.Name.rstrip(b'\x00').decode(), base + s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData, s.VirtualAddress) for s in pe.sections]
for s in secs:
    print('sec', s[0], 'va', hex(s[1]), 'raw', hex(s[2]), 'size', hex(s[3]))

def off2va(off):
    for name, va, raw, size, rva in secs:
        if raw <= off < raw + size:
            return va + (off - raw)
    return None

def va2off(va):
    for name, sva, raw, size, rva in secs:
        if sva <= va < sva + size:
            return raw + (va - sva)
    return None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

def disasm_window(va, before=64, after=96):
    off = va2off(va)
    if off is None:
        return '  <no section>'
    lines = []
    # walk back a bit aligning by brute force: decode from va-before candidates
    start = max(0, off - before)
    for back in range(0, before):
        code = data[start + back: off + after]
        insns = list(md.disasm(code, va - (before - back)))
        hit = [i for i in insns if i.address == va]
        if hit:
            for i in insns:
                mark = '>>>' if i.address == va else '   '
                op = i.op_str
                # annotate call/jmp targets
                lines.append(f'{mark} {hex(i.address)} {i.mnemonic} {op}')
            return '\n'.join(lines)
    return '  <disasm align fail>'

strings = ['SymTable', 'stock.xdr', 'latelydays', 'StaMem', 'ActMem', 'SecTable', 'minbase', 'daybase', 'ActMem_I', 'Mem_']
found = {}
for s in strings:
    b = s.encode('ascii')
    start = 0
    while True:
        i = data.find(b, start)
        if i < 0:
            break
        # check null-terminated-ish
        va = off2va(i)
        if va:
            # full string
            end = data.find(b'\x00', i)
            full = data[i:end].decode('ascii', 'ignore')
            found.setdefault(full, []).append(va)
        start = i + 1

for full, vas in sorted(found.items()):
    print('STR', repr(full), [hex(v) for v in vas])

# scan .text for dword refs to each string VA
text = None
for name, sva, raw, size, rva in secs:
    if name == '.text':
        text = (sva, raw, size)
sva, traw, tsize = text
codebytes = data[traw:traw + tsize]

def find_refs(va):
    pat = struct.pack('<I', va)
    res = []
    st = 0
    while True:
        j = codebytes.find(pat, st)
        if j < 0:
            break
        res.append(sva + j)
        st = j + 1
    return res

for full, vas in sorted(found.items()):
    if 'rld' in full or full in ('SymTable', 'stock.xdr', 'latelydays', 'StaMem', 'ActMem', 'SecTable', 'ActMem_I', 'minbase', 'daybase'):
        pass
    for va in vas:
        refs = find_refs(va)
        if refs:
            print(f'=== refs to {full!r} @ {hex(va)}: {[hex(r) for r in refs]}')
            for r in refs[:6]:
                print(disasm_window(r))
                print('---')
