import pefile, capstone, os

APP = r'D:\a_ronglide\缠中说禅'
TARGET = os.path.join(APP, 'rquo.dll')
pe = pefile.PE(TARGET, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
data = open(TARGET, 'rb').read()
secs = [(s.Name.rstrip(b'\x00').decode(), base + s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData) for s in pe.sections]

def va2off(va):
    for name, sva, raw, size in secs:
        if sva <= va < sva + size:
            return raw + (va - sva)
    return None

exports = []
pe.parse_data_directories([pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    if e.name:
        exports.append((base + e.address, e.name.decode()))
exports.sort()

def nearest_export(va):
    best = None
    for a, n in exports:
        if a <= va:
            best = (a, n)
        else:
            break
    if best and va - best[0] < 0x20000:
        return f'{best[1][:80]} +{hex(va-best[0])}'
    return None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

# find function start: scan backwards from 0x1001f090 for int3 padding
start = 0x1001f090
o = va2off(start)
while o > 0 and data[o-1:o] not in (b'\xcc', b'\xc3'):
    o -= 1
    start = None
# simpler: find nearest preceding int3 run
o = va2off(0x1001f090)
cand = None
i = o - 1
while i > o - 0x200:
    if data[i] == 0xcc and data[i-1] == 0xcc:
        cand = i + 1
        break
    i -= 1
followed = None
if cand:
    va_cand = None
    # find va of cand
    for name, sva, raw, size in secs:
        if raw <= cand < raw + size:
            va_cand = sva + (cand - raw)
            break
    followed = va_cand
print('orchestrator function start guess:', hex(followed) if followed else None, nearest_export(followed) if followed else '')

# disasm from start
if followed:
    off = va2off(followed)
    cnt = 0
    for i in md.disasm(data[off:off + 900], followed):
        ann = ''
        if i.mnemonic in ('call', 'jmp'):
            try:
                t = int(i.op_str, 16)
                ne = nearest_export(t)
                if ne:
                    ann = f'  ; {ne}'
            except Exception:
                pass
        for op in i.operands:
            if op.type == capstone.x86.X86_OP_IMM and 0x10000000 <= op.imm < 0x100c0000:
                o2 = va2off(op.imm)
                if o2 is not None:
                    raw = data[o2:o2+48]
                    if raw[0] >= 32 and all(32 <= c < 127 or c == 0 for c in raw[:24]):
                        s = raw.split(b'\x00')[0].decode('ascii', 'ignore')
                        if len(s) > 4:
                            ann += f'  ; "{s}"'
        print(f'{hex(i.address)} {i.mnemonic} {i.op_str}{ann}')
        cnt += 1
        if cnt >= 120:
            break

# callers of the function start
print()
print('=== callers of orchestrator ===')
text_sec = None
for s in pe.sections:
    if s.Name.rstrip(b'\x00') == b'.text':
        text_sec = s
tstart = base + text_sec.VirtualAddress
tsize = text_sec.SizeOfRawData
toff = text_sec.PointerToRawData
for m in md.disasm(data[toff:toff + tsize], tstart):
    if m.mnemonic == 'call' and m.operands and m.operands[0].type == capstone.x86.X86_OP_IMM:
        if m.operands[0].imm == followed:
            print(f'call from {hex(m.address)}  ({nearest_export(m.address)})')
