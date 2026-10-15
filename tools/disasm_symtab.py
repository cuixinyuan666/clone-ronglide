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
    if best and va - best[0] < 0x10000:
        return f'{best[1][:80]} +{hex(va-best[0])}'
    return None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True
md.skipdata = True

# disasm region, and find function prologues within
START, END = 0x10027a00, 0x10028900
off = va2off(START)
print('off:', off, 'bytes:', data[off:off+16].hex() if off else None)
blob = data[off:off + (END - START)]
funcs = set()
last_end = 0
lines = []
for i in md.disasm(blob, START):
    if i.id == 0:
        continue
    ins = f'{hex(i.address)} {i.mnemonic} {i.op_str}'
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
    # detect function prologue: push ebp / sub esp after int3 padding
    raw_at = data[va2off(i.address):va2off(i.address) + 6]
    lines.append(ins + ann)

out = '\n'.join(lines)
open(r'D:\a_ronglide\clone-ronglide\tools\_symtab_region.txt', 'w', encoding='utf-8').write(out)
print('lines:', len(lines))

# find call targets in whole .text that land in this region (possible entry points)
text_sec = None
for s in pe.sections:
    if s.Name.rstrip(b'\x00') == b'.text':
        text_sec = s
tstart = base + text_sec.VirtualAddress
tsize = text_sec.SizeOfRawData
toff = text_sec.PointerToRawData
calls = {}
for m in md.disasm(data[toff:toff + tsize], tstart):
    if m.mnemonic == 'call' and m.operands and m.operands[0].type == capstone.x86.X86_OP_IMM:
        t = m.operands[0].imm
        if START <= t < END:
            calls.setdefault(t, []).append(m.address)
for t in sorted(calls):
    callers = calls[t]
    ne = nearest_export(t)
    print(f'call target {hex(t)} ({ne}) from: {[hex(c) for c in callers[:8]]}{" ..." if len(callers)>8 else ""}')
