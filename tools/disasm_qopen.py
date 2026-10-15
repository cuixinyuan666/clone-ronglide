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
    if best and va - best[0] < 0x8000:
        return f'{best[1][:90]} +{hex(va-best[0])}'
    return None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

def disasm(va, n=220, tag=''):
    off = va2off(va)
    print(f'=== {tag} @ {hex(va)} (file off {hex(off)}) ===')
    cnt = 0
    for i in md.disasm(data[off:off + n*10], va):
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
                    if all(32 <= c < 127 or c == 0 for c in raw[:24]) and raw[0] >= 32:
                        s = raw.split(b'\x00')[0].decode('ascii', 'ignore')
                        if len(s) > 3:
                            ann += f'  ; "{s}"'
        print(f'{hex(i.address)} {i.mnemonic} {i.op_str}{ann}')
        cnt += 1
        if cnt >= n:
            break

disasm(base + 0x479f0, 200, 'q_module(x) <- QuoApi::Initialize target')
