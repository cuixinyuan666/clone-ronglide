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
    if best and va - best[0] < 0x3000:
        return f'{best[1]} +{hex(va-best[0])}'
    return None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

def disasm(va, n=200, tag=''):
    off = va2off(va)
    print(f'=== disasm @ {hex(va)} {tag} ===')
    cnt = 0
    for i in md.disasm(data[off:off + n*8], va):
        ann = ''
        if i.mnemonic in ('call', 'jmp'):
            try:
                t = int(i.op_str, 16)
                ne = nearest_export(t)
                if ne:
                    ann = f'  ; {ne}'
            except Exception:
                pass
        print(f'{hex(i.address)} {i.mnemonic} {i.op_str}{ann}')
        cnt += 1
        if cnt >= n:
            break

disasm(base + 0x4daa0, 220, 'ImportHistory main impl')
