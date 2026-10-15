import pefile, capstone, os, struct

APP = r'D:\a_ronglide\缠中说禅'
TARGET = os.path.join(APP, 'RDM_C.dll')
pe = pefile.PE(TARGET, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
data = open(TARGET, 'rb').read()
secs = [(s.Name.rstrip(b'\x00').decode(), base + s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData, s.VirtualAddress) for s in pe.sections]

def va2off(va):
    for name, sva, raw, size, rva in secs:
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
    lo, hi = 0, len(exports) - 1
    best = None
    for a, n in exports:
        if a <= va:
            best = (a, n)
        else:
            break
    if best and va - best[0] < 0x2000:
        return f'{best[1]} (+{hex(va-best[0])})'
    return None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

# ImportHistory RVA 0x4360
start_va = base + 0x4360
off = va2off(start_va)
code = data[off:off + 0x400]
print('=== ImportHistory disasm ===')
n = 0
for i in md.disasm(code, start_va):
    ann = ''
    if i.mnemonic == 'call':
        try:
            t = int(i.op_str, 16)
            ne = nearest_export(t)
            ann = f'  ; {ne}' if ne else ''
        except Exception:
            pass
    print(f'{hex(i.address)} {i.mnemonic} {i.op_str}{ann}')
    n += 1
    if n > 150:
        break
