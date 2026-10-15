import pefile, os

APP = r'D:\a_ronglide\缠中说禅'
TARGET = os.path.join(APP, 'rquo.dll')
pe = pefile.PE(TARGET, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
data = open(TARGET, 'rb').read()
secs = [(s.Name.rstrip(b'\x00').decode(), base + s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData) for s in pe.sections]

targets = {
    0x1009be3c: '%s/SymTable.tmp',
    0x1009be4c: '%s/SymTable.rs',
    0x1009be5c: 'open symbol table file %02X %s',
    0x1009be7c: 'update symbol table %02X %d',
    0x1009be98: '%s/StaMem_%02X.tmp',
    0x1009beac: '%s/StaMem_%02X.rs',
    0x1009bec0: 'write active memory file %02X',
    0x1009bee0: '%s/ActMem_%02X.tmp',
    0x1009bef4: '%s/ActMem_%02X.rs',
    0x1009bf08: '%s/ActMem_I_%02X.tmp',
    0x1009bf20: '%s/ActMem_I_%02X.rs',
    0x1009bf34: 'making symbol lately days %02X',
    0x1009bf54: 'making symbol lately days %s',
    0x1009bf74: '%s/latelydays.bin',
}

def off2va(off):
    for name, sva, raw, size in secs:
        if raw <= off < raw + size:
            return sva + (off - raw)
    return None

for tva, tname in targets.items():
    pat = tva.to_bytes(4, 'little')
    hits = []
    pos = 0
    while True:
        p = data.find(pat, pos)
        if p < 0:
            break
        hits.append(off2va(p))
        pos = p + 1
    print(f'{hex(tva)} {tname!r}: refs at {[hex(h) for h in hits]}')
