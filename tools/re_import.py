import pefile, re, sys

PATH = r'D:\a_ronglide\缠中说禅\MainApp.exe'
GBK = '导入完毕'.encode('gbk')

pe = pefile.PE(PATH, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
data = open(PATH, 'rb').read()

def off2va(off):
    for s in pe.sections:
        if s.PointerToRawData <= off < s.PointerToRawData + s.SizeOfRawData:
            return base + s.VirtualAddress + (off - s.PointerToRawData)
    return None

# find GBK string
idx = data.find(GBK)
print('导入完毕 gbk at file off', hex(idx))
va = off2va(idx)
print('VA', hex(va) if va else None)

# scan for dword refs
pat = va.to_bytes(4, 'little')
hits = []
start = 0
while True:
    i = data.find(pat, start)
    if i < 0:
        break
    hits.append(i)
    start = i + 1
print('dword ref hits:', [hex(h) + ' -> ' + str(hex(off2va(h))) for h in hits])

# also scan for the utf16 数据目录 refs (dialog creation anchor)
for t in ['数据目录', '数据导入']:
    b = t.encode('utf-16-le')
    offs = []
    st = 0
    while True:
        i = data.find(b, st)
        if i < 0:
            break
        offs.append(i); st = i + 2
    print(t, 'utf16 at', [hex(o) + ' VA=' + str(hex(off2va(o))) for o in offs])

# list imports from rld/rquo
pe.parse_data_directories()
print('--- imports ---')
for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
    dll = entry.dll.decode()
    if 'rld' in dll.lower() or 'rquo' in dll.lower() or 'rdm' in dll.lower():
        for imp in entry.imports:
            n = (imp.name or b'').decode() if imp.name else str(imp.ordinal)
            if 'rsfile' in n.lower() or 'import' in n.lower() or 'memory' in n.lower() or 'save' in n.lower():
                print(f'{dll}!{n} @ IAT {hex(imp.address)}')
