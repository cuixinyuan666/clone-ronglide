import pefile, os, sys

APP = r'D:\a_ronglide\缠中说禅'
for f in ['RDM_C.dll', 'rquo.dll', 'rdm.dll']:
    p = os.path.join(APP, f)
    pe = pefile.PE(p, fast_load=True)
    pe.parse_data_directories([pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
    syms = pe.DIRECTORY_ENTRY_EXPORT.symbols if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else []
    print('===', f, 'exports:', len(syms))
    for e in syms:
        n = e.name.decode() if e.name else str(e.ordinal)
        if any(k in n for k in ['Count', 'Import', 'Memory', 'Min', 'History', 'Request', 'Symbol', 'Recordset', 'Save', 'Load']):
            print(' ', hex(e.address), n[:130])
