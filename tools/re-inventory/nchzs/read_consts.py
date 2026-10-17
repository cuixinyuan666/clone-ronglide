import struct, sys, pefile
p = r"D:\a_ronglide\clone-ronglide\ronglide-app\chlib.dll"
pe = pefile.PE(p, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
def rd(va, n):
    for s in pe.sections:
        lo = base + s.VirtualAddress
        hi = lo + max(s.Misc_VirtualSize, s.SizeOfRawData)
        if lo <= va < hi:
            off = s.PointerToRawData + (va - lo)
            return pe.__data__[off:off+n]
    return None
for va in (0x100154b8, 0x100154c0, 0x100154c8, 0x100154e0):
    b = rd(va, 8)
    d, = struct.unpack("<d", b)
    print("0x%08x  bytes=%s  double=%r" % (va, b.hex(), d))
