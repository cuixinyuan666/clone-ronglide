"""pe_info.py - quick PE32 header dump: ImageBase, DllCharacteristics, sections,
relocation/import data directories. Usage: python pe_info.py <file.dll> [...]"""
import struct
import sys


def parse(path):
    with open(path, "rb") as fh:
        data = fh.read()
    if data[:2] != b"MZ":
        print("%s: not MZ" % path)
        return
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        print("%s: no PE sig" % path)
        return
    coff = e_lfanew + 4
    num_sec, = struct.unpack_from("<H", data, coff + 2)
    opt_size, = struct.unpack_from("<H", data, coff + 16)
    opt = coff + 20
    magic, = struct.unpack_from("<H", data, opt)
    image_base = struct.unpack_from("<I", data, opt + 0x1C if magic == 0x10B else opt + 0x18)[0]
    if magic == 0x10B:
        dllchar, = struct.unpack_from("<H", data, opt + 0x46)
        dirs = opt + 0x60
        n_dirs, = struct.unpack_from("<I", data, opt + 0x5C)
    else:
        dllchar, = struct.unpack_from("<H", data, opt + 0x5E)
        dirs = opt + 0x70
        n_dirs, = struct.unpack_from("<I", data, opt + 0x6C)
    import_rva, import_size = struct.unpack_from("<II", data, dirs + 1 * 8)
    reloc_rva, reloc_size = struct.unpack_from("<II", data, dirs + 5 * 8)
    print("== %s ==" % path)
    print("  size=%d PE32%s imageBase=0x%x dllchar=0x%04x dirs=%d" % (
        len(data), "" if magic == 0x10B else "+(64?)", image_base, dllchar, n_dirs))
    print("  import: rva=0x%x size=%d   reloc: rva=0x%x size=%d%s" % (
        import_rva, import_size, reloc_rva, reloc_size,
        "  <-- NO RELOCATIONS!" if reloc_size == 0 else ""))
    print("  dynamic_base=%s" % bool(dllchar & 0x40))
    sec_off = opt + opt_size
    secs = []
    print("  sections:")
    for i in range(num_sec):
        s = sec_off + i * 0x28
        name = data[s:s + 8].rstrip(b"\0").decode("ascii", "replace")
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, s + 8)
        chars, = struct.unpack_from("<I", data, s + 0x24)
        secs.append((va, vsize, rawptr, rawsize))
        print("    %-8s va=0x%06x vsize=0x%06x raw=0x%06x rawptr=0x%06x chars=0x%08x" % (
            name, va, vsize, rawsize, rawptr, chars))

    def rva2off(rva):
        for va, vsize, rawptr, rawsize in secs:
            if va <= rva < va + max(vsize, rawsize):
                return rawptr + (rva - va)
        return None

    dlls = []
    off = rva2off(import_rva)
    if off is not None:
        for i in range(64):
            desc = off + i * 20
            oft, tds, fc, name_rva, first_thunk = struct.unpack_from("<IIIII", data, desc)
            if oft == 0 and tds == 0 and fc == 0 and name_rva == 0 and first_thunk == 0:
                break
            noff = rva2off(name_rva)
            if noff is None:
                break
            try:
                end = data.index(b"\0", noff)
            except ValueError:
                break
            dlls.append(data[noff:end].decode("ascii", "replace"))
    print("  imports: %s" % ", ".join(dlls))


if __name__ == "__main__":
    for p in sys.argv[1:]:
        parse(p)
