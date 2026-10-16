# -*- coding: utf-8 -*-
"""dump_vt_nchzs.py — 读取 chlib!ch::ch_api 虚表 (0x10015214) 的 +0x60..+0xc0 槽。

用法: python dump_vt_nchzs.py [-o out.txt]
用于 NChZs 族 kickoff（T3 侦察表）: 把 TAFLib 包装层的 vt 槽 -> chlib 实现地址对上。
"""
import struct
import sys

import pefile

CHLIB = r"D:/a_ronglide/clone-ronglide/ronglide-app/chlib.dll"
VT = 0x10015214


def main():
    out = None
    if "-o" in sys.argv:
        out = sys.argv[sys.argv.index("-o") + 1]
    pe = pefile.PE(CHLIB, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    sec = next(s for s in pe.sections if b".text" in s.Name)
    raw = open(CHLIB, "rb").read()

    def rd(va):
        off = va - base - sec.VirtualAddress + sec.PointerToRawData
        return struct.unpack("<I", raw[off:off + 4])[0]

    lines = ["# chlib!ch_api vtable @ 0x%08x  slots +0x00..+0xd0" % VT]
    for off in range(0, 0xd4, 4):
        fn = rd(VT + off)
        lines.append("+0x%02x    %08x" % (off, fn))
    txt = "\n".join(lines) + "\n"
    if out:
        open(out, "w").write(txt)
        print("[written] %s" % out)
    else:
        print(txt)


if __name__ == "__main__":
    main()
