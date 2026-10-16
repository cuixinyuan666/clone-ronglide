# -*- coding: utf-8 -*-
"""dump_chlib_vtable.py — 导出 chlib!ch::ch_api 虚表与 CreateLib/ctor 关键片段。

用法: python dump_chlib_vtable.py [-o out.txt]

chlib.dll 只导出 CreateLib/FreeLib; ch_api 的实现只能通过虚表定位。
本脚本:
  1) 反汇编 CreateLib(0x10001010) 与 ch_api::ch_api(ch_auth*)(0x100010d0);
  2) 从 ctor 首句读出 vtable 常量 (当前 = 0x10015214);
  3) 展开 vtable 全部槽位, 并标注 TAFLib NChB* 家族实际使用的槽
     (TAFLib 侧: mov ecx,[esi+0xbc] -> mov edx,[ecx] -> mov edx,[edx+SLOT] -> call edx)。
"""
import os
import struct
import sys

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs

CHLIB = r"D:/a_ronglide/clone-ronglide/ronglide-app/chlib.dll"

# TAFLib 导出 -> (授权码, 门控, ch_api 槽)  [来自 tools/re-inventory/nchbi/nchbi_entry.txt 分析]
SLOT_MAP = [
    ("NChBi",       "0x10012a50", "EA62", "P in {0,51}", "+0x34"),
    ("NChBiSta",    "0x10012c40", "EA61", "always",     "+0x38"),
    ("NChBiSta2",   "0x10012cb0", "EA61", "always",     "+0x3c"),
    ("?",           "-",          "-",    "-",          "+0x40"),
    ("NChBiZj",     "0x10012d20", "EA61", "always",     "+0x44"),
    ("?",           "-",          "-",    "-",          "+0x48"),
    ("NChBiZjOrder","0x10012e00", "EA62", "always",     "+0x4c"),
    ("?",           "-",          "-",    "-",          "+0x50"),
    ("?",           "-",          "-",    "-",          "+0x54"),
    ("NChBiFxNum",  "0x10012e70", "EA62", "always",     "+0x58"),
    ("?",           "-",          "-",    "-",          "+0x5c"),
    ("NChBiSpeed",  "0x10012f50", "EA62", "always",     "+0x60"),
    ("?",           "-",          "-",    "-",          "+0x64"),
]


def main():
    out = None
    if "-o" in sys.argv:
        out = sys.argv[sys.argv.index("-o") + 1]
    pe = pefile.PE(CHLIB, fast_load=True)
    ib = pe.OPTIONAL_HEADER.ImageBase
    data = open(CHLIB, "rb").read()

    def rva2off(rva):
        for s in pe.sections:
            if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
                return s.PointerToRawData + (rva - s.VirtualAddress)
        return None

    def rd32(va):
        off = rva2off(va - ib)
        return struct.unpack("<I", data[off:off + 4])[0]

    sec = [s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text"][0]
    code = data[sec.PointerToRawData: sec.PointerToRawData + sec.Misc_VirtualSize]
    bva = ib + sec.VirtualAddress
    md = Cs(CS_ARCH_X86, CS_MODE_32)

    lines = []
    lines.append("### chlib.dll = %s  (ImageBase %08x)" % (CHLIB, ib))

    def dis(start, end, title):
        lines.append("")
        lines.append("--- %s ---" % title)
        i = start - bva
        while i < end - bva:
            got = None
            for ins in md.disasm(code[i:i + 16], bva + i):
                got = ins
                break
            if got is None:
                i += 1
                continue
            lines.append("%08x  %-8s %s" % (got.address, got.mnemonic, got.op_str))
            i += got.size

    dis(0x10001010, 0x10001078, "CreateLib 0x10001010")
    dis(0x100010d0, 0x10001160, "ch_api::ch_api(ch_auth*) 0x100010d0 -> vtable")

    # ctor 首句 mov dword ptr [esi], 0x10015214  (C7 06 imm32) -> 立即数在 0x10001104
    vt_off = rva2off(0x10001104 - ib)
    vt = struct.unpack("<I", data[vt_off:vt_off + 4])[0]
    lines.append("")
    lines.append("### ch_api vtable = %08x  (ctor 0x10001102 立即数)" % vt)
    slot2name = {int(k, 16): (n, a, auth, gate) for (n, a, auth, gate, k) in SLOT_MAP}
    lines.append("%-8s %-10s %s" % ("槽", "实现", "TAFLib 绑定"))
    for k in range(0, 0x80, 4):
        v = rd32(vt + k)
        nm = slot2name.get(k)
        tag = "  <- %s @ %s (auth %s, %s)" % nm if nm else ""
        lines.append("+0x%02x    %08x%s" % (k, v, tag))

    text = "\n".join(lines)
    print(text)
    if out:
        with open(out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        sys.stderr.write("[written] %s\n" % out)


if __name__ == "__main__":
    main()
