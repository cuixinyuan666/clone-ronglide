# -*- coding: utf-8 -*-
"""按成员偏移扫描 TAFLib.dll 的 .text 中对 [reg+disp] 的读写点。

用法:
    python scan_member.py 0xbc            # 扫描所有涉及 [reg+0xbc] 的指令
    python scan_member.py 0x34 --only-write
    python scan_member.py 0xbc --range 0x10012000 0x10013000

设计: 用 capstone 线性反汇编 .text, 遇 InvalidByte 跳 1 字节续扫(InvalidByte 续扫模式),
把指令的 mem 操作数 disp == 目标值的指令按 "写/读" 分类输出。
"""
import sys
import os
import struct

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_OP_IMM
import pefile


def find_dll():
    for base in (r"D:/a_ronglide/缠中说禅", r"D:/a_ronglide/clone-ronglide/ronglide-app"):
        p = os.path.join(base, "TAFLib.dll")
        if os.path.exists(p):
            return p
    raise SystemExit("TAFLib.dll not found")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        raise SystemExit(1)
    disp = int(sys.argv[1], 16) if sys.argv[1].startswith("0x") else int(sys.argv[1])
    only_write = "--only-write" in sys.argv
    lo, hi = 0, 1 << 32
    if "--range" in sys.argv:
        i = sys.argv.index("--range")
        lo, hi = int(sys.argv[i + 1], 16), int(sys.argv[i + 2], 16)

    path = find_dll()
    pe = pefile.PE(path, fast_load=True)
    ib = pe.OPTIONAL_HEADER.ImageBase
    data = open(path, "rb").read()
    sec = [s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text"][0]
    code = data[sec.PointerToRawData: sec.PointerToRawData + sec.Misc_VirtualSize]
    base_va = ib + sec.VirtualAddress

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    hits = []
    i = 0
    n = len(code)
    while i < n:
        got = None
        for ins in md.disasm(code[i:i + 16], base_va + i):
            got = ins
            break
        if got is None:
            i += 1
            continue
        if lo <= got.address < hi:
            mems = [o for o in got.operands if o.type == X86_OP_MEM]
            for o in mems:
                if o.mem.disp == disp:
                    # 是否写: 目标操作数(第 0 个)是 mem
                    is_write = got.operands[0].type == X86_OP_MEM and \
                        got.operands[0].mem.disp == disp
                    if only_write and not is_write:
                        continue
                    hits.append((got.address, "W" if is_write else "R",
                                 "%s %s" % (got.mnemonic, got.op_str)))
                    break
        i += got.size

    print("# scan disp=0x%x  hits=%d  (%s)" % (disp, len(hits), os.path.basename(path)))
    for a, k, t in hits:
        print("%08x  %s  %s" % (a, k, t))


if __name__ == "__main__":
    main()
