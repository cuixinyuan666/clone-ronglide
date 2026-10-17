# -*- coding: utf-8 -*-
"""scan_xref.py — 通用交叉引用扫描（chlib / TAFLib 双模块）

对每个目标 VA:
  (a) 线性反汇编(InvalidByte 续扫)中任何指令的立即数等于目标 -> 打印上下文
  (b) 任意 section 中出现的 4 字节小端 dword 等于目标 -> 打印地址（指针表/虚表）

用法: python scan_xref.py 0x1000ed20 0x10011500 --dll a.dll [--dll2 b.dll] [--back 10]
"""
import struct
import sys

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM

DLLS = [r"D:/a_ronglide/clone-ronglide/ronglide-app/chlib.dll",
        r"D:/a_ronglide/clone-ronglide/ronglide-app/TAFLib.dll"]


def load(path):
    pe = pefile.PE(path)
    base = pe.OPTIONAL_HEADER.ImageBase
    raw = open(path, "rb").read()
    return pe, base, raw


def main():
    argv = sys.argv[1:]
    targets = []
    back = 10
    dlls = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--back":
            back = int(argv[i + 1], 0)
            i += 2
            continue
        if a == "--dll":
            dlls.append(argv[i + 1])
            i += 2
            continue
        targets.append(int(a, 0))
        i += 1
    if not dlls:
        dlls = DLLS

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    for path in dlls:
        pe, base, raw = load(path)
        print("=" * 78)
        print("## DLL %s  base=0x%08x" % (path, base))
        text = next((s for s in pe.sections if b".text" in s.Name), None)
        if text is None:
            continue
        tstart = base + text.VirtualAddress
        tdata = raw[text.PointerToRawData: text.PointerToRawData + text.SizeOfRawData]

        insns = []
        off = 0
        n = len(tdata)
        while off < n:
            got = False
            for ins in md.disasm(tdata[off:off + 16], tstart + off):
                insns.append(ins)
                off += ins.size
                got = True
                break
            if not got:
                off += 1

        idx = {ins.address: k for k, ins in enumerate(insns)}

        for t in targets:
            print("\n---- target 0x%08x ----" % t)
            found = 0
            for k, ins in enumerate(insns):
                hit = any(op.type == X86_OP_IMM and op.imm == t for op in ins.operands)
                if hit:
                    found += 1
                    print("  [code] 0x%08x  %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))
                    lo = max(0, k - back)
                    for j in range(lo, min(len(insns), k + 2)):
                        pre = "   >>" if j == k else "      "
                        print("%s %08x  %-8s %s" % (pre, insns[j].address,
                                                    insns[j].mnemonic, insns[j].op_str))
            if not found:
                print("  [code] 无立即数引用")
            # data refs
            for s in pe.sections:
                sec = raw[s.PointerToRawData: s.PointerToRawData + s.SizeOfRawData]
                needle = struct.pack("<I", t)
                p = sec.find(needle)
                while p >= 0:
                    if p % 4 == 0:
                        print("  [data] %s + 0x%x -> VA 0x%08x" %
                              (s.Name.rstrip(b"\x00").decode(errors="replace"),
                               p, base + s.VirtualAddress + p))
                    p = sec.find(needle, p + 1)


if __name__ == "__main__":
    main()
