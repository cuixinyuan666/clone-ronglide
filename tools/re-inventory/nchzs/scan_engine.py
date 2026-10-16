# -*- coding: utf-8 -*-
"""scan_engine.py — NChZs 第二批工具: 全量 chlib 扫描辅助

三件事:
 1) 扫描 .text 中所有引用立即数 0x5d (中枢段 stride) 的指令 -> 定位容器生产者/消费者
 2) 枚举 .rdata 中的候选虚表 (连续 >=4 个指向 .text 的 dword)
 3) 扫描 .text 中 `mov dword ptr [reg+0x18], reg` 形态 (this[+0x18] 引擎字段写) -> 找构造点

用法: python scan_engine.py [--dll path] [-o out.txt]
"""
import struct
import sys

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs

DLL = r"D:/a_ronglide/clone-ronglide/ronglide-app/chlib.dll"


def main():
    dll = DLL
    argv = sys.argv[1:]
    if "--dll" in argv:
        dll = argv[argv.index("--dll") + 1]
    out = None
    if "-o" in argv:
        out = argv[argv.index("-o") + 1]

    pe = pefile.PE(dll)
    base = pe.OPTIONAL_HEADER.ImageBase
    text = next(s for s in pe.sections if b".text" in s.Name)
    raw = open(dll, "rb").read()
    tstart = base + text.VirtualAddress
    tend = tstart + text.Misc_VirtualSize
    tdata = raw[text.PointerToRawData: text.PointerToRawData + text.SizeOfRawData]

    def va2off(va):
        return va - base - text.VirtualAddress + text.PointerToRawData

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    lines = []

    # ---- 1) 立即数 0x5d 引用 ----
    lines.append("# ===== [1] 指令引用立即数 0x5d (中枢段 stride) =====")
    for ins in md.disasm(tdata, tstart):
        if "0x5d" in ins.op_str and "," in ins.op_str:
            # 排除 0x5d 作为内存位移 (如 [eax+0x5d]) 的命中? 先全报
            lines.append("%08x  %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))

    # ---- 2) 候选虚表: .rdata 中连续 >=5 dword 落在 .text ----
    lines.append("")
    lines.append("# ===== [2] 候选虚表 (.rdata 中连续指向 .text 的 dword 串) =====")
    rdata = next((s for s in pe.sections if b".rdata" in s.Name), None)
    if rdata:
        rstart = base + rdata.VirtualAddress
        rraw = raw[rdata.PointerToRawData: rdata.PointerToRawData + rdata.SizeOfRawData]
        n = len(rraw) // 4
        vals = list(struct.unpack("<%dI" % n, rraw[:n * 4]))
        i = 0
        while i < n:
            v = vals[i]
            if tstart <= v < tend:
                j = i
                while j < n and tstart <= vals[j] < tend:
                    j += 1
                if j - i >= 5:
                    vt_va = rstart + i * 4
                    ents = " ".join("%08x" % vals[k] for k in range(i, min(j, i + 24)))
                    lines.append("vt @ %08x  len=%d : %s" % (vt_va, j - i, ents))
                i = j
            else:
                i += 1

    # ---- 3) this[+0x18] 引擎字段写 ----
    lines.append("")
    lines.append("# ===== [3] mov dword ptr [reg+0x18], reg 形态 (引擎字段写) =====")
    for ins in md.disasm(tdata, tstart):
        if ins.mnemonic in ("mov", "lea") and "dword ptr [" in ins.op_str and "] ," not in ins.op_str:
            o = ins.op_str
            if "0x18] ," in o.replace(" ", "") or "+0x18]," in o.replace(" ", ""):
                lines.append("%08x  %-8s %s" % (ins.address, ins.mnemonic, o))

    txt = "\n".join(lines) + "\n"
    if out:
        open(out, "w", encoding="utf-8").write(txt)
        print("[written] %s  (%d lines)" % (out, len(lines)))
    else:
        print(txt)


if __name__ == "__main__":
    main()
