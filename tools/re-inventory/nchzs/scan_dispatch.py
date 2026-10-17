# -*- coding: utf-8 -*-
"""scan_dispatch.py — NChZs 第五批 T4 工具

目标: 定位 engine vt[+0x10] (dispatch 0x1000ed20) 的**选用者**，以及三支成员共用的
收尾补点器 0x100069b0 的全部调用者。

扫描四类形态 (线性反汇编 + InvalidByte 续扫):
  A) 直接 call 0x1000ed20
  B) 间接 `call dword ptr [reg + 0x10]`（虚表调用）
  C) `mov reg, [reg+0x10]` 后紧邻 call（先取槽再调）
  D) 直接 call 0x100069b0

每命中点打印前 14 条指令作为上下文（含 push 立即数 = mode 实参）。

用法: python scan_dispatch.py [--dll path] [-o out.txt]
"""
import sys

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

DLL = r"D:/a_ronglide/clone-ronglide/ronglide-app/chlib.dll"
DISPATCH = 0x1000ED20
TAIL = 0x100069B0


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
    tdata = raw[text.PointerToRawData: text.PointerToRawData + text.SizeOfRawData]

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    # 线性反汇编 + InvalidByte 续扫
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
            off += 1  # InvalidByte 续扫

    lines = ["# scan_dispatch.py — chlib.dll  dispatching/收尾器 调用点扫描",
             "# dispatch = 0x%08x   tail = 0x%08x   指令总数 %d" % (DISPATCH, TAIL, len(insns)),
             ""]

    def ctx(idx, back=14, tag=""):
        lines.append("### %s  命中 @ 0x%08x  (%s %s)" % (tag, insns[idx].address,
                                                      insns[idx].mnemonic, insns[idx].op_str))
        lo = max(0, idx - back)
        for j in range(lo, min(len(insns), idx + 3)):
            mark = ">>" if j == idx else "  "
            lines.append("%s %08x  %-8s %s" % (mark, insns[j].address, insns[j].mnemonic, insns[j].op_str))
        lines.append("")

    hits = {"A": 0, "B": 0, "C": 0, "D": 0}
    for i, ins in enumerate(insns):
        if ins.mnemonic != "call":
            continue
        ops = ins.operands
        if not ops:
            continue
        op = ops[0]
        if op.type == X86_OP_IMM:
            tgt = op.imm
            if tgt == DISPATCH:
                ctx(i, 14, "A direct-dispatch")
                hits["A"] += 1
            elif tgt == TAIL:
                ctx(i, 8, "D tail-0x100069b0")
                hits["D"] += 1
        elif op.type == X86_OP_MEM:
            m = op.mem
            if m.disp == 0x10 and m.base != 0:
                ctx(i, 14, "B vtable+0x10")
                hits["B"] += 1

    # C) mov reg,[reg+0x10] 后 1-3 条内 call reg
    for i, ins in enumerate(insns):
        if ins.mnemonic != "mov" or len(ins.operands) < 2:
            continue
        d, s = ins.operands[0], ins.operands[1]
        if d.type != 1 or s.type != X86_OP_MEM or s.mem.disp != 0x10:
            continue
        for j in range(i + 1, min(i + 4, len(insns))):
            if insns[j].mnemonic == "call" and insns[j].operands and \
               insns[j].operands[0].type == 1:
                ctx(j, 10, "C slot-then-call")
                hits["C"] += 1
                break

    lines.insert(3, "# 命中统计: A=%d B=%d C=%d D=%d" % (hits["A"], hits["B"], hits["C"], hits["D"]))
    txt = "\n".join(lines)
    if out:
        open(out, "w", encoding="utf-8").write(txt)
        print("written %s  (%d lines)" % (out, len(lines)))
    else:
        print(txt)
    print("stats:", hits)


if __name__ == "__main__":
    main()
