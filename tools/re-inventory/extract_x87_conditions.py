# -*- coding: utf-8 -*-
"""
x87 浮点条件提取器（通用逆向工具）

扫描指定函数区间, 提取所有 x87 比较三元组:
    [fld A] [fld B] fcompp  ->  fnstsw ax  ->  test ah, MASK  ->  jcc TARGET
并给出操作数来源(A/B)与按 Intel 语义解码的分支条件。

Intel 语义速查（FNSTSW 后 AX=状态字; AH: C0=b0, C2=b2, C3=b6）:
    ST0 > ST1: C3=0 C2=0 C0=0     ST0 < ST1: C3=0 C2=0 C0=1
    ST0 = ST1: C3=1 C2=0 C0=0     Unordered: C3=1 C2=1 C0=1

    test ah,0x41 ; jne : 落空 = ST0 >  ST1   (jne 去 else)
    test ah,0x41 ; jp  : 跳转 = ST0 =  ST1 (含Unordered)
    test ah,0x05 ; jp  : 落空 = ST0 <  ST1   (jp 跳走 = 非小于)
    test ah,0x01 ; jne : 跳转 = ST0 <  ST1 (含Unordered)

用法: python extract_x87_conditions.py <start_va> <end_va> [-o out.txt]
"""
import sys

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs

DLL = r"D:\a_ronglide\缠中说禅\TAFLib.dll"

MASK_DECODE = {
    (0x41, "jne"): "fall=ST0>ST1 (jne跳=not>)",
    (0x41, "je"): "jump=ST0=ST1|unord (je跳=not>且非<: 等或不可比)",
    (0x41, "jp"): "jump=ST0=ST1 (含unord)",
    (0x41, "jnp"): "jump=ST0<>ST1 (不含unord)",
    (0x05, "jp"): "fall=ST0<ST1 (jp跳=非<)",
    (0x05, "jnp"): "jump=ST0<ST1 (不含unord)",
    (0x01, "jne"): "jump=ST0<ST1 (含unord)",
    (0x01, "je"): "jump=not<|unord",
}


def main():
    start = int(sys.argv[1], 16)
    end = int(sys.argv[2], 16)
    out = None
    if "-o" in sys.argv:
        out = sys.argv[sys.argv.index("-o") + 1]

    pe = pefile.PE(DLL, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    sec = next(s for s in pe.sections if b".text" in s.Name)

    def va2off(va):
        return va - base - sec.VirtualAddress + sec.PointerToRawData

    code = pe.__data__[va2off(start): va2off(end)]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    insns = list(md.disasm(code, start))

    lines = []
    res = []
    n_fl = []
    for i, ins in enumerate(insns):
        m = ins.mnemonic
        if m == "fld":
            n_fl.append((ins.address, ins.op_str))
        elif m in ("fcompp", "fcomp"):
            # 取最近两次 fld
            a = n_fl[-2] if len(n_fl) >= 2 else ("?", "?")
            b = n_fl[-1] if len(n_fl) >= 1 else ("?", "?")
            # 找后续 test ah, MASK 与 jcc (最多向后 6 条)
            mask, jcc, tgt = None, None, None
            for j in range(i + 1, min(i + 7, len(insns))):
                if insns[j].mnemonic == "test" and "ah" in insns[j].op_str:
                    mask = int(insns[j].op_str.split(",")[1].strip(), 16)
                elif insns[j].mnemonic.startswith("j") and mask is not None:
                    jcc, tgt = insns[j].mnemonic, insns[j].op_str
                    break
            dec = MASK_DECODE.get((mask, jcc), "")
            # ST0 = 第二次 fld(B), ST1 = 第一次 fld(A)
            line = ("%x  fld %s [%s] / fld %s [%s] ; test ah,%s ; %s %s   ==> %s"
                    % (ins.address, "?", a[1], "?", b[1], hex(mask) if mask else "?",
                       jcc or "?", tgt or "?", dec))
            lines.append(line)
            res.append((ins.address, a[1], b[1], mask, jcc, tgt, dec))
            n_fl = []
    text = "\n".join(lines)
    print(text if len(lines) < 60 else "\n".join(lines[:60]) + "\n...(共%d条)" % len(lines))
    if out:
        open(out, "w").write(text + "\n")
        print("written", out, len(res), "conditions")


if __name__ == "__main__":
    main()
