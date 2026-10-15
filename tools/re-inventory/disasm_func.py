# -*- coding: utf-8 -*-
"""
函数级反汇编工具（InvalidByte 续扫模式）

capstone 线性 disasm 遇到无效字节会静默停止; 本工具在停止点跳 1 字节续扫,
直到函数边界: 连续 int3(0xCC)/nop 填充 或 撞到下一个函数的序.prologue。

用法: python disasm_func.py <start_va_hex> [-o out.txt] [--max 0x8000]
输出格式与 core_*.txt 一致: "地址  助记符  操作数"
"""
import sys

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_INS_INT3, X86_INS_NOP

DLL = r"D:\a_ronglide\缠中说禅\TAFLib.dll"


def main():
    start = int(sys.argv[1], 16)
    out = None
    max_len = 0x8000
    argv = sys.argv[2:]
    if "-o" in argv:
        out = argv[argv.index("-o") + 1]
    if "--max" in argv:
        max_len = int(argv[argv.index("--max") + 1], 16)

    pe = pefile.PE(DLL, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    sec = next(s for s in pe.sections if b".text" in s.Name)

    def va2off(va):
        return va - base - sec.VirtualAddress + sec.PointerToRawData

    md = Cs(CS_ARCH_X86, CS_MODE_32)

    lines = []
    va = start
    end_va = None
    bad_skips = 0
    while va < start + max_len:
        code = pe.__data__[va2off(va): va2off(va) + 0x1000]
        got = list(md.disasm(code, va))
        if not got:
            bad_skips += 1
            va += 1
            continue
        stop = False
        for ins in got:
            # 边界: int3 填充 或 连续3条nop(对齐填充) 视为函数结束
            if ins.mnemonic == "int3":
                stop = True
                break
            lines.append("%08x  %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))
        va = got[-1].address + got[-1].size
        if stop:
            # 吞掉尾部 int3 填充, 记录函数结束位置
            end_va = va
            break
        # capstone 静默停止(无效字节): 跳 1 字节续扫
        if not got or got[-1].address + got[-1].size < va + len(code):
            bad_skips += 1
            va += 1

    text = "\n".join(lines)
    print(text)
    sys.stderr.write("\n[info] end≈%s  insns=%d  resync_skips=%d\n"
                     % (hex(end_va) if end_va else "?", len(lines), bad_skips))
    if out:
        with open(out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        sys.stderr.write("[info] written %s\n" % out)


if __name__ == "__main__":
    main()
