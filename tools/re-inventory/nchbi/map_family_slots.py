# -*- coding: utf-8 -*-
"""map_family_slots.py — 同族槽位映射工具（NChBi 第二批）

把三者对上：
  TAFLib 导出名  <->  ch_api 虚表槽 (+0xNN)  <->  chlib 实现函数

做法：
  1) 读 TAFLib 导出表，取 0x10012700..0x10014000 段（NChB* 家族包装层）；
  2) 每个导出反汇编 ~0x220 字节，找模式
        mov ecx, dword ptr [esi + 0xbc]        ; ch_api*
        mov edx, dword ptr [ecx]               ; vtable
        mov edx, dword ptr [edx + 0xNN]        ; 槽
  3) 读 chlib ch_api 虚表（0x10015214）槽 -> 函数值；
  4) 汇总输出。

用法: python map_family_slots.py [-o out.txt]
"""
import struct
import sys

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs

TAFLIB = r"D:\a_ronglide\clone-ronglide\ronglide-app\TAFLib.dll"
CHLIB = r"D:\a_ronglide\clone-ronglide\ronglide-app\chlib.dll"
CH_API_VT = 0x10015214


def load(path):
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
    )
    data = open(path, "rb").read()
    return pe, data, pe.OPTIONAL_HEADER.ImageBase


def sec_of(pe, va, ib):
    rva = va - ib
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s
    return None


def rd32(pe, data, ib, va):
    s = sec_of(pe, va, ib)
    if not s:
        return None
    off = s.PointerToRawData + (va - ib - s.VirtualAddress)
    return struct.unpack("<I", data[off:off + 4])[0]


def disasm_range(pe, data, ib, start, size):
    s = sec_of(pe, start, ib)
    if not s:
        return []
    base = s.PointerToRawData + (start - ib - s.VirtualAddress)
    code = data[base:base + size]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    out = []
    i = 0
    while i < len(code):
        got = None
        for ins in md.disasm(code[i:i + 16], start + i):
            got = ins
            break
        if got is None:
            i += 1
            continue
        out.append(got)
        i += got.size
    return out


def find_slot(insns):
    """在指令序列里找 [reg+0xbc] -> vtable -> [+0xNN] 的槽"""
    for k, ins in enumerate(insns):
        if ins.mnemonic == "mov" and ", dword ptr [esi + 0xbc]" in ins.op_str:
            # 往后 6 条里找 [edx + 0xNN]
            for j in range(k + 1, min(k + 6, len(insns))):
                ij = insns[j]
                if ij.mnemonic == "mov" and ij.op_str.startswith("edx") and "[edx + 0x" in ij.op_str:
                    tail = ij.op_str.split("[edx + 0x", 1)[1].rstrip("]")
                    try:
                        return int(tail, 16)
                    except ValueError:
                        return None
    return None


def main():
    out_lines = []
    tpe, tdata, tib = load(TAFLIB)
    cpe, cdata, cib = load(CHLIB)

    # 1) TAFLib 家族导出
    exports = []
    for e in tpe.DIRECTORY_ENTRY_EXPORT.symbols:
        if e.name:
            va = tib + e.address
            if 0x1000f000 <= va < 0x10015000:
                exports.append((va, e.name.decode("latin1")))
    exports.sort()

    # 2) ch_api 虚表槽 -> chlib 函数
    vt = {}
    for k in range(0, 0xd0, 4):
        v = rd32(cpe, cdata, cib, CH_API_VT + k)
        if v and 0x10000000 <= v < 0x10020000:
            vt[k] = v

    rows = []
    for va, name in exports:
        insns = disasm_range(tpe, tdata, tib, va, 0x220)
        slot = find_slot(insns)
        rows.append((va, name, slot))

    out_lines.append("# TAFLib NChB* 家族包装层 -> ch_api 虚表槽 -> chlib 实现")
    out_lines.append("# ch_api vtable = %08x (chlib)" % CH_API_VT)
    out_lines.append("")
    out_lines.append("%-10s %-16s %-8s %-12s %s" % ("TAFLib VA", "export", "slot", "chlib fn", "备注"))
    for va, name, slot in rows:
        if slot is None:
            out_lines.append("%08x %-16s %-8s %-12s %s" % (va, name, "?", "?", "未匹配到 [esi+0xbc] 分发"))
        else:
            fn = vt.get(slot)
            out_lines.append("%08x %-16s +0x%-5x %-12s %s" % (
                va, name, slot, ("%08x" % fn) if fn else "?", "已定名" if fn else "槽空"))

    # 3) 反向：虚表槽全清单
    out_lines.append("")
    out_lines.append("# ch_api vtable 全槽清单")
    for k in sorted(vt):
        used = [n for (v, n, s) in rows if s == k]
        out_lines.append("  +0x%02x : %08x   %s" % (k, vt[k], ("<- " + ",".join(used)) if used else ""))

    text = "\n".join(out_lines) + "\n"
    if "-o" in sys.argv:
        path = sys.argv[sys.argv.index("-o") + 1]
        open(path, "w", encoding="utf-8").write(text)
        print("written %s (%d exports)" % (path, len(rows)))
    else:
        print(text)


if __name__ == "__main__":
    main()
