#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""函数边界与调用者定位:
  python findfn.py <dll> <十六进制VA> [VA2 ...]
对每个地址:
  1) 向后(低地址)扫描函数头痕�迹(SEH 序言 6A FF 68 / 55 8B EC / CC 填充)给出所属函数起点;
  2) 全 .text 扫描 E8 rel32 调用该起点的位置, 并按导出表标注调用者函数名。
"""
import struct, sys, bisect
import pefile


def main():
    p = sys.argv[1]
    targets = [int(a, 16) for a in sys.argv[2:]]
    pe = pefile.PE(p, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    data = open(p, 'rb').read()
    secs = [(s.Name.rstrip(b'\0').decode(), s.VirtualAddress, s.Misc_VirtualSize,
             s.PointerToRawData, s.SizeOfRawData) for s in pe.sections]
    text = [s for s in secs if s[0] == '.text'][0]
    tva, tvs, trp, trs = base + text[1], text[2], text[3], text[4]

    def va2off(va):
        r = va - base
        for name, v, vs, rp, rs in secs:
            if v <= r < v + max(vs, rs):
                return rp + (r - v)
        return None

    # 导出表(仅 .text)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
    exps = sorted(((s.address + base, s.name.decode() if s.name else 'ord%d' % s.ordinal)
                   for s in pe.DIRECTORY_ENTRY_EXPORT.symbols
                   if 0x10001000 <= s.address + base < 0x1009A000), key=lambda x: x[0])
    eaddrs = [a for a, _ in exps]

    def fn_owner(va):
        i = bisect.bisect_right(eaddrs, va) - 1
        if i < 0:
            return '(internal)'
        return '0x%08X %s' % (exps[i][0], exps[i][1])

    def find_start(va):
        o = va2off(va)
        return o

    # 更稳的办法: 找出所有"可能的函数头", 取 <= va 的最大者
    heads = []
    md_end = trp + trs
    for i in range(trp, md_end - 6):
        if data[i: i + 3] == b'\x6A\xFF\x68':
            heads.append(base + text[1] + (i - trp))
        elif data[i] == 0x55 and data[i + 1] == 0x8B and data[i + 2] == 0xEC:
            # 需前一个字节是填充/ret, 减少误报
            if data[i - 1] in (0xCC, 0xC3) or data[i - 1:i] == b'\xC2':
                heads.append(base + text[1] + (i - trp))
        elif data[i] == 0x83 and data[i + 1] == 0xEC and data[i - 1] == 0xCC:
            heads.append(base + text[1] + (i - trp))
    heads = sorted(set(heads))

    for t in targets:
        i = bisect.bisect_right(heads, t) - 1
        if i < 0:
            print('0x%08X: no head found' % t)
            continue
        fstart = heads[i]
        span = t - fstart
        print('=' * 70)
        print('0x%08X in function 0x%08X (offset +0x%X, %d bytes)' % (t, fstart, span, span))
        print('  owner export: %s' % fn_owner(t))
        # 调用者
        callers = []
        for off in range(trp, trp + trs - 5):
            if data[off] == 0xE8:
                rel = struct.unpack_from('<i', data, off + 1)[0]
                cva = base + text[1] + (off - trp)
                if (cva + 5 + rel) == fstart:
                    callers.append(cva)
        for c in callers:
            print('  called from 0x%08X   owner: %s' % (c, fn_owner(c)))


if __name__ == '__main__':
    main()
