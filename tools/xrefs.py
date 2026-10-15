#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""通用 PE32 xref 工具:
  python xrefs.py <dll路径> <子串> [子串2 ...]
定位含子串的字符串, 并对全镜像扫描其 VA 的 4 字节小端出现点, 反汇编上下文。
"""
import struct, sys, re
from capstone import *


def load_pe(path):
    data = open(path, 'rb').read()
    e = struct.unpack_from('<I', data, 0x3C)[0]
    assert struct.unpack_from('<H', data, e + 24)[0] == 0x10B, 'not PE32'
    nsec = struct.unpack_from('<H', data, e + 6)[0]
    opt = struct.unpack_from('<H', data, e + 20)[0]
    base = struct.unpack_from('<I', data, e + 24 + 28)[0]
    sh = e + 24 + opt
    secs = []
    for i in range(nsec):
        o = sh + i * 40
        name = data[o:o + 8].rstrip(b'\0').decode('latin1')
        vs, va, rs, rp = struct.unpack_from('<IIII', data, o + 8)
        flags = struct.unpack_from('<I', data, o + 36)[0]
        secs.append({'name': name, 'va': va, 'vs': vs, 'rp': rp, 'rs': rs, 'flags': flags})
    return data, base, secs


def va2off(secs, base, va):
    rva = va - base
    for s in secs:
        if s['va'] <= rva < s['va'] + max(s['vs'], s['rs']):
            return s['rp'] + (rva - s['va'])
    return None


def off2va(secs, base, off):
    for s in secs:
        if s['rp'] <= off < s['rp'] + s['rs']:
            return base + s['va'] + (off - s['rp'])
    return None


def main():
    path = sys.argv[1]
    needles = [a.encode('gbk', 'ignore') for a in sys.argv[2:]]
    data, base, secs = load_pe(path)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    print('image base: 0x%08X  size: %d' % (base, len(data)))
    print('sections:', [(s['name'], hex(base + s['va']), hex(s['vs']), hex(s['flags'])) for s in secs])

    for nd in needles:
        print('=' * 78)
        print('needle:', nd.decode('gbk', 'ignore'))
        for m in re.finditer(re.escape(nd), data):
            # 回退到字符串起点(前一个 \0 之后)
            st = data.rfind(b'\0', max(0, m.start() - 512), m.start()) + 1
            end = data.find(b'\0', m.start())
            if end < 0:
                continue
            sva = off2va(secs, base, st)
            if sva is None:
                continue
            print('-' * 78)
            print('string @ %s (0x%08X): %s' % (hex(st), sva, data[st:end].decode('gbk', 'ignore')))
            pat = struct.pack('<I', sva)
            hits = [x.start() for x in re.finditer(re.escape(pat), data)]
            for h in hits:
                hva = off2va(secs, base, h)
                if hva is None:
                    continue
                print('  ref @ file %s VA 0x%08X' % (hex(h), hva))
                start = max(0, h - 40)
                code = data[start:h + 16]
                cva = off2va(secs, base, start)
                for ins in md.disasm(code, cva):
                    mark = ' <== ' if ins.address <= hva < ins.address + len(ins.bytes) else '      '
                    print('    %08X: %-30s%s%s' % (ins.address, ins.mnemonic + ' ' + ins.op_str, ins.bytes.hex(), mark))


if __name__ == '__main__':
    main()
