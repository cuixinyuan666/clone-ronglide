# -*- coding: utf-8 -*-
"""
TAFLib.dll 函数注册表解析器（权威「公式名↔实现」映射）

实测布局（2026-10-16）:
  .rdata 中两张表:
  ① 指针表: 8 字节/条 = [seq:u32][fn_ptr:u32]，seq 连续递增
  ② 名字表: 80 字节/条 = [hdr(u32, 形如 0x??090500)][0][id:u32][0x24 zeros][name:32B]
  关联规则: 名字表 id = N  <->  指针表 seq = N+1   （实测固定 +1 偏移）
  name(如 BIZHONGSHU) -> fn_ptr(0x1000f910) -> 导出名(CalcProc_ChZhongShu)

输出: registry.json = { FORMULA_NAME: {export, va, seq} }
用法: python scan_registry.py [-o registry.json]
"""
import json
import re
import struct
import sys

import pefile

DLL = r"D:\a_ronglide\缠中说禅\TAFLib.dll"


def main():
    pe = pefile.PE(DLL, fast_load=True)
    pe.parse_data_directories(
        [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
    )
    raw = pe.__data__
    base = pe.OPTIONAL_HEADER.ImageBase

    va2name = {}
    for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if e.name:
            va2name[base + e.address] = e.name.decode()

    rdata = next(s for s in pe.sections if b".data" in s.Name)
    lo, hi = rdata.PointerToRawData, rdata.PointerToRawData + rdata.SizeOfRawData
    text_lo = base + 0x1000
    text_hi = base + 0x6F000

    # ---- ① 指针表: 收集所有 8 对齐 [seq][ptr] 且 seq 连续的结构 ----
    seq2ptr = {}
    for off in range(lo, hi - 8, 4):
        seq, ptr = struct.unpack_from("<II", raw, off)
        if 0x100 <= seq <= 0x20000 and text_lo <= ptr < text_hi:
            if seq not in seq2ptr:
                seq2ptr[seq] = ptr
    # 去噪: 只保留最长连续 seq 段
    seqs = sorted(seq2ptr)
    best, cur = [], []
    for s in seqs:
        if cur and s == cur[-1] + 1 and seq2ptr[s] != seq2ptr[cur[-1]]:
            cur.append(s)
        else:
            if len(cur) > len(best):
                best = cur
            cur = [s]
    if len(cur) > len(best):
        best = cur
    print("ptr table: seq %d..%d (%d entries)" % (best[0], best[-1], len(best)))
    keep = set(best)
    seq2ptr = {s: seq2ptr[s] for s in keep}

    # ---- ② 名字表: 通用扫描 —— name@X, id@(X-0x28), 其间 0x24 字节为 0 ----
    # (实测 .data 中存在多段名字表, hdr 字节因函数组而异, 故不校验 hdr)
    names = {}
    namere = re.compile(rb"[A-Z0-9_]{2,31}\x00")
    for x in range(lo + 0x28, hi - 0x20, 4):
        fid = struct.unpack_from("<I", raw, x - 0x28)[0]
        if (fid + 1) not in seq2ptr:
            continue
        if raw[x - 0x24 : x] != b"\x00" * 0x24:
            continue
        m = namere.match(raw[x : x + 0x20])
        if not m:
            continue
        names[fid] = (raw[x : x + m.end() - 1].decode(), x)
    print("name table records:", len(names))

    # ---- ③ 关联 (名字 id = N <-> 指针 seq = N+1) ----
    out = {}
    for fid, (name, off) in sorted(names.items()):
        ptr = seq2ptr.get(fid + 1)
        if ptr is None:
            continue
        exp = va2name.get(ptr, "?")
        m = re.match(r"\?(_?)CalcProc_(\w+)@", exp)
        out[name] = {
            "export": m.group(2) if m else exp,
            "va": "0x%x" % ptr,
            "seq": fid + 1,
        }

    # 反查: 导出名 -> 公式名 (一个导出可能多个名字)
    exp2name = {}
    for name, v in out.items():
        exp2name.setdefault(v["export"], []).append(name)

    print("mapped:", len(out), " distinct exports:", len(exp2name))
    if "-o" in sys.argv:
        json.dump(out, open(sys.argv[sys.argv.index("-o") + 1], "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1, sort_keys=True)
        print("written")


if __name__ == "__main__":
    main()
