# -*- coding: utf-8 -*-
"""
TAFLib.dll 授权码扫描器 —— 枚举所有导出函数的 Authorize(码) 调用点。

原理（实测 wnwrnew 入口 @0x10011ee0）:
    push  0xEA63            ; 授权码
    mov   ecx, <this>
    call  0x10014e60        ; ?Authorize@TAF_Calculator@@IAE_NI@Z
    test  al, al
    jne   <继续>            ; 未授权 → 返回空/0

用法:
  python scan_auth_codes.py [TAFLib.dll路径] [-o 输出json]
"""
import json
import sys
from bisect import bisect_left

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs

DEFAULT_DLL = r"D:\a_ronglide\缠中说禅\TAFLib.dll"
AUTHORIZE_VA = 0x10014E60  # ?Authorize@TAF_Calculator@@IAE_NI@Z
PAD = {0xCC, 0x90, 0x00}


def main():
    dll = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else DEFAULT_DLL
    out = None
    if "-o" in sys.argv:
        out = sys.argv[sys.argv.index("-o") + 1]

    pe = pefile.PE(dll, fast_load=True)
    pe.parse_data_directories(
        [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
    )
    base = pe.OPTIONAL_HEADER.ImageBase
    text = next(s for s in pe.sections if b".text" in s.Name)
    code = text.get_data()
    text_va = base + text.VirtualAddress

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    insns = {}
    offset = 0
    while offset < len(code):
        progressed = False
        for ins in md.disasm(code[offset:], text_va + offset):
            insns[ins.address] = ins
            offset += ins.size
            progressed = True
        if not progressed:
            offset += 1  # 无效字节, 跳过继续
    addrs = sorted(insns)
    print("disassembled insns:", len(addrs))

    # 1) 找所有 call Authorize 点
    calls = [
        a
        for a in addrs
        if insns[a].mnemonic == "call" and insns[a].op_str == "0x%x" % AUTHORIZE_VA
    ]
    calls.sort()
    print("total Authorize call sites:", len(calls))

    # 2) 回溯最近的 push 立即数（授权码）
    def code_of(call_addr):
        i = bisect_left(addrs, call_addr)  # 指向 call 本身
        for _ in range(30):
            if i <= 0:
                return None
            i -= 1
            ins = insns[addrs[i]]
            if ins.mnemonic == "push" and ins.operands and ins.operands[0].type == 2:
                return ins.operands[0].imm & 0xFFFFFFFF
        return None

    # 3) 归属到导出函数: 从导出入口线性反汇编, 跳过 ret 后继续(多出口函数),
    #    直到遇到下一个导出入口 / 连续填充 / 超限
    exports = []
    for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if not e.name:
            continue
        exports.append((base + e.address, e.name.decode()))
    exports.sort()
    export_starts = {va for va, _ in exports}
    print("total exports:", len(exports))

    result = {}
    calls_left = set(calls)
    for va, name in exports:
        body = []
        cur, n = va, 0
        while cur in insns and n < 8000:
            ins = insns[cur]
            body.append(ins)
            nxt = cur + ins.size
            if ins.mnemonic in ("ret", "retf"):
                # 后续 4 字节若为填充或已到下一导出入口 → 函数结束
                stop = True
                p = nxt
                for _ in range(4):
                    if p in export_starts or (
                        p in insns and insns[p].bytes and insns[p].bytes[0] not in PAD
                    ):
                        stop = False
                        break
                    p += 1
                if stop:
                    break
            elif nxt in export_starts:
                break
            cur = nxt
            n += 1
        found = []
        for ins in body:
            if ins.mnemonic == "call" and ins.op_str == "0x%x" % AUTHORIZE_VA:
                found.append((ins.address, code_of(ins.address)))
                calls_left.discard(ins.address)
        if found:
            result[name] = {
                "va": "0x%x" % va,
                "auth": [
                    {"call": "0x%x" % a, "code": ("0x%X" % c if c is not None else None)}
                    for a, c in found
                ],
            }

    print("exports with Authorize:", len(result))
    print("unattributed call sites:", ["0x%x" % a for a in sorted(calls_left)][:20])

    # 汇总码分布
    from collections import Counter

    cc = Counter()
    for name, d in result.items():
        for a in d["auth"]:
            cc[a["code"]] += 1
    for codev, cnt in sorted(cc.items(), key=lambda x: -x[1]):
        print("  code %s : %d" % (codev, cnt))

    if out:
        json.dump(result, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        print("written", out)


if __name__ == "__main__":
    main()
