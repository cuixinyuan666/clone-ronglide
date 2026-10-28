"""dbg_wnmr_full.py - phase-by-phase debug for wnmr_full assert. """
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from x86emu import Halt, AssertHit, UnknownCall, UnknownInsn, EmuError, SENTINEL, run
from chbi51 import build_inputs, load_tdx1, read_out
from wnmr_full import (make_emu_full, call_phase, hist, diff_list,
                       DUMPS, DATASET, STACK_TOP)


def trace_wrap(emu, k=48):
    ring = []

    def decode(pc):
        ring.append(pc)
        if len(ring) > k:
            ring.pop(0)
        return emu._dec_orig(pc)
    emu._dec_orig = emu.decode
    emu.decode = decode
    return ring


def state_dump(emu, label):
    r = emu.r
    print("== state at %s ==" % label)
    print("  eax=%08x ecx=%08x edx=%08x ebx=%08x esp=%08x ebp=%08x esi=%08x edi=%08x"
          % (r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]))
    w = 0x40000000
    print("  W=%08x  m4hdr=%08x  m4.begin=%08x m4.end=%08x m4.alloc=%08x" % (
        w, w + 0x40, emu.rd32(w + 0x44), emu.rd32(w + 0x48), emu.rd32(w + 0x4c)))
    sp = r[4]
    for off in (0x0c, 0x10, 0x14, 0x18, 0x438, 0x43c, 0x440):
        print("  [esp+%03x] = %08x" % (off, emu.rd32(sp + off)))
    n_m4 = (emu.rd32(w + 0x48) - emu.rd32(w + 0x44)) // 0x28
    print("  m4 count=%d" % n_m4)


def main():
    nbars = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
    H, L, _ = load_tdx1(DATASET)
    H, L = H[:nbars], L[:nbars]
    n = len(H)

    emu, _ = make_emu_full()
    build_inputs(emu, H, L)
    out_chbi, out_duan, out_wnmr, out_pri = (emu.alloc(8 * n) for _ in range(4))
    holder = emu.alloc(4)
    emu.wr32(holder, out_duan)
    ctx, cell, series = 0x40000400, 0x40000100, 0x40000200

    ret1, _ = call_phase(emu, 0x1002C1D0, [cell, n, out_chbi, series, ctx])
    print("[chbi] ret=%08x" % (ret1 or 0))
    ret2, _ = call_phase(emu, 0x1002C710, [out_duan, ctx], eax=cell, ecx=n)
    print("[chduan] ret=%08x" % (ret2 or 0))

    exp_path = os.path.join(DUMPS, "wnmr_e2e_full_%d.json" % n)
    if os.path.exists(exp_path):
        exp = json.load(open(exp_path, encoding="utf-8"))
        for name, key in (("chbi", "chbi"), ("chduan", "chduan")):
            d = diff_list(exp.get(key) or [], read_out(emu, {"chbi": out_chbi,
                          "chduan": out_duan}[name], n))
            print("[cmp] %-7s diff=%d" % (name, len(d)))
            for row in d[:5]:
                print("    [%d] real=%r py=%r" % row)

    # W container census after CHDUAN
    w = 0x40000000
    for off, stride, nm in ((0x00, 0xA0, "m0"), (0x20, 0x28, "m2"),
                            (0x30, 0x28, "m3"), (0x40, 0x28, "m4"),
                            (0x50, 0x28, "m5")):
        b, e = emu.rd32(w + off + 4), emu.rd32(w + off + 8)
        print("  %s count=%d" % (nm, (e - b) // stride))

    try:
        ring = trace_wrap(emu)
        ret3, _ = call_phase(emu, 0x1003A7C0, [out_wnmr, holder, ctx],
                             eax=cell, ecx=n)
        print("[wnmr] ret=%08x" % (ret3 or 0))
    except AssertHit as a:
        print("ASSERT at 0x%08x" % a.caller_pc)
        print("last pcs:")
        for pc in ring[-48:]:
            mn, ops = emu.code.get(pc, ("?", "?"))
            print("  0x%08x  %s %s" % (pc, mn, ops))
        state_dump(emu, "assert")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
