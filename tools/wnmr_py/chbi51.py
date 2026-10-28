"""chbi51.py - run the faithful CHBI P=51 pipeline (0x1002c4b0 / 0x1002c1d0)
under x86emu and expose it as a Python function for verification runs.

Usage:
  python chbi51.py --selftest
  python chbi51.py --replay <file.1> [--max-bars N] [--use-c1d0] [--dump-json out.json]
"""
import argparse
import json
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from x86emu import (Emu, Halt, AssertHit, UnknownCall, EmuError, SENTINEL,
                    HOOK_AUTH, make_emu)

HERE = os.path.dirname(os.path.abspath(__file__))
EVIDENCE_DIR = os.path.normpath(os.path.join(HERE, "..", "re-inventory", "chbi"))

# fixed address layout (deliberately far from code @0x1000xxxx and its data)
W_ENGINE = 0x40000000   # engine; m0@W+0 m5@W+0x50, ContA/B/C @ +0x20/+0x30/+0x40
CELL = 0x40000100       # holds pointer to engine (arg1 = W**)
SERIES = 0x40000200     # {pH, pL, pP}
P_VAL = 0x40000300      # double P value
IFACE = 0x40000400      # interface object; [IFACE] = vtbl
VTBL = 0x40000500       # vtbl[1] = EA62 gate hook
STACK_TOP = 0x30100000

ENTRY_C4B0 = 0x1002C4B0
ENTRY_C1D0 = 0x1002C1D0


def _init_container(emu, header, stride, cap_elems):
    buf = emu.alloc(stride * cap_elems)
    emu.wr32(header + 0x0, 0)
    emu.wr32(header + 0x4, buf)
    emu.wr32(header + 0x8, buf)
    emu.wr32(header + 0xC, buf + stride * cap_elems)


def build_inputs(emu, H, L, P=51.0, amount=1.0, auth_ok=1, with_iface=True):
    n = len(H)
    if n <= 0:
        raise ValueError("empty series")
    _init_container(emu, W_ENGINE + 0x00, 0xA0, n + 64)
    _init_container(emu, W_ENGINE + 0x20, 0x28, 2 * n + 64)
    _init_container(emu, W_ENGINE + 0x30, 0x28, 2 * n + 64)
    _init_container(emu, W_ENGINE + 0x40, 0x28, 2 * n + 64)
    _init_container(emu, W_ENGINE + 0x50, 0x28, 2 * n + 64)

    pH = emu.alloc(8 * n)
    pL = emu.alloc(8 * n)
    for i in range(n):
        emu.mem.wr_bytes(pH + 8 * i, struct.pack("<d", float(H[i])))
        emu.mem.wr_bytes(pL + 8 * i, struct.pack("<d", float(L[i])))
    pP = emu.alloc(8)
    emu.mem.wr_bytes(pP, struct.pack("<d", float(P)))
    emu.wr32(SERIES + 0, pH)
    emu.wr32(SERIES + 4, pL)
    emu.wr32(SERIES + 8, pP)

    out = emu.alloc(8 * n)
    emu.wr32(CELL, W_ENGINE)
    if with_iface:
        emu.wr32(IFACE, VTBL)
        emu.wr32(VTBL + 0, 0)
        emu.wr32(VTBL + 4, HOOK_AUTH)
        emu.wr32(VTBL + 8, 0)
    emu.auth_ok = auth_ok
    return out


def read_out(emu, out, n):
    raw = emu.mem.rd_bytes(out, 8 * n)
    return list(struct.unpack("<%dd" % n, raw))


def call_engine(emu, H, L, entry="c4b0", P=51.0, auth_ok=1, with_iface=True,
                max_steps=500000000):
    n = len(H)
    out = build_inputs(emu, H, L, P=P, auth_ok=auth_ok, with_iface=with_iface)
    iface = IFACE if with_iface else 0
    r = emu.r
    r[4] = STACK_TOP
    if entry == "c4b0":
        emu.push(iface)
        emu.push(out)
        emu.push(n)
        emu.push(CELL)
        ret_pc = ENTRY_C4B0
        r[0] = SERIES
    elif entry == "c1d0":
        emu.push(iface)
        emu.push(SERIES)
        emu.push(out)
        emu.push(n)
        emu.push(CELL)
        ret_pc = ENTRY_C1D0
    else:
        raise ValueError("unknown entry %r" % entry)
    emu.push(SENTINEL)
    emu.pc = ret_pc
    try:
        from x86emu import run
        run(emu, max_steps=max_steps)
        ret = None
    except Halt as h:
        ret = h.eax
    values = read_out(emu, out, n) if ret is not None else None
    return ret, values, emu


# ---- self test -----------------------------------------------------------

def synth_series(n):
    H, L = [], []
    p = 10.0
    step = [0.5, 1.5, 0.5, -1.0, -0.5, -1.5]
    for i in range(n):
        p += step[i % len(step)]
        H.append(round(p + 0.3, 6))
        L.append(round(p - 0.3, 6))
    return H, L


def _nonzero(vals):
    return [(i, v) for i, v in enumerate(vals) if v != 0.0]


def selftest():
    ok = True
    H, L = synth_series(60)

    t0 = time.perf_counter()
    emu1 = make_emu(EVIDENCE_DIR)
    ret1, out1, _ = call_engine(emu1, H, L, entry="c4b0")
    t1 = time.perf_counter()
    emu2 = make_emu(EVIDENCE_DIR)
    ret2, out2, _ = call_engine(emu2, H, L, entry="c1d0")
    t2 = time.perf_counter()

    checks = []
    checks.append(("c4b0 returns 0", ret1 == 0, ret1))
    checks.append(("c1d0 returns 0", ret2 == 0, ret2))
    checks.append(("outputs identical", out1 == out2, None))
    nz1 = _nonzero(out1) if out1 else []
    checks.append(("output has marks", len(nz1) > 0, len(nz1)))
    checks.append(("no assert fired", emu2.assert_count == 0 and emu1.assert_count == 0,
                   emu1.assert_count + emu2.assert_count))
    check_vals = [v for _, v in nz1]
    checks.append(("mark values in {-2,-1,1,2}",
                   all(v in (-2.0, -1.0, 1.0, 2.0) for v in check_vals),
                   sorted(set(check_vals))))

    emu3 = make_emu(EVIDENCE_DIR)
    ret3, out3, _ = call_engine(emu3, H, L, entry="c4b0", auth_ok=0)
    checks.append(("auth denied -> -1", ret3 == 0xFFFFFFFF, ret3))
    checks.append(("auth denied -> out zero", out3 and all(v == 0.0 for v in out3), None))

    emu4 = make_emu(EVIDENCE_DIR)
    out5 = build_inputs(emu4, H[:2], L[:2])
    emu4.r[4] = STACK_TOP
    emu4.push(IFACE)
    emu4.push(out5)
    emu4.push(0)
    emu4.push(CELL)
    emu4.push(SENTINEL)
    emu4.pc = ENTRY_C4B0
    emu4.r[0] = SERIES
    try:
        from x86emu import run
        run(emu4)
        ret5 = None
    except Halt as h:
        ret5 = h.eax
    checks.append(("count=0 -> -1", ret5 == 0xFFFFFFFF, ret5))

    for name, good, extra in checks:
        status = "PASS" if good else "FAIL"
        if not good:
            ok = False
        print("  [%s] %s%s" % (status, name, "" if extra is None else "  (%r)" % (extra,)))
    print("selftest: %s  (c4b0 %.2fs / c1d0 %.2fs, 60 bars)" % (
        "ALL PASS" if ok else "FAILURES", t1 - t0, t2 - t1))
    if out1:
        print("  sample out: %s" % out1[:24])
    return ok


# ---- data loader + replay ------------------------------------------------

def load_tdx1(path):
    with open(path, "rb") as fh:
        data = fh.read()
    n = (len(data) - 68) // 36
    H = [0.0] * n
    L = [0.0] * n
    stamps = [None] * n
    off = 68
    for i in range(n):
        date, time = struct.unpack_from("<II", data, off)
        h, l = struct.unpack_from("<ff", data, off + 0x10)
        H[i] = h
        L[i] = l
        stamps[i] = (date, time)
        off += 36
    return H, L, stamps


def replay(args):
    H, L, stamps = load_tdx1(args.replay)
    if args.max_bars:
        H = H[:args.max_bars]
        L = L[:args.max_bars]
        stamps = stamps[:args.max_bars]
    n = len(H)
    print("replay: %d bars from %s" % (n, args.replay))
    emu = make_emu(EVIDENCE_DIR)
    t0 = time.perf_counter()
    entry = "c1d0" if args.use_c1d0 else "c4b0"
    ret, values, emu = call_engine(emu, H, L, entry=entry, max_steps=args.max_steps)
    dt = time.perf_counter() - t0
    print("ret=0x%08x steps=%d (%.0f/s) time=%.2fs asserts=%d mallocs=%d" % (
        ret if ret is not None else 0xDEADDEAD, emu.steps,
        emu.steps / max(dt, 1e-9), dt, emu.assert_count, len(emu.malloc_log)))
    if ret != 0 or values is None:
        return 1
    nz = _nonzero(values)
    print("nonzero marks: %d (%.1f%%)" % (len(nz), 100.0 * len(nz) / n))
    if args.dump_json:
        payload = {
            "source": os.path.basename(args.replay),
            "entry": entry,
            "bars": n,
            "out": values,
            "stamps": [[s[0], s[1]] for s in stamps],
        }
        with open(args.dump_json, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, separators=(",", ":"))
        print("json dumped: %s" % args.dump_json)
    return 0


def main():
    ap = argparse.ArgumentParser(description="CHBI P=51 faithful pipeline harness")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--replay", metavar="FILE.1")
    ap.add_argument("--max-bars", type=int, default=0)
    ap.add_argument("--max-steps", type=int, default=500000000)
    ap.add_argument("--use-c1d0", action="store_true")
    ap.add_argument("--dump-json", metavar="OUT.json")
    args = ap.parse_args()
    if args.selftest:
        return 0 if selftest() else 1
    if args.replay:
        return replay(args)
    ap.print_help()
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertHit, UnknownCall, EmuError) as e:
        print("EMULATION ERROR: %s" % e)
        sys.exit(3)
