"""dbg_em.py - instrumented emulator run: count hook calls + container states.

Usage: python dbg_em.py [bars]
"""
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import x86emu
from x86emu import make_emu
import chbi51

counts = {}
PUSHES = []


def wrap(name):
    orig = getattr(x86emu, name)

    def f(emu):
        counts[name] = counts.get(name, 0) + 1
        return orig(emu)

    setattr(x86emu, name, f)


def wrap_push(name, tag, stride, cap):
    orig = getattr(x86emu, name)
    tag_cnt = {"n": 0}

    def f(emu):
        counts[name] = counts.get(name, 0) + 1
        tag_cnt["n"] += 1
        if tag_cnt["n"] <= cap:
            try:
                cont = emu.r[6]
                rec = emu.r[3]
                b = emu.rd32(cont + 4)
                e = emu.rd32(cont + 8)
                raw = emu.mem.rd_bytes(rec, 0xA0)
                fields = [struct.unpack_from("<I", raw, o)[0] for o in (0, 0xC, 0x20, 0x98)]
                PUSHES.append("%s:%d cont=0x%08x nrec=%d rec=0x%08x f00=0x%x f0C=0x%x f20=0x%x f98=0x%x"
                              % (tag, tag_cnt["n"], cont, (e - b) // stride, rec,
                                 fields[0], fields[1], fields[2], fields[3]))
            except Exception as ex:
                PUSHES.append("%s err %r" % (tag, ex))
        return orig(emu)

    setattr(x86emu, name, f)


for n in ("h_iter_at", "h_iter_begin", "h_malloc", "h_free", "h_ftol", "h_assert"):
    wrap(n)
wrap_push("h_copy_a0", "push-m0", 0xA0, 60)
wrap_push("h_copy_28", "push-m5", 0x28, 40)

path = r"D:\a_ronglide\缠中说禅\Dat\His\02\1\600000.1"
H, L, _ = chbi51.load_tdx1(path)
maxb = int(sys.argv[1]) if len(sys.argv) > 1 else 200
H, L = H[:maxb], L[:maxb]
emu = make_emu(chbi51.EVIDENCE_DIR)
t0 = time.perf_counter()
try:
    ret, vals, emu = chbi51.call_engine(emu, H, L, entry="c4b0")
except Exception as e:
    print("EMU EXCEPTION: %r" % (e,))
    ret, vals = None, None
dt = time.perf_counter() - t0
print("bars=%d ret=%s steps=%d time=%.2fs asserts=%d" % (
    maxb, hex(ret) if ret is not None else "None", emu.steps, dt, emu.assert_count))
print("hook calls:", {k: counts[k] for k in sorted(counts)})
w = chbi51.W_ENGINE
b, e, a = struct.unpack("<III", emu.mem.rd_bytes(w + 4, 12))
print("m0  : begin=0x%x end=0x%x alloc=0x%x nrec=%d cap=%d" % (
    b, e, a, (e - b) // 0xA0, (a - b) // 0xA0))
for off in (0x20, 0x30, 0x40, 0x50):
    b, e, a = struct.unpack("<III", emu.mem.rd_bytes(w + off + 4, 12))
    print("c+%02x: nrec=%d cap=%d" % (off, (e - b) // 0x28, (a - b) // 0x28))
if vals is not None:
    nz = [(i, v) for i, v in enumerate(vals) if v != 0.0]
    print("marks=%d" % len(nz))
    print("first10=%s" % (nz[:10],))
print("--- first pushes ---")
for line in PUSHES[:80]:
    print(line)
