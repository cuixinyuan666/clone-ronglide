"""gdata_probe.py - check whether TAFLib.dll's real .data/.rdata initializers
(and global reads) change the emulator's CHBI P=51 output.

Baseline: emulator as-is (all-zero globals except 4 constants).
Overlay : real .data/.rdata file bytes mapped at 0x10000000+VA.
Also logs which globals the engine actually reads during a short run.
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from x86emu import make_emu, SENTINEL, Halt
from chbi51 import call_engine, load_tdx1, EVIDENCE_DIR

DLL = r"D:\a_ronglide\缠中说禅\TAFLib.dll"
DATASET = r"D:\a_ronglide\缠中说禅\Dat\His\02\1\600000.1"
IMAGE_BASE = 0x10000000
GLO_LO, GLO_HI = 0x1006E000, 0x10086000


def parse_sections(path):
    with open(path, "rb") as fh:
        data = fh.read()
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    coff = e_lfanew + 4
    num_sec, = struct.unpack_from("<H", data, coff + 2)
    opt_size, = struct.unpack_from("<H", data, coff + 16)
    sec_off = coff + 20 + opt_size
    secs = []
    for i in range(num_sec):
        s = sec_off + i * 0x28
        name = data[s:s + 8].rstrip(b"\0").decode("ascii", "replace")
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, s + 8)
        secs.append((name, va, vsize, rawptr, rawsize))
    return data, secs


def overlay(emu, raw, secs):
    for name, va, vsize, rawptr, rawsize in secs:
        if name in (".text", ".reloc", ".rsrc"):
            continue
        chunk = raw[rawptr:rawptr + rawsize]
        for off in range(0, len(chunk), 4096):
            emu.mem.wr_bytes(IMAGE_BASE + va + off, chunk[off:off + 4096])
    emu.mem.wr_bytes(0x1006F194, (0xDEADF194).to_bytes(4, "little"))
    emu.mem.wr_bytes(0x1006FC28, struct.pack("<d", 0.001))
    emu.mem.wr_bytes(0x1006FC50, struct.pack("<f", -1.0))


def run_case(H, L, do_overlay, raw, secs, read_log=None):
    emu = make_emu(EVIDENCE_DIR)
    if do_overlay:
        overlay(emu, raw, secs)
    if read_log is not None:
        mem = emu.mem
        orig_rd_bytes = mem.rd_bytes
        orig_rd32 = mem.rd32

        def rd_bytes(a, n):
            if GLO_LO <= (a & 0xFFFFFFFF) < GLO_HI:
                read_log[a & 0xFFFFFFFF] = read_log.get(a & 0xFFFFFFFF, 0) + 1
            return orig_rd_bytes(a, n)

        def rd32(a):
            if GLO_LO <= (a & 0xFFFFFFFF) < GLO_HI:
                read_log[a & 0xFFFFFFFF] = read_log.get(a & 0xFFFFFFFF, 0) + 1
            return orig_rd32(a)

        mem.rd_bytes = rd_bytes
        mem.rd32 = rd32
    ret, vals, emu = call_engine(emu, H, L, entry="c4b0", max_steps=80000000)
    return ret, vals, emu


def main():
    nbars = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    H, L, _ = load_tdx1(DATASET)
    H, L = H[:nbars], L[:nbars]
    raw, secs = parse_sections(DLL)

    print("== baseline (zero globals) ==")
    ret1, v1, emu1 = run_case(H, L, False, None, None)
    nz1 = sum(1 for v in v1 if v != 0.0) if v1 else None
    print("ret=%s nonzero=%s steps=%d" % (ret1, nz1, emu1.steps))

    print("== overlay (real .data/.rdata) ==")
    ret2, v2, emu2 = run_case(H, L, True, raw, secs)
    nz2 = sum(1 for v in v2 if v != 0.0) if v2 else None
    print("ret=%s nonzero=%s steps=%d" % (ret2, nz2, emu2.steps))

    if v1 is not None and v2 is not None:
        if len(v1) != len(v2):
            print("LENGTH MISMATCH")
        else:
            diff = [i for i in range(len(v1)) if v1[i] != v2[i]]
            print("differing marks: %d" % len(diff))
            for i in diff[:10]:
                print("   [%d] zero=%r overlay=%r" % (i, v1[i], v2[i]))

    print("== global read log (baseline run) ==")
    log = {}
    ret3, v3, emu3 = run_case(H, L, False, None, None, read_log=log)
    def fileval(addr):
        rva = addr - IMAGE_BASE
        for name, va, vsize, rawptr, rawsize in secs:
            if va <= rva < va + max(vsize, rawsize):
                off = rawptr + (rva - va)
                if off + 4 <= len(raw):
                    return "sec=%s file=0x%08x" % (
                        name, int.from_bytes(raw[off:off + 4], "little"))
                return "sec=%s" % name
        return "unmapped"
    top = sorted(log.items(), key=lambda kv: -kv[1])[:40]
    for addr, cnt in top:
        print("   0x%08x  reads=%-7d %s" % (addr, cnt, fileval(addr)))


if __name__ == "__main__":
    main()
