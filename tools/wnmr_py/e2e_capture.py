"""e2e_capture.py - attach to the live client (MainApp.exe), install e2e_capture.js,
save captured CHBI P=51 input/output to dumps/, and (by default) compare with the
x86 emulator bit-exactly.

Usage:
  python e2e_capture.py                 # attach to MainApp.exe (first non-7920 pid)
  python e2e_capture.py 1234            # attach to explicit pid
  python e2e_capture.py --no-compare    # only save captures
"""
import argparse
import datetime
import hashlib
import json
import os
import struct
import sys
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from chbi51 import call_engine, EVIDENCE_DIR  # noqa: E402
from x86emu import make_emu  # noqa: E402

SCRIPT_PATH = os.path.join(HERE, "e2e_capture.js")
DUMP_DIR = os.path.join(HERE, "dumps")

COMPARE = True


def log(msg):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print("[%s] %s" % (ts, msg), flush=True)


def find_pid(target):
    dev = frida.get_local_device()
    if target and str(target).isdigit():
        return int(target), dev
    name = (target or "MainApp.exe")
    if not target or "mainapp" in str(target).lower():
        try:
            import win32gui
            import ctypes as _ct
            wins = []
            win32gui.EnumWindows(
                lambda h, _: wins.append(h)
                if win32gui.IsWindowVisible(h) and
                win32gui.GetClassName(h) == "CLASSNAME_RLD_CZSC_MAINAPP" else None,
                None)
            if wins:
                _pid = _ct.c_ulong(0)
                _ct.windll.user32.GetWindowThreadProcessId(wins[0], _ct.byref(_pid))
                log("resolved %r -> pid %d (main window)" % (target, _pid.value))
                return _pid.value, dev
        except Exception as e:
            log("window-based pid resolve failed: %r" % (e,))
    cands = []
    for p in dev.enumerate_processes():
        if name.lower().replace(".exe", "") in p.name.lower():
            cands.append(p)
    cands = [p for p in cands if p.pid != 7920] or cands
    if not cands:
        log("no process matching %r; candidates:" % name)
        for p in dev.enumerate_processes():
            if "main" in p.name.lower() or "exe" in p.name.lower():
                log("   %d %s" % (p.pid, p.name))
        return None, dev
    if len(cands) > 1:
        log("multiple candidates: %s" % [(p.pid, p.name) for p in cands])
    return cands[0].pid, dev


def handle_capture(payload, data):
    n = int(payload["count"])
    entry = payload["entry"]
    cid = payload["id"]
    if len(data) != 24 * n:
        log("capture size mismatch: got %d want %d" % (len(data), 24 * n))
        return
    hb = data[: 8 * n]
    lb = data[8 * n: 16 * n]
    ob = data[16 * n: 24 * n]
    H = struct.unpack("<%dd" % n, hb)
    L = struct.unpack("<%dd" % n, lb)
    OUT = struct.unpack("<%dd" % n, ob)

    base = "e2e_app_%s_%d_%d" % (entry, n, cid)
    bin_path = os.path.join(DUMP_DIR, base + ".bin")
    meta_path = os.path.join(DUMP_DIR, base + ".json")
    with open(bin_path, "wb") as fh:
        fh.write(hb + lb + ob)
    meta = dict(payload)
    meta["time"] = datetime.datetime.now().isoformat(timespec="seconds")
    meta["sha1"] = hashlib.sha1(hb + lb + ob).hexdigest()
    meta["h_head"] = list(H[:4])
    meta["l_head"] = list(L[:4])
    with open(meta_path, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, ensure_ascii=True, indent=1)

    nz = [(i, v) for i, v in enumerate(OUT) if v != 0.0]
    hist = {}
    for _, v in nz:
        hist[v] = hist.get(v, 0) + 1
    log("CAPTURE %s n=%d -> %s" % (entry, n, os.path.basename(bin_path)))
    log("  H[0..3]=%s L[0..3]=%s" % (list(H[:4]), list(L[:4])))
    log("  Hmin=%.6f Hmax=%.6f" % (min(H), max(H)))
    log("  nonzero=%d hist=%s" % (len(nz), hist))
    if nz:
        log("  first nz: %s" % nz[:5])
        log("  last  nz: %s" % nz[-5:])

    if not COMPARE:
        return
    log("  running emulator on captured H/L (entry=%s)... " % entry)
    t0 = time.perf_counter()
    try:
        emu = make_emu(EVIDENCE_DIR)
        ret, values, emu = call_engine(emu, list(H), list(L), entry=entry, P=51.0)
    except Exception as e:
        log("  EMULATION ERROR: %r" % (e,))
        return
    dt = time.perf_counter() - t0
    if ret != 0 or values is None:
        log("  emulator ret=0x%08X (expect 0) in %.1fs" % (ret, dt))
        return
    diffs = []
    for i in range(n):
        if struct.pack("<d", values[i]) != ob[8 * i: 8 * i + 8]:
            diffs.append(i)
    emu_path = os.path.join(DUMP_DIR, "e2e_emu_%s_%d.bin" % (entry, n))
    with open(emu_path, "wb") as fh:
        fh.write(struct.pack("<%dd" % n, *values))
    if not diffs:
        log("  [E2E] entry=%s n=%d compare=BIT-EXACT diffs=0 time=%.1fs" % (entry, n, dt))
        log("  emulator dump: %s" % emu_path)
    else:
        n_float_eq = sum(1 for i in diffs if values[i] == OUT[i])
        log("  [E2E] entry=%s n=%d compare=DIFF bit_diffs=%d float_eq_among=%d time=%.1fs"
            % (entry, n, len(diffs), n_float_eq, dt))
        for i in diffs[:10]:
            log("    [%d] app=%r emu=%r" % (i, OUT[i], values[i]))


def main():
    global COMPARE
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", default=None,
                    help="process name or pid (default: MainApp.exe)")
    ap.add_argument("--no-compare", action="store_true")
    args = ap.parse_args()
    COMPARE = not args.no_compare

    os.makedirs(DUMP_DIR, exist_ok=True)
    pid, dev = find_pid(args.target)
    if pid is None:
        return 1
    log("attaching to pid %d ..." % pid)
    session = dev.attach(pid)
    with open(SCRIPT_PATH, encoding="utf-8") as fh:
        script = session.create_script(fh.read())

    def on_message(message, data):
        mtype = message.get("type")
        if mtype == "send":
            payload = message.get("payload") or {}
            if isinstance(payload, dict) and payload.get("name") == "e2e_capture":
                try:
                    handle_capture(payload, data)
                except Exception as e:
                    log("handle_capture EXC: %r" % (e,))
            else:
                log("MSG %r" % (payload,))
        elif mtype == "error":
            log("SCRIPT ERROR: %s" % message.get("stack") or message)
        else:
            log("MSG %r" % (message,))

    script.on("message", on_message)
    script.load()
    log("script loaded. Trigger CHBI P=51 in the client (formula preview etc.).")
    log("Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    try:
        session.detach()
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
