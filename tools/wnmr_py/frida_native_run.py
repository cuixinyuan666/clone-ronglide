"""frida_native_run.py - natively execute the real TAFLib.dll CHBI entries (c4b0/c1d0)
inside a freshly spawned MainApp process, feeding the full 58560-bar 600000 dataset,
then compare the returned out[] bit-exactly against the x86emu replay dumps.

Usage:
  python frida_native_run.py                    # spawn MainApp, run, compare
  python frida_native_run.py --attach 1234      # use an already running pid
"""
import argparse
import array
import json
import os
import struct
import sys
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from chbi51 import load_tdx1

JS_PATH = os.path.join(HERE, "frida_native_call.js")
DUMP_DIR = os.path.join(HERE, "dumps")

CLIENT_DIR = r"D:\a_ronglide\缠中说禅"
EXE = os.path.join(CLIENT_DIR, "MainApp.exe")
DATASET = os.path.join(CLIENT_DIR, "Dat", "His", "02", "1", "600000.1")
EMU_C4B0 = r"C:\Users\Administrator\AppData\Local\Temp\opencode\chbi51_600000.json"
EMU_C1D0 = r"C:\Users\Administrator\AppData\Local\Temp\opencode\chbi51_600000_c1d0.json"

EMU_REF = {"c4b0": EMU_C4B0, "c1d0": EMU_C1D0}


def compare(tag, native_out, emu_path):
    with open(emu_path, encoding="utf-8") as fh:
        emu = json.load(fh)
    eout = emu["out"]
    if len(eout) != len(native_out):
        print("[%s] COUNT MISMATCH emu=%d native=%d" % (tag, len(eout), len(native_out)))
        return False
    diff = [i for i in range(len(eout)) if eout[i] != native_out[i]]
    nz = sum(1 for v in native_out if v != 0.0)
    hist = {}
    for v in native_out:
        if v != 0.0:
            hist[v] = hist.get(v, 0) + 1
    print("[%s] bars=%d nonzero=%d hist=%s" % (tag, len(native_out), nz, sorted(hist.items())))
    if diff:
        print("[%s] DIFFERING bits: %d (first 20:)" % (tag, len(diff)))
        for i in diff[:20]:
            print("    [%d] emu=%r native=%r" % (i, eout[i], native_out[i]))
        return False
    print("[%s] MATCH: native == emulator bit-exact" % tag)
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--attach", type=int, default=0)
    ap.add_argument("--wait", type=float, default=12.0)
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--max-bars", type=int, default=0)
    args = ap.parse_args()

    H, L, _ = load_tdx1(DATASET)
    if args.max_bars:
        H, L = H[:args.max_bars], L[:args.max_bars]
    n = len(H)
    payload = array.array("d", H + L).tobytes()
    print("dataset: %d bars from %s (%.1f KB payload)" % (n, DATASET, len(payload) / 1024.0))

    device = frida.get_local_device()
    if args.attach:
        pid = args.attach
        session = device.attach(pid)
        print("attached to pid %d" % pid)
        spawned = False
    else:
        pid = device.spawn([EXE], cwd=CLIENT_DIR)
        session = device.attach(pid)
        print("spawned pid %d" % pid)
        spawned = True

    with open(JS_PATH, encoding="utf-8") as fh:
        script = session.create_script(fh.read())

    results = {}

    def on_message(message, data):
        if message["type"] != "send":
            print("[script msg] %r" % (message,))
            return
        payload_msg = message.get("payload") or {}
        kind = payload_msg.get("type")
        if kind == "script_ready":
            print("[js] script_ready")
        elif kind == "entry_result":
            entry = payload_msg["entry"]
            cnt = payload_msg["n"]
            out = list(struct.unpack("<%dd" % cnt, data))
            results[entry] = {"rc": payload_msg["rc"], "out": out}
            print("[js] %s rc=0x%08x bars=%d bytes=%d" % (
                entry, payload_msg["rc"], cnt, len(data)))
        elif kind == "done":
            print("[js] done")
        elif kind == "call_error":
            print("[js] CALL ERROR in %s: %s" % (payload_msg["entry"], payload_msg["msg"]))
            print("[js] last trace (%d): %s" % (
                len(payload_msg.get("trace") or []), " -> ".join(payload_msg.get("trace") or [])))
        elif kind == "script_error":
            print("[js] ERROR: %s" % payload_msg.get("stack"))
            if payload_msg.get("trace"):
                print("[js] last trace: %s" % " -> ".join(payload_msg["trace"]))
        else:
            print("[js] %r" % (payload_msg,))

    detached = {"flag": False}

    def on_detached(*a):
        detached["flag"] = True
        print("[session] DETACHED: %r" % (a,))

    session.on("detached", on_detached)
    script.on("message", on_message)
    script.load()

    if spawned:
        device.resume(pid)
        print("resumed; waiting %.1fs for startup" % args.wait)
        time.sleep(args.wait)

    print("posting run payload (%d bars) ..." % n)
    script.post({"type": "run", "n": n}, payload)

    t0 = time.time()
    while len(results) < 2 and time.time() - t0 < args.timeout:
        if detached["flag"]:
            print("target detached/crashed before returning results")
            break
        time.sleep(0.5)
    took = time.time() - t0
    print("native run finished in %.1fs" % took)

    os.makedirs(DUMP_DIR, exist_ok=True)
    ok = True
    for entry, res in results.items():
        path = os.path.join(DUMP_DIR, "chbi_native_%s_%d.json" % (entry, len(res["out"])))
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"entry": entry, "count": len(res["out"]),
                       "rc": res["rc"], "out": res["out"]}, fh)
        print("saved %s (rc=0x%08x)" % (path, res["rc"]))
        if res["rc"] != 0:
            print("[%s] NONZERO RETURN - skip compare" % entry)
            ok = False
            continue
        ref = EMU_REF.get(entry)
        if ref and os.path.exists(ref):
            if not compare(entry, res["out"], ref):
                ok = False
        else:
            print("[%s] no emulator reference at %s" % (entry, ref))

    missing = {"c4b0", "c1d0"} - set(results)
    if missing:
        print("MISSING entries: %s" % sorted(missing))
        ok = False

    try:
        script.unload()
    except Exception:
        pass
    session.detach()
    print("RESULT: %s" % ("ALL MATCH" if ok else "FAILED/INCOMPLETE"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
