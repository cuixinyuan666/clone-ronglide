"""frida_native_host.py - run the real TAFLib.dll CHBI entries natively inside a
minimal 32-bit host process (spawned with cwd = client dir so TAFLib's own
imports rld_lib/chlib/RDM_C/RCommon/RData resolve). With 0x10000000 free the
DLL lands at its preferred image base, matching the emulator's assumption.

Usage: python frida_native_host.py [--max-bars N]
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
from frida_native_run import compare, EMU_REF

JS_PATH = os.path.join(HERE, "frida_native_call.js")
DUMP_DIR = os.path.join(HERE, "dumps")
CRASH_REPORT = r"C:\Users\Administrator\AppData\Local\Temp\opencode\crash_report.txt"

CLIENT_DIR = r"D:\a_ronglide\缠中说禅"
DATASET = os.path.join(CLIENT_DIR, "Dat", "His", "02", "1", "600000.1")
HOST = r"C:\Windows\SysWOW64\notepad.exe"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-bars", type=int, default=0)
    ap.add_argument("--timeout", type=float, default=120.0)
    args = ap.parse_args()

    if os.path.exists(CRASH_REPORT):
        os.remove(CRASH_REPORT)

    H, L, _ = load_tdx1(DATASET)
    if args.max_bars:
        H, L = H[:args.max_bars], L[:args.max_bars]
    n = len(H)
    payload = array.array("d", H + L).tobytes()
    print("dataset: %d bars (%.1f KB payload)" % (n, len(payload) / 1024.0))

    device = frida.get_local_device()
    pid = device.spawn([HOST], cwd=CLIENT_DIR)
    session = device.attach(pid)
    print("spawned host pid %d (%s)" % (pid, HOST))

    with open(JS_PATH, encoding="utf-8") as fh:
        script = session.create_script(fh.read())

    results = {}
    last_tail = {"trace": []}
    detached = {"flag": False}

    def on_message(message, data):
        if message["type"] != "send":
            print("[script msg] %r" % (message,))
            return
        p = message.get("payload") or {}
        kind = p.get("type")
        if kind == "script_ready":
            print("[js] script_ready")
        elif kind == "scan":
            print("[js] scan base=%s unreloc-hits=%d samples=%s" % (
                p["base"], p["hits"], p["samples"]))
        elif kind == "trace_tail":
            last_tail["trace"] = p["trace"]
        elif kind == "entry_result":
            entry = p["entry"]
            cnt = p["n"]
            out = list(struct.unpack("<%dd" % cnt, data))
            results[entry] = {"rc": p["rc"], "out": out}
            print("[js] %s rc=0x%08x bars=%d" % (entry, p["rc"], cnt))
        elif kind == "done":
            print("[js] done")
        elif kind == "thread_started":
            print("[js] engine thread created: %s" % p["thread"])
        elif kind == "thread_timeout":
            last_tail["flags"] = "flag0=0x%x flag1=0x%x flag2=0x%x" % (
                p.get("flag0", 0), p["flag1"], p["flag2"])
            print("[js] THREAD TIMEOUT %s" % last_tail["flags"])
            print("[js] trace: %s" % " -> ".join(p.get("trace") or []))
        elif kind == "call_error":
            print("[js] CALL ERROR in %s: %s" % (p["entry"], p["msg"]))
            print("[js] trace: %s" % " -> ".join(p.get("trace") or []))
        elif kind == "script_error":
            print("[js] ERROR: %s" % p.get("stack"))
            print("[js] trace: %s" % " -> ".join(p.get("trace") or []))
        elif kind == "probe":
            print("[probe] %s" % p.get("line"))
        else:
            print("[js] %r" % (p,))

    def on_detached(*a):
        detached["flag"] = True
        print("[session] DETACHED: %r" % (a,))

    session.on("detached", on_detached)
    script.on("message", on_message)
    script.load()
    device.resume(pid)
    time.sleep(2.5)

    print("posting run payload (%d bars) ..." % n)
    script.post({"type": "run", "n": n}, payload)

    t0 = time.time()
    while len(results) < 2 and time.time() - t0 < args.timeout:
        if detached["flag"]:
            break
        time.sleep(0.5)
    print("native run finished in %.1fs" % (time.time() - t0))

    for entry in ("c1d0", "c4b0"):
        if entry not in results:
            continue
        res = results[entry]
        os.makedirs(DUMP_DIR, exist_ok=True)
        path = os.path.join(DUMP_DIR, "chbi_native_%s_%d.json" % (entry, len(res["out"])))
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"entry": entry, "count": len(res["out"]),
                       "rc": res["rc"], "out": res["out"]}, fh)
        print("saved %s (rc=0x%08x)" % (path, res["rc"]))

    ok = len(results) == 2
    for entry, res in results.items():
        if res["rc"] != 0:
            print("[%s] NONZERO RETURN" % entry)
            ok = False
            continue
        ref = EMU_REF.get(entry)
        if ref and os.path.exists(ref):
            if not compare(entry, res["out"], ref):
                ok = False
        else:
            print("[%s] no emulator reference at %s" % (entry, ref))

    if not results:
        print("no results - flags: %s" % last_tail.get("flags", "?"))
        print("no results - last trace tail: %s" % " -> ".join(last_tail["trace"]))

    if os.path.exists(CRASH_REPORT):
        print("==== CRASH REPORT ====")
        with open(CRASH_REPORT, encoding="utf-8") as fh:
            print(fh.read())

    print("RESULT: %s" % ("ALL MATCH" if ok else "FAILED/INCOMPLETE"))
    sys.stdout.flush()
    os._exit(0 if ok else 1)


if __name__ == "__main__":
    sys.exit(main())
