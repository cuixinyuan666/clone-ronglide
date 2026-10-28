"""frida_runner.py - attach to the running chart client, load frida_chbi_600000.js,
and save every P=51 out[] dump from TAFLib.dll to JSON files.

Usage:
  python frida_runner.py                 # auto-pick a candidate process
  python frida_runner.py <process-name>  # explicit name or pid

Workflow (manual, in the client):
  1) open 600000 (浦发银行) with 1-minute bars loaded for the full year
  2) enable the CHBI "笔" formula once so the engine call fires
Then this script prints and saves dumps like: dumps/chbi_frida_c4b0_58560.json
"""
import json
import os
import sys
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT_PATH = os.path.join(HERE, "frida_chbi_600000.js")
DUMP_DIR = os.path.join(HERE, "dumps")

CANDIDATES = ["缠中说禅.exe", "chan.exe", "tdx.exe", "zszq.exe"]


def find_process(name_or_pid):
    if name_or_pid and name_or_pid.isdigit():
        return int(name_or_pid), frida.get_local_device()
    device = frida.get_local_device()
    procs = device.enumerate_processes()
    if name_or_pid:
        for p in procs:
            if name_or_pid.lower() in p.name.lower():
                return p.pid, device
        print("no process matching %r; candidates:" % name_or_pid)
        for p in procs:
            print("   %d %s" % (p.pid, p.name))
        return None, device
    for cand in CANDIDATES:
        for p in procs:
            if cand.lower().replace(".exe", "") in p.name.lower():
                return p.pid, device
    print("no candidate process found; running processes:")
    for p in procs:
        if "exe" in p.name.lower() or "tdx" in p.name.lower():
            print("   %d %s" % (p.pid, p.name))
    return None, device


def main():
    os.makedirs(DUMP_DIR, exist_ok=True)
    pid, device = find_process(sys.argv[1] if len(sys.argv) > 1 else None)
    if pid is None:
        return 1
    print("attaching to pid %d ..." % pid)
    session = device.attach(pid)
    with open(SCRIPT_PATH, encoding="utf-8") as fh:
        script = session.create_script(fh.read())

    saved = []

    def on_message(message, data):
        if message["type"] == "send":
            payload = message.get("payload") or {}
            if payload.get("name") == "chbi_p51_out":
                body = payload["payload"]
                count = body["count"]
                path = os.path.join(
                    DUMP_DIR, "chbi_frida_%s_%d.json" % (body["entry"], count))
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump(body, fh)
                saved.append(path)
                nz = sum(1 for v in body["out"] if v != 0.0)
                print("[dump] %s  nonzero=%d" % (path, nz))
        elif message["type"] == "error":
            print("[script error] %s" % message.get("stack") or message)

    script.on("message", on_message)
    script.load()
    print("script loaded. Now start the P=51 computation in the client.")
    print("press Ctrl+C to stop")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    print("saved %d dump(s)" % len(saved))
    return 0


if __name__ == "__main__":
    sys.exit(main())
