"""wnmr_e2e.py - 「无脑买入线段」全链原生端到端验证。

链路（全部由真实 TAFLib.dll 原生执行）:
    CHBI(c1d0) -> CHDUAN(0x2c710) -> [快照 W->m[0]] -> WNMRNEW(0x3a7c0) -> WNMRPRINEW(0x3a960)

然后把快照喂给 wnmr.py 的 Python 移植，与真实输出逐点对拍。

用法:
    python wnmr_e2e.py [--max-bars N] [--timeout S]
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
from wnmr import LevelObj, wnwr_new, wnwr_pri_new

JS_PATH = os.path.join(HERE, "frida_wnmr_e2e.js")
DUMP_DIR = os.path.join(HERE, "dumps")
CRASH_REPORT = r"C:\Users\Administrator\AppData\Local\Temp\opencode\wnmr_e2e_crash.txt"

CLIENT_DIR = r"D:\a_ronglide\缠中说禅"
DATASET = os.path.join(CLIENT_DIR, "Dat", "His", "02", "1", "600000.1")
HOST = r"C:\Windows\SysWOW64\notepad.exe"

REC = 0xA0


def f32(buf, off):
    return struct.unpack_from("<f", buf, off)[0]


def i32(buf, off):
    return struct.unpack_from("<i", buf, off)[0]


def parse_records(raw):
    nrec = len(raw) // REC
    objs = []
    rows = []
    for i in range(nrec):
        b = raw[i * REC:(i + 1) * REC]
        o = LevelObj(
            index=i32(b, 0x00),
            idx_prev=i32(b, 0x04),
            idx_next=i32(b, 0x08),
            low=f32(b, 0x0C),
            high=f32(b, 0x10),
            level_type=i32(b, 0x14),
            direction=i32(b, 0x20),
            fractal=i32(b, 0x88),
            signal_flag=i32(b, 0x8C),
            status=i32(b, 0x90),
            price=f32(b, 0x94),
        )
        objs.append(o)
        rows.append(o)
    return objs, rows


def obj_row(o):
    return {
        "index": o.index, "idx_prev": o.idx_prev, "idx_next": o.idx_next,
        "low": o.low, "high": o.high, "level_type": o.level_type,
        "direction": o.direction, "fractal": o.fractal,
        "signal_flag": o.signal_flag, "status": o.status, "price": o.price,
    }


def hist_int(vals):
    h = {}
    for v in vals:
        h[v] = h.get(v, 0) + 1
    return {str(k): h[k] for k in sorted(h)}


def compare(name, real, py):
    diffs = []
    for i in range(min(len(real), len(py))):
        if real[i] != py[i]:
            diffs.append((i, real[i], py[i]))
    print("[cmp] %s len real=%d py=%d diff=%d" % (name, len(real), len(py), len(diffs)))
    for d in diffs[:20]:
        print("       [%d] real=%r py=%r" % d)
    return diffs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-bars", type=int, default=2000)
    ap.add_argument("--timeout", type=float, default=600.0)
    ap.add_argument("--keep-going", action="store_true")
    ap.add_argument("--probe", action="store_true")
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

    state = {
        "meta": None,
        "phase1": None,
        "phase2": None,
        "snapshot": None,
        "snapshot_post": None,
        "census": None,
        "containers": {},
        "probe": [],
        "probe_meta": None,
        "outs": {},
        "done": False,
        "error": None,
    }
    detached = {"flag": False}

    def on_message(message, data):
        if message["type"] != "send":
            print("[script msg] %r" % (message,))
            return
        p = message.get("payload") or {}
        kind = p.get("type")
        if kind == "script_ready":
            print("[js] script_ready")
        elif kind == "e2e_meta":
            state["meta"] = p
            print("[js] addrs: %s" % json.dumps(p.get("addrs"), ensure_ascii=False))
        elif kind == "phase1_started":
            print("[js] phase1 thread %s" % p.get("thread"))
        elif kind == "phase1_done":
            state["phase1"] = p
            print("[js] phase1 done nrec=%d" % p.get("nrec"))
        elif kind == "w_snapshot":
            state["snapshot"] = data
            print("[js] snapshot %d records (%.1f KB)" % (p.get("nrec", 0), len(data) / 1024.0))
        elif kind == "out":
            state["outs"][p["name"]] = list(struct.unpack("<%dd" % p["n"], data))
            print("[js] out %s %d doubles" % (p["name"], p["n"]))
        elif kind == "post_census":
            state["census"] = p.get("census")
            print("[js] post census: %s" % json.dumps(state["census"]))
        elif kind == "w_post":
            state["snapshot_post"] = data
            print("[js] post snapshot %d records" % p.get("nrec", 0))
        elif kind == "container":
            state["containers"][p["off"]] = data
            print("[js] container off=0x%x stride=%d cnt=%d" % (
                p["off"], p["stride"], p["cnt"]))
        elif kind == "probe_installed":
            print("[js] probe installed at %s stub=%s" % (p["addr"], p["stub"]))
        elif kind == "instance_hits":
            print("[js] buy status-1 write hits: %s" % p["hits"])
        elif kind == "probe_log":
            state["probe_meta"] = p
            print("[js] probe hits=%d" % p["count"])
        elif kind == "probe_data":
            nrec = p["count"]
            state["probe"] = [
                struct.unpack_from("<12I", data, k * 0x30) for k in range(nrec)
            ]
        elif kind == "phase2_started":
            print("[js] phase2 thread %s" % p.get("thread"))
        elif kind == "phase2_done":
            state["phase2"] = p
            print("[js] phase2 done rc_wnmrnew=%d rc_wnmrpri=%d nrec_after=%d" % (
                p.get("rc_wnmrnew", -99), p.get("rc_wnmrpri", -99), p.get("nrec_after", -1)))
        elif kind == "done":
            state["done"] = True
            print("[js] done")
        elif kind in ("phase1_error", "phase2_timeout", "thread_timeout", "snapshot_error",
                      "script_error", "phase1_timeout"):
            state["error"] = p
            print("[js] ERROR %s" % json.dumps(p, ensure_ascii=False))
        else:
            print("[js] %r" % (p,))

    def on_detached(*a):
        detached["flag"] = True
        print("[session] DETACHED: %r" % (a,))

    session.on("detached", on_detached)
    script.on("message", on_message)
    script.load()
    device.resume(pid)
    time.sleep(2.0)

    print("posting run payload (%d bars) ..." % n)
    script.post({"type": "run", "n": n, "probe": args.probe}, payload)

    t0 = time.time()
    while not state["done"] and not state["error"] and not detached["flag"]:
        if time.time() - t0 > args.timeout:
            print("[host] TIMEOUT after %.1fs" % args.timeout)
            break
        time.sleep(0.5)
    print("native phase finished in %.1fs" % (time.time() - t0))

    os.makedirs(DUMP_DIR, exist_ok=True)
    tag = "%d" % n
    raw_path = os.path.join(DUMP_DIR, "wnmr_e2e_raw_%s.json" % tag)
    with open(raw_path, "w", encoding="utf-8") as fh:
        json.dump({
            "count": n,
            "meta": state["meta"],
            "phase1": state["phase1"],
            "phase2": state["phase2"],
            "outs": state["outs"],
        }, fh)
    print("saved %s" % raw_path)

    if state["snapshot"] is None:
        print("RESULT: NO SNAPSHOT (%s)" % json.dumps(state["error"], ensure_ascii=False))
        if os.path.exists(CRASH_REPORT):
            print("==== CRASH REPORT ====")
            print(open(CRASH_REPORT, encoding="utf-8").read())
        os._exit(2)

    snap_path = os.path.join(DUMP_DIR, "wnmr_e2e_w_%s.bin" % tag)
    with open(snap_path, "wb") as fh:
        fh.write(state["snapshot"])
    print("saved %s" % snap_path)

    objs, _ = parse_records(state["snapshot"])
    print("[w] records=%d  index_range=(%d..%d)" % (
        len(objs),
        min((o.index for o in objs), default=-1),
        max((o.index for o in objs), default=-1)))

    if state["snapshot_post"] is not None:
        post_path = os.path.join(DUMP_DIR, "wnmr_e2e_w_post_%s.bin" % tag)
        with open(post_path, "wb") as fh:
            fh.write(state["snapshot_post"])
        print("saved %s" % post_path)
        post_objs, _ = parse_records(state["snapshot_post"])
        print("[w-post] records=%d status_hist=%s price_nonzero=%d signal_hist=%s" % (
            len(post_objs),
            json.dumps(hist_int([o.status for o in post_objs])),
            sum(1 for o in post_objs if o.price != 0.0),
            json.dumps(hist_int([o.signal_flag for o in post_objs]))))
        for off, buf in state["containers"].items():
            cpath = os.path.join(DUMP_DIR, "wnmr_e2e_c%x_%s.bin" % (off, tag))
            with open(cpath, "wb") as fh:
                fh.write(buf)
            print("saved %s" % cpath)

    if state["probe"] and state["probe_meta"]:
        m0b = state["probe_meta"]["m0_begin"]
        m4b = state["probe_meta"]["m4_begin"]
        print("[probe] buy-block entries=%d" % len(state["probe"]))
        for e in state["probe"][:80]:
            bi = (e[1] - m4b) // 0x28 if m4b and e[1] >= m4b else -1
            b2i = (e[2] - m4b) // 0x28 if m4b and e[2] >= m4b else -1
            o2i = (e[4] - m0b) // 0xA0 if m0b and e[4] >= m0b else -1
            print("   entry bar=%d bar2=%d o2pos=%d" % (bi, b2i, o2i))

    outs = state["outs"]
    real_wnmr = outs.get("wnmr", [])
    real_pri = outs.get("wnmrpri", [])
    chduan = outs.get("chduan", [])
    chbi = outs.get("chbi", [])

    print("[native] CHBI nonzero=%d  CHDUAN nonzero=%d" % (
        sum(1 for v in chbi if v != 0.0), sum(1 for v in chduan if v != 0.0)))
    print("[native] WNMR status hist=%s" % json.dumps(hist_int(real_wnmr)))
    print("[native] WNMRPRI nonzero=%d" % sum(1 for v in real_pri if v != 0.0))

    # ---- Python replay on the exact same pre-WNMRNEW container snapshot ----
    py_objs, _ = parse_records(state["snapshot"])
    t1 = time.time()
    py_out = wnwr_new(py_objs, n, arr=chduan)
    py_pri = wnwr_pri_new(py_objs, n)
    print("[py] replay %.2fs  status hist=%s  pri nonzero=%d" % (
        time.time() - t1, json.dumps(hist_int(py_out)),
        sum(1 for v in py_pri if v != 0.0)))

    d_status = compare("WNMRNEW status", real_wnmr, py_out)
    d_price = compare("WNMRPRINEW price", real_pri, py_pri)

    # per-object diff detail
    detail = []
    if d_status or d_price:
        real_by_idx = {}
        for o in objs:
            real_by_idx.setdefault(o.index, []).append(o)
        py_by_idx = {}
        for o in py_objs:
            py_by_idx.setdefault(o.index, []).append(o)
        bad_idx = sorted({d[0] + 1 for d in d_status} | {d[0] + 1 for d in d_price})
        for idx in bad_idx[:200]:
            for o in real_by_idx.get(idx, []):
                detail.append({"side": "native", **obj_row(o)})
            for o in py_by_idx.get(idx, []):
                detail.append({"side": "python", **obj_row(o)})

    report = {
        "count": n,
        "records": len(objs),
        "native": {
            "chbi_nonzero": sum(1 for v in chbi if v != 0.0),
            "chduan_nonzero": sum(1 for v in chduan if v != 0.0),
            "wnmr_hist": hist_int(real_wnmr),
            "pri_nonzero": sum(1 for v in real_pri if v != 0.0),
        },
        "python": {
            "wnmr_hist": hist_int(py_out),
            "pri_nonzero": sum(1 for v in py_pri if v != 0.0),
        },
        "diff": {
            "status_count": len(d_status),
            "price_count": len(d_price),
            "status_first": d_status[:50],
            "price_first": d_price[:50],
        },
        "detail": detail,
    }
    rep_path = os.path.join(DUMP_DIR, "wnmr_e2e_report_%s.json" % tag)
    with open(rep_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    print("saved %s" % rep_path)

    full_path = os.path.join(DUMP_DIR, "wnmr_e2e_full_%s.json" % tag)
    with open(full_path, "w", encoding="utf-8") as fh:
        json.dump({"count": n, "native_wnmr": real_wnmr, "native_pri": real_pri,
                   "python_wnmr": py_out, "python_pri": py_pri,
                   "chbi": chbi, "chduan": chduan}, fh)
    print("saved %s" % full_path)

    if os.path.exists(CRASH_REPORT):
        print("==== CRASH REPORT ====")
        print(open(CRASH_REPORT, encoding="utf-8").read())

    ok = state["done"] and not d_status and not d_price
    print("RESULT: %s" % ("ALL MATCH" if ok else "DIFF/INCOMPLETE"))
    sys.stdout.flush()
    os._exit(0 if ok else 1)


if __name__ == "__main__":
    main()
