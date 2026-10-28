"""wnmr_full.py - 「无脑买入线段」全链 x86emu 执行 + 原生 e2e 对拍。

链路（全部由 x86emu 逐条执行 TAFLib.dll 真实反汇编）:
    CHBI(c1d0) -> CHDUAN(0x2c710) -> WNMRNEW(0x3a7c0) -> WNMRPRINEW(0x3a960)

对拍基准: dumps/wnmr_e2e_full_{N}.json（frida 原生执行产物, 2026-10-19）。
目标: chbi/chduan/wnmr/wnmrpri 四组输出逐位 0 diff。

用法:
    python wnmr_full.py --max-bars 2000
    python wnmr_full.py --max-bars 58560 --dump-json out.json
"""
import argparse
import json
import os
import pickle
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from x86emu import Halt, AssertHit, UnknownCall, UnknownInsn, EmuError, SENTINEL, run
from chbi51 import build_inputs, load_tdx1, read_out, EVIDENCE_DIR as CHBI_DIR

HERE = os.path.dirname(os.path.abspath(__file__))
REINV = os.path.normpath(os.path.join(HERE, "..", "re-inventory"))
CHDUAN_DIR = os.path.join(REINV, "chduan")
WNMR_DIR = os.path.join(REINV, "wnmr")
DUMPS = os.path.join(HERE, "dumps")
DATASET = r"D:\a_ronglide\缠中说禅\Dat\His\02\1\600000.1"

# chbi51 的 CODE_FILES 之外, WNMR/CHDUAN 链路所需的全部函数体
EXTRA_CODE = [
    # WNMRNEW 编排层 + 主引擎 + 打标 + 归并 (chbi/ 证据集, 2026-10-19 实例归因用)
    ("chbi", "f_10056190.txt"),   # MainEngine 8173 条指令, 4 内联实例
    ("chbi", "f_10060aa0.txt"),   # MarkSignalFlag
    ("chbi", "f_100616b0.txt"),   # MergeByFlag
    # CHDUAN 入口 + prepare
    ("chduan", "engine_1002c710.txt"),
    # 本批新增反汇编 (disasm_func.py 生成)
    ("wnmr", "f_1003a7c0.txt"),   # WNMRNEW 封装层
    ("wnmr", "f_1003a960.txt"),   # WNMRPRINEW
    ("wnmr", "f_10053540.txt"),   # CHDUAN prepare
    ("wnmr", "f_10056010.txt"),   # argmax (严格 < 更新)
    ("wnmr", "f_100560d0.txt"),   # argmin (>= 更新)
    # 受检迭代器取元素 + vector 扩容族 (运行中 UnknownCall 补齐)
    ("wnmr", "f_1006a830.txt"),
    ("wnmr", "f_1006a930.txt"),
    ("wnmr", "f_1006a9e0.txt"),
    ("wnmr", "f_1006a680.txt"),
    ("wnmr", "f_1006a6a0.txt"),
    ("wnmr", "f_1006a860.txt"),
    ("wnmr", "f_1006a8e0.txt"),
    ("wnmr", "f_1006aa90.txt"),
    ("wnmr", "f_1006ad60.txt"),
    ("wnmr", "f_1003d720.txt"),
]

ENTRY_CHDUAN = 0x1002C710
ENTRY_WNMRNEW = 0x1003A7C0
ENTRY_WNMRPRI = 0x1003A960

STACK_TOP = 0x30100000


def make_emu_full():
    from x86emu import make_emu
    emu = make_emu(CHBI_DIR)
    n = 0
    for sub, name in EXTRA_CODE:
        n += emu.load_dis_file(os.path.join(REINV, sub, name))
    return emu, n


def call_phase(emu, pc_entry, args, eax=0, ecx=0, edx=0, max_steps=500000000):
    """单阶段调用: args 按cdecl逆序压栈(最后一个参数先压), SENTINEL 停机。"""
    r = emu.r
    r[4] = STACK_TOP
    r[0] = eax
    r[1] = ecx
    r[2] = edx
    for v in reversed(args):
        emu.push(v)
    emu.push(SENTINEL)
    emu.pc = pc_entry
    t0 = time.perf_counter()
    try:
        run(emu, max_steps=max_steps)
        ret = None
    except Halt as h:
        ret = h.eax
    return ret, time.perf_counter() - t0


def hist(vals):
    h = {}
    for v in vals:
        h[v] = h.get(v, 0) + 1
    return {str(k): h[k] for k in sorted(h)}


def diff_list(real, py):
    return [(i, real[i], py[i]) for i in range(min(len(real), len(py)))
            if real[i] != py[i]]


def save_ckpt(emu, path):
    with open(path, "wb") as fh:
        pickle.dump({"pages": emu.mem.pages, "heap": emu.heap,
                     "malloc_log": emu.malloc_log, "steps": emu.steps}, fh, 2)
    print("checkpoint saved: %s (%.1f MB)" % (path, os.path.getsize(path) / 1e6))


def load_ckpt(emu, path):
    with open(path, "rb") as fh:
        d = pickle.load(fh)
    emu.mem.pages = d["pages"]
    emu.heap = d["heap"]
    emu.malloc_log = d["malloc_log"]
    emu.steps = d["steps"]
    print("checkpoint loaded: %s" % path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-bars", type=int, default=2000)
    ap.add_argument("--max-steps", type=int, default=2000000000)
    ap.add_argument("--dataset", default=DATASET)
    ap.add_argument("--dump-json", metavar="OUT.json")
    ap.add_argument("--no-compare", action="store_true")
    ap.add_argument("--ckpt", metavar="FILE.pkl",
                    help="load/save pre-WNMRNEW state (auto-save after CHDUAN)")
    args = ap.parse_args()

    H, L, _ = load_tdx1(args.dataset)
    if args.max_bars:
        H, L = H[:args.max_bars], L[:args.max_bars]
    n = len(H)
    print("dataset: %d bars" % n)

    emu, nextra = make_emu_full()
    print("emu loaded: %d instrs (extra %d lines)" % (len(emu.code), nextra))

    build_inputs(emu, H, L)  # W 容器 + series + CELL/IFACE; 返回值弃用
    out_chbi, out_duan, out_wnmr, out_pri = (emu.alloc(8 * n) for _ in range(4))
    holder = emu.alloc(4)
    emu.wr32(holder, out_duan)
    ctx = 0x40000400  # IFACE (chbi51.build_inputs 内 vtbl[1]=HOOK_AUTH)
    cell = 0x40000100  # CELL
    series = 0x40000200

    if args.ckpt and os.path.exists(args.ckpt):
        load_ckpt(emu, args.ckpt)
    else:
        # ---- phase 1: CHBI c1d0 (cell,count,out,series,iface) ----
        ret1, t1 = call_phase(emu, 0x1002C1D0, [cell, n, out_chbi, series, ctx])
        print("[chbi]  ret=0x%08x  %.2fs steps=%d" % (ret1 or 0, t1, emu.steps))
        if ret1 != 0:
            return 1

        # ---- phase 2: CHDUAN (eax=cell, ecx=count, [out, ctx], ret 8) ----
        ret2, t2 = call_phase(emu, ENTRY_CHDUAN, [out_duan, ctx], eax=cell, ecx=n)
        print("[chduan] ret=0x%08x  %.2fs steps=%d" % (ret2 or 0, t2, emu.steps))
        if ret2 != 0:
            return 1
        if args.ckpt:
            save_ckpt(emu, args.ckpt)

    # ---- phase 3: WNMRNEW (eax=cell, ecx=count, [out, holder, ctx], ret 0xC) ----
    ret3, t3 = call_phase(emu, ENTRY_WNMRNEW, [out_wnmr, holder, ctx],
                          eax=cell, ecx=n)
    print("[wnmr]  ret=0x%08x  %.2fs steps=%d asserts=%d" % (
        ret3 or 0, t3, emu.steps, emu.assert_count))
    if ret3 != 1:
        return 1

    # ---- phase 4: WNMRPRINEW (eax=cell, ecx=count, edx=ctx, [out], ret 4) ----
    ret4, t4 = call_phase(emu, ENTRY_WNMRPRI, [out_pri], eax=cell, ecx=n, edx=ctx)
    print("[pri]   ret=0x%08x  %.2fs steps=%d" % (ret4 or 0, t4, emu.steps))
    if ret4 != 1:
        return 1

    got = {
        "chbi": read_out(emu, out_chbi, n),
        "chduan": read_out(emu, out_duan, n),
        "wnmr": read_out(emu, out_wnmr, n),
        "pri": read_out(emu, out_pri, n),
    }
    print("[hist] chduan non-zero=%d  wnmr=%s  pri non-zero=%d" % (
        sum(1 for v in got["chduan"] if v != 0.0),
        json.dumps(hist(got["wnmr"])),
        sum(1 for v in got["pri"] if v != 0.0)))

    if args.dump_json:
        with open(args.dump_json, "w", encoding="utf-8") as fh:
            json.dump({"count": n, **{k: got[k] for k in got}}, fh)
        print("dumped %s" % args.dump_json)

    if args.no_compare:
        return 0

    exp_path = os.path.join(DUMPS, "wnmr_e2e_full_%d.json" % n)
    if not os.path.exists(exp_path):
        print("no native baseline: %s (skip compare)" % exp_path)
        return 0
    with open(exp_path, encoding="utf-8") as fh:
        exp = json.load(fh)
    ok = True
    for name, key in (("chbi", "chbi"), ("chduan", "chduan"),
                      ("wnmr", "native_wnmr"), ("pri", "native_pri")):
        real = exp.get(key) or []
        d = diff_list(real, got[name])
        print("[cmp] %-7s len real=%d py=%d diff=%d" % (
            name, len(real), len(got[name]), len(d)))
        for row in d[:10]:
            print("       [%d] real=%r py=%r" % row)
        if d:
            ok = False
    print("RESULT: %s" % ("ALL MATCH" if ok else "DIFF"))
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertHit, UnknownCall, UnknownInsn, EmuError) as e:
        print("EMULATION ERROR: %s" % e)
        sys.exit(3)
