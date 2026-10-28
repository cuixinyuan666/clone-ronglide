"""dupai.py - compare the emulator's CHBI P=51 output against a live frida dump.

Usage:
  python dupai.py <emulator.json> <frida.json> [--tol 1e-9]

Both files carry {"count": N, "out": [...doubles...]}. Exits non-zero when any
element differs beyond tolerance.
"""
import argparse
import json
import sys


def load(path):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    count = data.get("count", data.get("bars"))
    return count, data["out"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("emulator")
    ap.add_argument("frida")
    ap.add_argument("--tol", type=float, default=1e-9)
    args = ap.parse_args()

    ca, a = load(args.emulator)
    cb, b = load(args.frida)
    if ca != cb:
        print("count mismatch: emulator=%d frida=%d" % (ca, cb))
        return 2
    diff = [(i, a[i], b[i]) for i in range(ca) if abs(a[i] - b[i]) > args.tol]
    nz_a = sum(1 for v in a if v != 0.0)
    nz_b = sum(1 for v in b if v != 0.0)
    print("count=%d  nonzero: emulator=%d frida=%d  differing=%d" % (
        ca, nz_a, nz_b, len(diff)))
    if diff:
        print("first differences:")
        for i, va, vb in diff[:20]:
            print("  [%d] emulator=%r frida=%r" % (i, va, vb))
        return 1
    print("MATCH: outputs are identical")
    return 0


if __name__ == "__main__":
    sys.exit(main())
