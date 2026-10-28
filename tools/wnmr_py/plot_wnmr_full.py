"""Read wnmr_full JSON dump and plot signal window."""
import argparse
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from chbi51 import load_tdx1

DATASET = r"D:\a_ronglide\缠中说禅\Dat\His\02\1\600000.1"

STATE_LABEL = {
    2: "买入价",
    3: "止损价",
    5: "卖出价",
    6: "止赢价",
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default=os.path.join(HERE, "dumps", "wnmr_run_latest.json"))
    ap.add_argument("--out", default=os.path.join(HERE, "wnmr_full_chart.png"))
    ap.add_argument("--i0", type=int, default=34800)
    ap.add_argument("--i1", type=int, default=36000)
    ap.add_argument("--dataset", default=DATASET)
    args = ap.parse_args()

    with open(args.json, encoding="utf-8") as fh:
        d = json.load(fh)
    n = d["count"]
    wnmr = d["wnmr"]
    pri = d["pri"]

    H, L, _ = load_tdx1(args.dataset)
    if len(H) > n:
        H, L = H[:n], L[:n]
    mid = [(H[i] + L[i]) / 2.0 for i in range(n)]

    i0 = max(0, args.i0)
    i1 = min(n, args.i1)
    xs = list(range(i0, i1))
    ys = [mid[i] for i in xs]

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    from matplotlib import font_manager

    cjk = None
    for fname in ("Microsoft YaHei", "SimHei", "SimSun", "MS Gothic"):
        try:
            cjk = font_manager.FontProperties(family=fname)
            plt.rcParams["font.sans-serif"] = [fname]
            plt.rcParams["axes.unicode_minus"] = False
            break
        except Exception:
            cjk = None
    if cjk is None:
        cjk = font_manager.FontProperties()

    fig, ax = plt.subplots(figsize=(14, 6), dpi=120)
    ax.plot(xs, ys, color="#333333", linewidth=0.8, label="(H+L)/2")
    ax.set_title("WNMR full signals (wnmr_full.py)")
    ax.set_xlabel("bar index (0-based)")
    ax.set_ylabel("price")
    ax.grid(True, alpha=0.3)

    for i in range(n):
        st = int(wnmr[i]) if wnmr[i] == int(wnmr[i]) else wnmr[i]
        if st == 0 or st == 0.0:
            continue
        st_i = int(st)
        if not (i0 <= i < i1):
            continue
        price = pri[i] if pri[i] else mid[i]
        label = STATE_LABEL.get(st_i, str(st_i))
        ax.scatter([i], [price], s=80, zorder=5)
        ax.annotate(
            "%s\n%.2f" % (label, price),
            (i, price),
            textcoords="offset points",
            xytext=(0, 12),
            ha="center",
            fontsize=9,
            color="#c00000",
            fontproperties=cjk,
        )

    fig.tight_layout()
    fig.savefig(args.out)
    print("saved", args.out)


if __name__ == "__main__":
    main()
