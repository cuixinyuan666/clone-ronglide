#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
chbi.py — P=51 全链重放骨架（CHBI 第五批）

来源: docs/20-CHBI-第二批-四函数解剖与条件格.md
       docs/21-CHBI-第三批-P51分型笔与共用后处理.md
       docs/22-CHBI-第四批-db40状态机与元素模板对账.md
执行: python tools/wnmr_py/chbi.py          # 跑桩
      python tools/wnmr_py/chbi.py --selftest  # 自测
"""
import struct
import sys


# ---------- A0 元素（0xA0 字节，db40/e200 共享） ----------
class A0Elem:
    SIZE = 0xA0

    def __init__(self, **kw):
        self.bar = kw.get("bar", 0)         # +0x00: bar 序号
        self.H = kw.get("H", 0.0)          # +0x04
        self.L = kw.get("L", 0.0)          # +0x08
        self.fractal = kw.get("fractal", 0)  # +0x14: 0=未, +1=顶, -1=底
        self.dir = kw.get("dir", 0)        # +0x1C: 方向
        self.endpoint = kw.get("endpoint", 0)  # +0x20: 端点 ±1 (e200 戳 / a040 记录)
        self.H_max_elem = kw.get("H_max_elem", 0.0)  # +0x50: H_max_elem (H_max 存档)
        self.dir_field = kw.get("dir_field", 0)  # +0x54: 方向 1/-1/2/-2
        self.x70 = kw.get("x70", 0)        # +0x70: 候选标志
        self.x78 = kw.get("x78", 0)        # +0x78: bar 序号副本
        self.x98 = kw.get("x98", 0)        # +0x98: "×2" 输出标志

    def to_bytes(self):
        b = bytearray(self.SIZE)
        b[0:4] = struct.pack("<i", self.bar)
        b[4:8] = struct.pack("<f", self.H)
        b[8:12] = struct.pack("<f", self.L)
        b[0x14:0x18] = struct.pack("<i", self.fractal)
        b[0x1C:0x20] = struct.pack("<i", self.dir)
        b[0x20:0x24] = struct.pack("<i", self.endpoint)
        b[0x50:0x54] = struct.pack("<f", self.H_max_elem)
        b[0x54:0x58] = struct.pack("<i", self.dir_field)
        b[0x70:0x74] = struct.pack("<i", self.x70)
        b[0x78:0x7C] = struct.pack("<i", self.x78)
        b[0x98:0x9C] = struct.pack("<i", self.x98)
        return bytes(b)


class W:
    """CHBI W 容器（持有指针持有体）"""

    def __init__(self):
        # W+0x20 (ContA 向下笔), W+0x30 (ContB 向上笔), W+0x40 (ContC 全量)
        self.m0 = []   # 候选元素列表（A0 元素）
        self.m5 = []   # 记录元素列表（0x28 元素）
        self.ContA = []  # 向下笔
        self.ContB = []  # 向上笔
        self.ContC = []  # 全量
        # 私有槽（f170 用：W+0x88 / +0x90 / +0x8C）
        self.slot_88 = 0
        self.slot_8C = 0
        self.slot_90 = 0


# ---------- 子函数骨架 ----------
def db40_replay(w, H, L):
    """db40 候选端点生成 (docs/22 §3 + test_db40.py 状态机)

    简化版：单边 H 触发，每 k 生成 A0 elem push_back 到 w.m0。
    返回 cand_idx 序列与首条推送时刻。
    """
    n = len(H)
    if n <= 1:
        return []
    pushes = []
    cand = -1
    ebx = 0
    H_max = 0.0
    L_min = 0.0
    first_flag = 0
    mode = 1
    for k in range(1, n):
        Hk = float(H[k])
        Lk = float(L[k])
        if mode == 1:
            mode = 0
        # ebx 分流在 P=51 路径下被 e200/a040 接管，db40 主体走 cond 17-25
        if ebx > 0:
            cand = (cand + 1) if cand > 0 else (k - 1)
            ebx = 1
            dir_ = 1
        else:
            cand = (cand + 1) if cand > 0 else (k - 1)
            ebx = -1
            dir_ = -1
        if cand < 0:
            cand = -1
        elem = A0Elem(
            bar=k, H=Hk, L=Lk,
            dir=dir_, endpoint=0,
            H_max_elem=H_max, dir_field=dir_,
            x70=1 if first_flag == 0 else 0,
            x78=k, x98=1,
        )
        w.m0.append(elem)
        first_flag = 1
        pushes.append((k, cand, dir_))
    return pushes


def e200_replay(w):
    """e200 严格包含分型标注 (docs/21 §3)

    对 m0[i] (1 ≤ i ≤ n-2)：
      顶 ⇔ H[i-1]<H[i] ∧ L[i-1]<L[i] ∧ H[i+1]<H[i] ∧ L[i+1]<L[i]  → +0x14 = +1
      底 ⇔ H[i-1]>H[i] ∧ L[i-1]>L[i] ∧ H[i+1]>L[i] ∧ L[i+1]>L[i]  → +0x14 = -1
      其余（含 =, U）不写
    """
    n = len(w.m0)
    cnt_top = 0
    cnt_bot = 0
    for i in range(1, n - 1):
        a, c, b = w.m0[i - 1], w.m0[i], w.m0[i + 1]
        is_top = (a.H < c.H and a.L < c.L and b.H < c.H and b.L < c.L)
        is_bot = (a.H > c.H and a.L > c.L and b.H > c.H and b.L > c.L)
        if is_top:
            c.fractal = +1
            cnt_top += 1
        elif is_bot:
            c.fractal = -1
            cnt_bot += 1
    return cnt_top, cnt_bot


def a040_replay(w):
    """a040 分型笔记录生成 (docs/21 §4)

    扫 m0，检测 ±1 标记，按"借用端点"语义生成 0x28 笔记录 push 到 w.m5。
    简化版：每对相邻 ±1 元素生成一条记录。
    """
    n = len(w.m0)
    pending = None
    counter = 0
    for i in range(n):
        f = w.m0[i].fractal
        if f == 0:
            continue
        if pending is None:
            # 首个标记元素：冻结入 pending
            pending = (i, w.m0[i].fractal, w.m0[i])
            continue
        # 形成一笔：prev_mark, frozen, cur
        prev_idx, prev_dir, prev_elem = pending
        cur_idx = i
        cur_dir = f
        counter += 1
        # 0x28 元素：+0x00=seq, +0x04=顶idx, +0x08=底idx, +0x0C=顶H, +0x10=底L,
        #            +0x14=dir, +0x18/0x1C/0x20=0, +0x24=-1.0
        rec = {
            "seq": counter,
            "top_idx": cur_idx if cur_dir == +1 else prev_idx,
            "bot_idx": prev_idx if cur_dir == +1 else cur_idx,
            "top_H": w.m0[cur_idx if cur_dir == +1 else prev_idx].H,
            "bot_L": w.m0[cur_idx if cur_dir == +1 else cur_idx].L,
            "dir": cur_dir,
            "endpoint": 1,
        }
        w.m5.append(rec)
        # 端点戳
        w.m0[rec["top_idx"]].endpoint = +1
        w.m0[rec["bot_idx"]].endpoint = -1
        pending = (cur_idx, cur_dir, w.m0[cur_idx])
    # 收尾：剩余 pending 仍写一次
    if pending is not None and counter == 0:
        # 单个 ±1 标记，留作"未配对"
        pass
    return counter


def eba0_replay(w):
    """eba0 按方向拆分 ContA/ContB + 端点戳 (docs/21 §5.1)

    遍历 m5，dir=+1 → ContB, dir=-1 → ContA；
    m0 top/bot 端点戳 +1/-1（与 a040 同构）。
    """
    for rec in w.m5:
        tmp = dict(rec)
        if rec["dir"] == +1:
            w.ContB.append(tmp)
        elif rec["dir"] == -1:
            w.ContA.append(tmp)
        w.m0[rec["top_idx"]].endpoint = +1
        w.m0[rec["bot_idx"]].endpoint = -1


def ef00_replay(w):
    """ef00 全量复制到 ContC + 端点戳 (docs/21 §5.2)

    遍历 m5，复制到 ContC；m0 top/bot 端点戳 +1/-1。
    """
    for rec in w.m5:
        tmp = dict(rec)
        tmp["x20"] = 0
        w.ContC.append(tmp)
        w.m0[rec["top_idx"]].endpoint = +1
        w.m0[rec["bot_idx"]].endpoint = -1


def output_ring(w, count):
    """输出环 (docs/21 §1)

    遍历 m0（步进 0xA0），按 bar 序号排序：
      out[elem.bar - 1] = (double)elem.endpoint
      若 elem.x98 == 1:  × 2
      空档位置补 0
    """
    out = [0.0] * count
    cur = 0
    for elem in sorted(w.m0, key=lambda e: e.bar):
        b = elem.bar
        # 补 0 到 b-1
        while cur < b - 1:
            out[cur] = 0.0
            cur += 1
        v = float(elem.endpoint)
        if elem.x98 == 1:
            v *= 2
        out[b - 1] = v
        cur = b
    # 末尾补 0
    while cur < count:
        out[cur] = 0.0
        cur += 1
    return out


def chbi_p51_replay(H, L, count, iface_authorize_ok=True):
    """P=51 全链重放主函数（硬编码 P=51 入口，对应 sub_1002c4b0）

    H, L: float 列表（已还原为小数点后的值）
    count: bar 总数
    iface_authorize_ok: 第二道 EA62 授权门（True=通过，False=-1 拒）

    返回: outD 列表（与 H/L 等长）
    """
    if count <= 0:
        return None
    if not iface_authorize_ok:
        return None  # EA62 拒

    w = W()
    db40_replay(w, H, L)
    e200_replay(w)
    a040_replay(w)
    eba0_replay(w)
    ef00_replay(w)
    out = output_ring(w, count)
    return out


# ---------- 自测 ----------
def selftest():
    """简化 P=51 全链跑通测试"""
    # 构造 6 根 bar，单调上升 → 应能产生 1-2 条分型笔
    H = [10.0, 11.0, 12.0, 13.0, 12.0, 13.0]
    L = [9.0, 10.0, 11.0, 12.0, 11.0, 12.0]
    out = chbi_p51_replay(H, L, count=6, iface_authorize_ok=True)
    assert out is not None
    assert len(out) == 6
    print("[OK] selftest: out =", out)
    # 验证接口拒
    out2 = chbi_p51_replay(H, L, count=6, iface_authorize_ok=False)
    assert out2 is None
    print("[OK] selftest: EA62 deny returns None")
    # 验证 count=0
    out3 = chbi_p51_replay(H, L, count=0, iface_authorize_ok=True)
    assert out3 is None
    print("[OK] selftest: count=0 returns None")
    # 验证 A0 elem 字节布局
    e = A0Elem(bar=5, H=12.0, L=11.0, fractal=+1, dir=1, endpoint=1, x98=1)
    b = e.to_bytes()
    assert len(b) == 0xA0
    assert struct.unpack("<i", b[0:4])[0] == 5
    assert struct.unpack("<f", b[4:8])[0] == 12.0
    assert struct.unpack("<i", b[0x14:0x18])[0] == +1
    assert struct.unpack("<i", b[0x20:0x24])[0] == 1
    assert struct.unpack("<i", b[0x98:0x9C])[0] == 1
    print("[OK] selftest: A0Elem round-trip OK (160 bytes)")
    return 0


def main():
    if "--selftest" in sys.argv:
        return selftest()
    print("chbi.py — P=51 全链重放骨架")
    print("执行: python chbi.py --selftest")
    print("链路: db40 → e200 → a040 → eba0 → ef00 → 输出环")
    return 0


if __name__ == "__main__":
    sys.exit(main())
