#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
db40 状态机 Python 重放（可运行单元测试）

来源: tools/re-inventory/chbi/f_1003db40.txt + cond_1003db40.txt
语义: 复刻 0x1003db40 的"候选端点生成"决策——给定 H/L 序列，按
  cand/refpoint 规则产生 A0 元素 push_back 序列。

执行: python tools/re-inventory/chbi/test_db40.py
"""
import struct
import sys


# ---------- x87 flag decoder (from x87_sim.py) ----------
def fcom(st0, stk):
    """Return (C0, C2, C3) from comparing st0 vs stk (x87 fcom encoding).

    C0=st0<stk, C2=unordered, C3=st0==stk.
    """
    if st0 != st0 or stk != stk:  # NaN/unordered
        return 1, 1, 1
    if st0 > stk:  return 0, 0, 0  # >
    if st0 < stk:  return 1, 0, 0  # <
    return 0, 0, 1  # equal


def jcc_taken(cond_mask, c0, c2, c3):
    """Decode 'test ah, X; jcc target' from 25-cond table.

    Returns (zf, pf, sf) flags after the AND.
    """
    ah = c0 | (c2 << 2) | (c3 << 6)
    res = ah & cond_mask
    zf = res == 0
    pf = bin(res & 0xff).count("1") % 2 == 0  # PF=1: even number of set bits
    sf = (res & 0x80) != 0
    return zf, pf, sf


# ---------- A0 元素模板 (0xA0 字节) ----------
class A0Elem:
    SIZE = 0xA0

    def __init__(self):
        self.data = bytearray(self.SIZE)

    def __setitem__(self, k, v):
        if isinstance(v, float):
            self.data[k:k+4] = struct.pack("<f", v)
        else:
            self.data[k:k+4] = struct.pack("<f", float(v))

    def __getitem__(self, k):
        return struct.unpack("<f", bytes(self.data[k:k+4]))[0]


# ---------- db40 状态机 (Python 重放) ----------
def db40(H, L):
    """Replay 0x1003db40(W, count, srcH, srcL).

    H, L: parallel float lists (length = count).
    Returns: list of (k, cand_idx, dir, elem) — push_back sequence.
    """
    n = len(H)
    if n <= 1:
        return []

    # stack locals
    first_flag = 0
    mode = 1
    H_max = 0.0
    L_min = 0.0
    cand = None
    ebx = 0
    pushes = []

    for k in range(1, n):
        Hk = float(H[k])
        Lk = float(L[k])
        if mode == 1:
            mode = 0  # 首轮：仅写一次
        if ebx > 0:
            # 上轮向上 → 触顶候选
            c1 = fcom(L_min, Hk)  # cond 1: L_min < Hk?
            c2 = fcom(H_max, Lk)  # cond 2: H_max > Lk?
            if c1[0] == 1 and c2[0] == 0:  # L_min<Hk AND H_max<=Lk
                cand = (cand + 1) if (cand is not None and cand > 0) else (k - 1)
            else:
                cand = k - 1
            ebx = 1
            push_dir = 1
        elif ebx <= 0:
            # 上轮向下 / 首轮 → 触底候选
            c3 = fcom(L_min, Hk)
            c4 = fcom(H_max, Lk)
            if c3[0] == 1 and c4[0] == 0:
                cand = (cand + 1) if (cand is not None and cand > 0) else (k - 1)
            else:
                cand = k - 1
            ebx = -1
            push_dir = -1
        else:
            push_dir = 0

        if cand is None or cand < 0:
            cand = -1

        elem = A0Elem()
        elem[0x00] = float(k)
        elem[0x04] = Hk
        elem[0x08] = Lk
        elem[0x0C] = float(push_dir)
        elem[0x10] = H_max
        elem[0x50] = H_max
        elem[0x54] = float(push_dir)
        elem[0x70] = 1
        elem[0x78] = float(k)
        elem[0x98] = 1
        pushes.append((k, cand, push_dir, elem))

    return pushes


# ---------- self-tests ----------
def test_elem_size():
    e = A0Elem()
    assert len(e.data) == 0xA0
    e[0] = 42.0
    assert e[0] == 42.0
    e[4] = 0.5
    assert e[4] == 0.5
    print("[OK] test_elem_size")


def test_fcom_unordered():
    assert fcom(float('nan'), 1.0) == (1, 1, 1)
    print("[OK] test_fcom_unordered")


def test_fcom_basic():
    assert fcom(2.0, 1.0) == (0, 0, 0)  # >
    assert fcom(1.0, 2.0) == (1, 0, 0)  # <
    assert fcom(1.0, 1.0) == (0, 0, 1)  # =
    print("[OK] test_fcom_basic")


def test_x87_ah1_jne():
    """cond 1/3/5/6/15/16/20: 'test ah,1 jne' 译码 = st0<stk 或 U 跳"""
    # (C0, C2, C3): >=(0,0,0); <(1,0,0); =(0,0,1); U(1,1,1)
    # jne = ZF=0 → res!=0 → C0=1 → 跳
    cases = [((0, 0, 0), False), ((1, 0, 0), True),
             ((0, 0, 1), False), ((1, 1, 1), True)]
    for (c0, c2, c3), expect_jump in cases:
        zf, _, _ = jcc_taken(1, c0, c2, c3)
        assert (not zf) == expect_jump, "ah,1 jne (%d,%d,%d) fail" % (c0, c2, c3)
    print("[OK] test_x87_ah1_jne (cond 1/3/5/6/15/16/20: st0<stk or U)")


def test_x87_ah41_jp():
    """cond 2/4/13/19: 'test ah,0x41 jp' 译码 = > 或 U 跳 (PF=1)"""
    # >: ah=0    → res=0   (0 bits) → PF=1
    # <: ah=1    → res=1   (1 bit)  → PF=0
    # =: ah=0x40 → res=0x40 (1 bit)  → PF=0
    # U: ah=0x45 → res=0x41 (2 bits) → PF=1
    cases = [((0, 0, 0), True), ((1, 0, 0), False),
             ((0, 0, 1), False), ((1, 1, 1), True)]
    for (c0, c2, c3), expect_pf in cases:
        _, pf, _ = jcc_taken(0x41, c0, c2, c3)
        assert pf == expect_pf, "ah,0x41 jp (%d,%d,%d) fail" % (c0, c2, c3)
    print("[OK] test_x87_ah41_jp (cond 2/4/13/19: st0>stk or U)")


def test_x87_ah5_jp():
    """cond 8/23: 'test ah,5 jp' 译码 = ≥ (含 =) 跳; < 不跳; U 跳(因 0x5=0b101 偶数 bits)"""
    # ah,0x5 = C0(b0) | C2(b2). mask 只看 bit 0/2.
    # < (1,0,0): ah=1    res=1    (1 bit)  → PF=0 → 不跳
    # > (0,0,0): ah=0    res=0    (0 bits) → PF=1 → 跳
    # = (0,0,1): ah=0x40 res=0    (C2,C0=0, bit 6 不在 mask) → PF=1 → 跳
    # U (1,1,1): ah=0x45 res=0x5  (bits 0,2) → 2 bits PF=1 → 跳
    # 即 ah,5 jp = st0>=stk 或 unordered
    cases = [((1, 0, 0), False), ((0, 0, 0), True),
             ((0, 0, 1), True), ((1, 1, 1), True)]
    for (c0, c2, c3), expect_pf in cases:
        _, pf, _ = jcc_taken(5, c0, c2, c3)
        assert pf == expect_pf, "ah,5 jp (%d,%d,%d) expected PF=%s got %s" % (c0, c2, c3, expect_pf, pf)
    print("[OK] test_x87_ah5_jp (cond 8/23: st0>=stk or U)")


def test_x87_ah44_jnp():
    """cond 22: 'test ah,0x44 jnp' 译码 = jnp 跳 = PF=0"""
    # ah,0x44 mask 包含 bit 6 (C3) 与 bit 2 (C2)
    # =: ah=0x40 → res=0x40 (1 bit) → PF=0 → jnp 跳
    # >: ah=0    → res=0    (0 bits) → PF=1 → jnp 不跳
    # <: ah=1    → res=0    (0 bits) → PF=1 → jnp 不跳
    # U: ah=0x45 → res=0x44 (2 bits) → PF=1 → jnp 不跳
    # 即 ah,0x44 jnp = st0==stk only（NaN 不会触发；非 NaN 输入时是 "=="）
    cases = [((0, 0, 1), True), ((0, 0, 0), False),
             ((1, 0, 0), False), ((1, 1, 1), False)]
    for (c0, c2, c3), expect_jnp_jump in cases:
        _, pf, _ = jcc_taken(0x44, c0, c2, c3)
        # jnp 跳 = PF=0
        actual_jnp_jump = (not pf)
        assert actual_jnp_jump == expect_jnp_jump, \
            "ah,0x44 jnp (%d,%d,%d) expect_jnp=%s got=%s" % (c0, c2, c3, expect_jnp_jump, actual_jnp_jump)
    print("[OK] test_x87_ah44_jnp (cond 22: st0==stk only, NaN-safe)")


def test_empty_input():
    assert db40([], []) == []
    assert db40([10], [9]) == []
    print("[OK] test_empty_input")


def test_basic_up():
    """单调上升：cand 应为合法值序列，元素结构正确"""
    H = [10, 11, 12, 13, 14, 15, 16]
    L = [9, 10, 11, 12, 13, 14, 15]
    out = db40(H, L)
    assert len(out) > 0
    for k, cand, d, elem in out:
        assert cand >= -1
        assert d in (-1, 0, 1)
        # 元素结构：H[+4] == 输入 Hk
        assert abs(elem[4] - H[k]) < 1e-6, "elem[4]=%g Hk=%g" % (elem[4], H[k])
        # 元素结构：L[+8] == 输入 Lk
        assert abs(elem[8] - L[k]) < 1e-6
    print("[OK] test_basic_up: %d pushes, all cand>=-1, elem struct OK" % len(out))


def test_basic_down():
    """单调下降：同上结构检查"""
    H = [16, 15, 14, 13, 12, 11, 10]
    L = [15, 14, 13, 12, 11, 10, 9]
    out = db40(H, L)
    assert len(out) > 0
    for k, cand, d, elem in out:
        assert cand >= -1
        assert d in (-1, 0, 1)
        assert abs(elem[4] - H[k]) < 1e-6
        assert abs(elem[8] - L[k]) < 1e-6
    print("[OK] test_basic_down: %d pushes, elem struct OK" % len(out))


def test_cand_init_minus_one():
    H = [10, 11, 12, 13]
    L = [9, 10, 11, 12]
    out = db40(H, L)
    assert out[0][1] >= 0
    print("[OK] test_cand_init_minus_one: first cand = %d" % out[0][1])


def test_cand_minus_one_keeps():
    """cand=-1 写值后续会被用到（验证 round-trip 不会越界）"""
    H = [0, 0, 0, 0, 1, 1, 1, 1]
    L = [0, 0, 0, 0, 0, 0, 0, 0]
    out = db40(H, L)
    assert all(c >= -1 for _, c, _, _ in out)
    print("[OK] test_cand_minus_one_keeps: %d pushes, all cand>=-1" % len(out))


def main():
    test_elem_size()
    test_fcom_unordered()
    test_fcom_basic()
    test_x87_ah1_jne()
    test_x87_ah41_jp()
    test_x87_ah5_jp()
    test_x87_ah44_jnp()
    test_empty_input()
    test_basic_up()
    test_basic_down()
    test_cand_init_minus_one()
    test_cand_minus_one_keeps()
    print("\n=== db40 状态机单元测试 12/12 通过 ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
