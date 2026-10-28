# -*- coding: utf-8 -*-
"""test_wnmr.py — wnmr.py 分支级逐点核对 (期望值手工推导自 docs 03/05/12)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wnmr import (LevelObj, Bar28, arg_max, arg_min, mark_signal_flag,
                  merge_by_flag, main_engine, mark_direction,
                  wnwr_new, wnwr_pri_new)

PASS = []
FAIL = []

def check(name, cond, detail=''):
    if cond:
        PASS.append(name)
    else:
        FAIL.append('%s %s' % (name, detail))
        print('FAIL:', name, detail)


def mk_obj(index, low=0.0, high=0.0, **kw):
    o = LevelObj(index=index, low=low, high=high)
    for k, v in kw.items():
        setattr(o, k, v)
    return o


def test_argmax():
    check('argmax.basic', arg_max([3, 1, 4, 1, 5, 9, 2, 6]) == 6)
    check('argmax.tie_first', arg_max([5, 5]) == 1)
    check('argmax.tie_mid', arg_max([1, 5, 5, 2]) == 2)
    check('argmax.last', arg_max([1, 2, 3]) == 3)
    check('argmax.single', arg_max([7]) == 1)


def test_argmin():
    check('argmin.tie_last', arg_min([5, 5]) == 2)
    check('argmin.mid', arg_min([3, 1, 1, 2]) == 3)
    check('argmin.last', arg_min([3, 1, 4, 1, 5]) == 4)
    check('argmin.single', arg_min([7]) == 1)


def test_mark_signal_flag():
    objs = [mk_obj(i) for i in range(1, 6)]
    mark_signal_flag(objs, [0.0, 1.0, 0.0, -1.0, 0.0])
    got = [o.signal_flag for o in objs]
    check('msf.map', got == [0, 1, 0, -1, 0], got)

    mark_signal_flag(objs, [2.0, 0.0, 0.0, -0.5, 0.0])
    got = [o.signal_flag for o in objs]
    check('msf.nonpm1_skipped_and_cleared', got == [0, 0, 0, 0, 0], got)

    objs2 = [mk_obj(i) for i in (1, 3, 5)]
    mark_signal_flag(objs2, [1.0, 0.0, -1.0, 0.0, 1.0])
    got = [o.signal_flag for o in objs2]
    check('msf.sparse_index', got == [1, -1, 1], got)


def test_merge_by_flag():
    vals = [(1, 1, 2), (3, 3, 4), (5, 5, 6), (7, 7, 8), (9, 9, 10)]
    objs = [mk_obj(i, low=l, high=h) for i, (_, l, h) in enumerate(vals, 1)]
    for o, s in zip(objs, [0, -1, 1, -1, 1]):
        o.signal_flag = s
    bars = merge_by_flag(objs)
    check('mbf.count', len(bars) == 3, len(bars))
    if len(bars) == 3:
        check('mbf.bar0', bars[0].low == 5 and bars[0].high == 4, (bars[0].low, bars[0].high))
        check('mbf.bar1', bars[1].low == 5 and bars[1].high == 8, (bars[1].low, bars[1].high))
        check('mbf.bar2', bars[2].low == 9 and bars[2].high == 8, (bars[2].low, bars[2].high))

    check('mbf.n_le_2', merge_by_flag([mk_obj(1), mk_obj(2)]) == [])
    three = [mk_obj(i) for i in (1, 2, 3)]
    for o, s in zip(three, [0, 1, 0]):
        o.signal_flag = s
    check('mbf.no_pair', merge_by_flag(three) == [])


def test_main_engine_buy():
    A = mk_obj(1, low=1, high=2)
    B = mk_obj(2, low=12, high=15)
    C = mk_obj(3, low=7, high=9)
    D = mk_obj(4, low=20, high=25)
    objs = [A, B, C, D]
    bar = Bar28(serial=1, f04=3, pos=1, low=10, high=11)
    journal = []
    main_engine(objs, [bar], journal=journal)
    check('buy.strict_trigger', len(journal) == 1 and journal[0][0] == 'buy', journal)
    check('buy.o1_status', B.status == 1, B.status)
    check('buy.o2_status', D.status == 2, D.status)
    check('buy.price_src_high', B.price == 11 and D.price == 11, (B.price, D.price))

    A2 = mk_obj(1, low=1, high=100)
    B2 = mk_obj(2, low=12, high=15)
    B2.direction = 1
    bar2 = Bar28(serial=1, f04=0, pos=1, low=10, high=11)
    main_engine([A2, B2], [bar2])
    check('buy.direction_filter', B2.status == 0, B2.status)

    A3 = mk_obj(1, low=1, high=100)
    B3 = mk_obj(2, low=12, high=15)
    bar3 = Bar28(serial=1, f04=0, pos=1, low=10, high=12)
    main_engine([A3, B3], [bar3])
    check('buy.strict_equal_no_trigger', B3.status == 0, B3.status)

    A4 = mk_obj(1, low=1, high=2)
    B4 = mk_obj(2, low=12, high=15)
    bar4 = Bar28(serial=1, f04=0, pos=99, low=10, high=11)
    main_engine([A4, B4], [bar4])
    check('buy.sentinel_skip', B4.status == 0, B4.status)


def test_main_engine_sell():
    A = mk_obj(1, low=1, high=2)
    B = mk_obj(2, low=7, high=9)
    bar = Bar28(serial=1, f04=1, pos=0, low=10, high=11)
    main_engine([A, B], [bar])
    check('sell.strict_trigger', B.status == 4 and A.status == 5, (A.status, B.status))
    check('sell.price_src_low', A.price == 10 and B.price == 10, (A.price, B.price))

    A2 = mk_obj(1, low=1, high=2)
    bar2 = Bar28(serial=1, f04=0, pos=0, low=2, high=11)
    main_engine([A2], [bar2])
    check('sell.strict_equal_no_trigger', A2.status == 0, A2.status)

    A3 = mk_obj(1, low=1, high=2)
    A3.direction = -1
    bar3 = Bar28(serial=1, f04=0, pos=0, low=10, high=11)
    main_engine([A3], [bar3])
    check('sell.direction_filter', A3.status == 0, A3.status)


def test_wnwr_new_end_to_end():
    A = mk_obj(1, low=1, high=2)
    B = mk_obj(2, low=12, high=15)
    C = mk_obj(3, low=7, high=9)
    D = mk_obj(4, low=20, high=25)
    objs = [A, B, C, D]
    bars = [Bar28(serial=1, f04=3, pos=1, low=10, high=11),
            Bar28(serial=2, f04=0, pos=3, low=26, high=27)]
    out = wnwr_new(objs, 4, bars=bars)
    check('e2e.out', out == [4.0, 1.0, 0.0, 5.0], out)
    pri = wnwr_pri_new(objs, 4)
    check('e2e.pri', pri == [26.0, 11.0, 0.0, 26.0], pri)
    check('e2e.multi_object_distinct', len({id(A), id(B), id(C), id(D)}) == 4)


def test_mark_direction():
    tbl = [mk_obj(i) for i in range(6)]
    src = mk_obj(9, low=5, high=6, idx_prev=1, idx_next=3)
    mark_direction(src, tbl)
    check('mdir.prev+1', tbl[1].direction == 1, tbl[1].direction)
    check('mdir.next-1', tbl[3].direction == -1, tbl[3].direction)


def main():
    for fn in (test_argmax, test_argmin, test_mark_signal_flag, test_merge_by_flag,
               test_main_engine_buy, test_main_engine_sell,
               test_wnwr_new_end_to_end, test_mark_direction):
        fn()
    print('PASS: %d  FAIL: %d' % (len(PASS), len(FAIL)))
    if FAIL:
        for f in FAIL:
            print('  -', f)
        sys.exit(1)


if __name__ == '__main__':
    main()
