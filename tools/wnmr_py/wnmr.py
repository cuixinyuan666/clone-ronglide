# -*- coding: utf-8 -*-
"""wnmr.py — 「无脑买入线段」核心算法 Python 移植 (from pseudocode/wnmr.c + docs/03,05,12)

逐条证据映射（地址为 TAFLib.dll, ImageBase 0x10000000）:
  LevelObj           步长 0xA0, 字段偏移见 doc 05 §8.1 / doc 12 §8
  Bar28              步长 0x28, W->m[4] 输入 bar, doc 12 §2/§8
  vec_begin_plus_n   sub_1003F0D0 (0 基, 越界夹到 end —— 复刻显式跳过, doc 12 §3.3)
  ArgMax             sub_10056010 (严格 < 才更新, 取 max 首次位置)
  ArgMin             sub_100560D0 (>= 即更新, 取 min 最后位置)
  MarkSignalFlag     sub_10060AA0 (直接映射 1.0f→+1, -1.0f→-1)
  MergeByFlag        sub_100616B0 (相邻相反信号配对成 bar)
  MainEngine         sub_10056190 (区间不重叠判定 + 状态码写入)
  WNMRNEW            sub_1003A7C0 (编排: 打标→归并→主引擎→快照→out[index-1]=status)
  WNMRPRINEW         sub_1003A960 (out[index-1]=price)

证据等级标注:
  [强] 静态反汇编直接读出   [中] 结构/对称性推理   [开] 待动态验证 (doc 12 §5 V1-V5)
"""
from dataclasses import dataclass, field

ST_STRUCT_UP = 1
ST_BUY = 2
ST_STOPLOSS = 3
ST_STRUCT_DOWN = 4
ST_SELL = 5
ST_TAKEPROFIT = 6


@dataclass
class LevelObj:
    index: int = 0          # +0x00  1 基序号 (out 下标 = index-1)          [强]
    idx_prev: int = 0       # +0x04  索引A=前一顶点 (卖出组查表用)           [强]
    idx_next: int = 0       # +0x08  索引B=后一顶点 (买入组查表用)           [强]
    low: float = 0.0        # +0x0C  LOW  (卖出价格源)                     [强]
    high: float = 0.0       # +0x10  HIGH (买入价格源)                     [强]
    level_type: int = 0     # +0x14  分型选择器: 1=取后继底 -1=取前驱顶      [强]
    direction: int = 0      # +0x20  1=涨 -1=跌 0=未定 (0 才处理)           [强]
    fractal: int = 0        # +0x88  1=顶 -1=底                            [强]
    signal_flag: int = 0    # +0x8C  MarkSignalFlag 写入                   [强]
    status: int = 0         # +0x90  ★状态码 1..6 → VAR5                  [强]
    price: float = 0.0      # +0x94  ★实际价格  → VAR6                     [强]


@dataclass
class Bar28:
    serial: int = 0         # +0x00  1 基序号                              [强]
    f04: int = 0            # +0x04  索引 (卖出组查表基)                    [中]
    pos: int = 0            # +0x08  0 基索引 → LevelObj 下标 (买入组查表基)  [强]
    low: float = 0.0        # +0x0C                                        [强]
    high: float = 0.0       # +0x10                                        [强]


def vec_begin_plus_n(objs, n):
    if n < 0 or n >= len(objs):
        return None
    return objs[n]


def arg_max(arr):
    best = arr[0]
    idx = 1
    for k in range(1, len(arr)):
        if not (best >= arr[k]):
            best = arr[k]
            idx = k + 1
    return idx


def arg_min(arr):
    best = arr[0]
    idx = 1
    for k in range(1, len(arr)):
        if best >= arr[k]:
            best = arr[k]
            idx = k + 1
    return idx


def mark_signal_flag(objs, arr):
    for o in objs:
        o.signal_flag = 0
    for i, v in enumerate(arr):
        if v != 1.0 and v != -1.0:
            continue
        for o in objs:
            if o.index == i + 1:
                o.signal_flag = 1 if v == 1.0 else -1
                break


def merge_by_flag(objs):
    bars = []
    n = len(objs)
    if n <= 2:
        return bars
    prev = objs[1]
    for i in range(2, n):
        curr = objs[i]
        if curr.signal_flag == 1 and prev.signal_flag == -1:
            bars.append(Bar28(low=curr.low, high=prev.high))
        elif curr.signal_flag == -1 and prev.signal_flag == 1:
            bars.append(Bar28(low=prev.low, high=curr.high))
        prev = curr
    return bars


def write_status(o, status, price):
    o.status = status
    o.price = price


def main_engine(objs, bars, journal=None):
    """sub_10056190 核心骨架。

    已验证 (静态):
      [强] 触发条件为严格不等式 (fcompp + test 掩码 41h/1/5, doc 05 §3.2/§4.1)
           买入: bar.high < t.low    (t = objs[bar.pos])   ← 掩码 1 / jne
           卖出: bar.low  > t.high   (t = objs[bar.f04])   ← 掩码 41h
      [强] direction ∈ {1,-1} 跳过 (0x1005a18e/0x1005a19f)
      [强] 哨兵 n 越界显式跳过 (复刻要求, doc 12 §3.3)
      [强] 卖出组 4/5/6 与 买入组 1/2/3 写向不同对象 (否则公式无法同时显示全部标签)
      [中] 卖出组首写查表基 = bar+0x04, 买入组 = bar+0x08 (doc 05 §5.1 对称表)
      [中] 组内三写目标: 首写=查表(bar.f04/pos), 次写=本 bar 的 pos 对象, 末写=窗口后一 bar (doc 12 §4.1 block 5,5,7)
      [开] 次写对象 [esp+6Ch] 与窗口配对细节需 x64dbg 验证 (doc 12 §5)
    """
    n = len(objs)
    for i, bar in enumerate(bars):
        buy_t = vec_begin_plus_n(objs, bar.pos)
        if buy_t is not None and bar.high < buy_t.low and buy_t.direction == 0:
            o1 = buy_t
            o2 = vec_begin_plus_n(objs, bar.f04)
            o3 = None
            nxt = bars[i + 2] if i + 2 < len(bars) else None
            if nxt is not None:
                o3 = vec_begin_plus_n(objs, nxt.pos)
            write_status(o1, ST_STRUCT_UP, bar.high)
            if o2 is not None:
                write_status(o2, ST_BUY, bar.high)
            if o3 is not None:
                write_status(o3, ST_STOPLOSS, bar.high)
            if journal is not None:
                journal.append(('buy', i, bar, o1, o2, o3))

        sell_t = vec_begin_plus_n(objs, bar.f04)
        if sell_t is not None and bar.low > sell_t.high and sell_t.direction == 0:
            o4 = sell_t
            o5 = vec_begin_plus_n(objs, bar.pos)
            o6 = None
            nxt = bars[i + 2] if i + 2 < len(bars) else None
            if nxt is not None:
                o6 = vec_begin_plus_n(objs, nxt.f04)
            write_status(o4, ST_STRUCT_DOWN, bar.low)
            if o5 is not None:
                write_status(o5, ST_SELL, bar.low)
            if o6 is not None:
                write_status(o6, ST_TAKEPROFIT, bar.low)
            if journal is not None:
                journal.append(('sell', i, bar, o4, o5, o6))


def mark_direction(src, table):
    t1 = vec_begin_plus_n(table, src.idx_prev)
    if t1 is not None:
        t1.direction = 1
    t2 = vec_begin_plus_n(table, src.idx_next)
    if t2 is not None:
        t2.direction = -1


def wnwr_new(objs, count, arr=None, bars=None):
    """sub_1003A7C0: 三级流水线 + out[obj.index-1]=status。arr/bars 由上游 CHBI/CHDUAN 提供。"""
    out = [0.0] * count
    if arr is not None:
        mark_signal_flag(objs, arr)
    if bars is None:
        bars = merge_by_flag(objs)
    main_engine(objs, bars)
    for o in objs:
        k = o.index - 1
        if 0 <= k < count:
            out[k] = float(o.status)
    return out


def wnwr_pri_new(objs, count):
    """sub_1003A960: out[obj.index-1]=price。"""
    out = [0.0] * count
    for o in objs:
        k = o.index - 1
        if 0 <= k < count:
            out[k] = float(o.price)
    return out
