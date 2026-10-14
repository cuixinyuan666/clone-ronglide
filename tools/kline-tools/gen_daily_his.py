# -*- coding: utf-8 -*-
"""从 1 分钟数据聚合成日线，并按融立德自描述容器格式写 .his 文件。
容器格式: [u32 头长=14+n*6][u16 ?][u16 记录数][u16 ?][u16 记录长][u16 字段数]
          然后 n 个 6 字节字段定义: (id:u16, (偏移<<8)|类型:u16, flags:u16=0x0400)
"""
import struct, os, sys, collections

SRC = r"C:\Users\Administrator\Downloads\1min"
APP = r"D:\a_ronglide\缠中说禅"

# 字段 id / 类型 (从官方 02# 文件破解得到)
F_DATE, F_TIME = 102, 101
F_O, F_C, F_H, F_L = 104, 105, 107, 108
F_VOL, F_AMT, F_RSV = 211, 214, 225
T_DATE, T_TIME, T_FLOAT, T_OTHER = 12, 13, 10, 9


def build(header_schema, records):
    n = len(header_schema)
    hdr_size = 14 + n * 6
    rec_size = max(off + 4 for _, off, _ in header_schema)
    buf = bytearray()
    buf += struct.pack("<I", hdr_size)
    buf += struct.pack("<H", 0) + struct.pack("<H", len(records))
    buf += struct.pack("<H", 0) + struct.pack("<H", rec_size)
    buf += struct.pack("<H", n)
    for fid, off, typ in header_schema:
        buf += struct.pack("<HHH", fid, (off << 8) | typ, 0x0400)
    for r in records:
        rec = bytearray(rec_size)
        for (fid, off, typ), val in zip(header_schema, r):
            if typ == T_FLOAT:
                struct.pack_into("<f", rec, off, float(val))
            else:
                struct.pack_into("<I", rec, off, int(val) & 0xFFFFFFFF)
        buf += rec
    return bytes(buf)


def daily_agg(src_file):
    data = open(src_file, "rb").read()
    hdr_size = struct.unpack_from("<I", data, 0)[0]
    cnt = struct.unpack_from("<H", data, 6)[0]
    rec_size = struct.unpack_from("<H", data, 10)[0]
    off = hdr_size
    days = collections.OrderedDict()
    for i in range(cnt):
        r = data[off:off + rec_size]
        off += rec_size
        d = struct.unpack_from("<I", r, 0)[0]
        o, c = struct.unpack_from("<f", r, 8)[0], struct.unpack_from("<f", r, 12)[0]
        h, l = struct.unpack_from("<f", r, 16)[0], struct.unpack_from("<f", r, 20)[0]
        v, a = struct.unpack_from("<f", r, 24)[0], struct.unpack_from("<f", r, 28)[0]
        if d not in days:
            days[d] = [o, c, h, l, v, a]
        else:
            e = days[d]
            e[1] = c
            e[2] = max(e[2], h)
            e[3] = min(e[3], l)
            e[4] += v
            e[5] += a
    return [(d, *vals) for d, vals in days.items()]


# 日线 schema 猜测(8 字段, 无时间)
SCHEMA8 = [
    (F_DATE, 0, T_DATE),
    (F_O, 4, T_FLOAT),
    (F_C, 8, T_FLOAT),
    (F_H, 12, T_FLOAT),
    (F_L, 16, T_FLOAT),
    (F_VOL, 20, T_FLOAT),
    (F_AMT, 24, T_FLOAT),
    (F_RSV, 28, T_FLOAT),
]
# 变体: 保留时间字段(9 字段)
SCHEMA9 = [
    (F_DATE, 0, T_DATE),
    (F_TIME, 4, T_TIME),
    (F_O, 8, T_FLOAT),
    (F_C, 12, T_FLOAT),
    (F_H, 16, T_FLOAT),
    (F_L, 20, T_FLOAT),
    (F_VOL, 24, T_FLOAT),
    (F_AMT, 28, T_FLOAT),
    (F_RSV, 32, T_FLOAT),
]

code = sys.argv[1] if len(sys.argv) > 1 else "600000"
variant = sys.argv[2] if len(sys.argv) > 2 else "8"
market = sys.argv[3] if len(sys.argv) > 3 else "02"

bars = daily_agg(os.path.join(SRC, f"02#{code}#1"))
print(code, "daily bars:", len(bars), "range", bars[0][0], "..", bars[-1][0])

if variant == "8":
    recs = [[d, o, c, h, l, v, a, 0.0] for d, o, c, h, l, v, a in bars]
    blob = build(SCHEMA8, recs)
else:
    recs = [[d, 0, o, c, h, l, v, a, 0.0] for d, o, c, h, l, v, a in bars]
    blob = build(SCHEMA9, recs)

for sub in (market, "SH" if market == "02" else "SZ"):
    dst_dir = os.path.join(APP, "Dat", "His", sub)
    os.makedirs(dst_dir, exist_ok=True)
    dst = os.path.join(dst_dir, f"{code}.his")
    open(dst, "wb").write(blob)
    print("wrote", dst, len(blob))
