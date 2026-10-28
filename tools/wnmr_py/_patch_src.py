# -*- coding: utf-8 -*-
path = r"D:\a_ronglide\缠中说禅\TAF\UserTA.taf"
src = (
    "DRAWTEXT(CURRBARSCOUNT=23155 OR (DATE=20170810 AND HOUR=13 AND MINUTE=6),H,'买入价 12.72'),COLORCYAN;\r\n"
    "DRAWTEXT(CURRBARSCOUNT=23160 OR (DATE=20170810 AND HOUR=13 AND MINUTE=1),L,'止损价 12.70'),COLORRED;\r\n"
    "DRAWTEXT(CURRBARSCOUNT=23280 OR (DATE=20170810 AND HOUR=9 AND MINUTE=31),H,'状态1 12.72'),COLORYELLOW;\r\n"
    "WNMRSHOW:C;"
)
b = src.encode("gbk")
d = open(path, "rb").read()
start = d.find(b"ST1:=")
if start < 0:
    start = d.find(b"DRAWTEXT")
prefix = start - 5
if d[prefix] != 0xFF:
    raise SystemExit("prefix %s" % d[prefix:start].hex())
old = int.from_bytes(d[prefix + 1:prefix + 5], "little")
end = start + old
print("old", old, "new", len(b), "tail", len(d) - end)
out = d[:prefix] + bytes([0xFF]) + len(b).to_bytes(4, "little") + b + d[end:]
open(path, "wb").write(out)
print("wrote", len(out))
