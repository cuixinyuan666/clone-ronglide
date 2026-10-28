# -*- coding: utf-8 -*-
path = r"D:\a_ronglide\缠中说禅\TAF\UserTA.taf"
src = (
    "DRAWTEXT(DATE=20170810 AND HOUR=13 AND MINUTE=6,H,'买入价 12.72'),COLORCYAN;\r\n"
    "DRAWTEXT(DATE=1170810 AND HOUR=13 AND MINUTE=6,H,'买入价 12.72'),COLORCYAN;\r\n"
    "DRAWTEXT(DATE=20170810 AND HOUR=13 AND MINUTE=1,L,'止损价 12.70'),COLORRED;\r\n"
    "DRAWTEXT(DATE=1170810 AND HOUR=13 AND MINUTE=1,L,'止损价 12.70'),COLORRED;\r\n"
    "DRAWTEXT(DATE=20170810 AND HOUR=9 AND MINUTE=31,H,'状态1 12.72'),COLORYELLOW;\r\n"
    "DRAWTEXT(DATE=1170810 AND HOUR=9 AND MINUTE=31,H,'状态1 12.72'),COLORYELLOW;\r\n"
    "WNMRSHOW:C;"
)
b = src.encode("gbk")
d = open(path, "rb").read()
start = d.find(b"DRAWTEXT")
prefix = start - 5
if d[prefix] != 0xFF:
    raise SystemExit("bad prefix")
old = int.from_bytes(d[prefix + 1:prefix + 5], "little")
end = start + old
out = d[:prefix] + bytes([0xFF]) + len(b).to_bytes(4, "little") + b + d[end:]
open(path, "wb").write(out)
print("newsrc", len(b), "file", len(out))
