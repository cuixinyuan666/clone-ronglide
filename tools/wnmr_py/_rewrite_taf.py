# -*- coding: utf-8 -*-
"""用短公式重写 UserTA，长度字节走 1 字节，避免 0xFF 扩展。"""
import os
import struct

BACKUP = r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\install_backup\TAF\UserTA.taf"
OUT = r"D:\a_ronglide\缠中说禅\TAF\UserTA.taf"
SRC = (
    "DRAWTEXT(DATE=20170810 AND HOUR=13 AND MINUTE=6,12.80,'买入价12.72'),COLORCYAN;\r\n"
    "DRAWTEXT(DATE=20170810 AND HOUR=13 AND MINUTE=1,12.70,'止损价12.70'),COLORRED;\r\n"
    "DRAWTEXT(DATE=20170810 AND HOUR=9 AND MINUTE=31,12.78,'状态1 12.72'),COLORYELLOW;"
    "WNMRSHOW:C;"
)


def enc(s):
    b = s.encode("gbk")
    if not (0 < len(b) < 255) and s != "":
        if len(b) >= 255:
            raise SystemExit("too long %d" % len(b))
    return bytes([len(b)]) + b


def main():
    raw = open(BACKUP, "rb").read()
    if b"WNMRSHOW" in raw:
        raise SystemExit("backup already modified")
    src_end = raw.find(b"TESTCHBI:VAR1;") + len(b"TESTCHBI:VAR1;")
    trailer = raw[src_end:src_end + 37]
    if len(trailer) != 37 or raw[-2:] != bytes.fromhex("1b7a"):
        raise SystemExit("bad backup")
    b = SRC.encode("gbk")
    print("src", len(b))
    rec = b"".join([
        enc("WNMRSHOW"),
        enc(""),
        enc("技术指标/缠论"),
        enc("0.0.0"),
        enc(""),
        enc(SRC),
    ]) + trailer
    body = raw[:-2] + rec + raw[-2:]
    count = struct.unpack_from("<I", body, 8)[0]
    body = body[:8] + struct.pack("<I", count + 1) + body[12:]
    open(OUT, "wb").write(body)
    print("wrote", len(body), "count", struct.unpack_from("<I", body, 8)[0])
    # sanity: source length byte is not 0xFF
    i = body.find(b"WNMRSHOW")
    print("near", body[i:i + 20])


if __name__ == "__main__":
    main()
