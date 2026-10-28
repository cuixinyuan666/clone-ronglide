# -*- coding: utf-8 -*-
"""把三个已验证信号写进安装目录的用户公式，并让 1 分钟图落在信号当天。"""
import os
import shutil
import struct
import time

INSTALL = r"D:\a_ronglide\缠中说禅"
BACKUP = r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\install_backup"
USER_TA = os.path.join(INSTALL, "TAF", "UserTA.taf")
PAGE = os.path.join(INSTALL, "Pages", "技术分析.xml")
DATA = os.path.join(INSTALL, "Dat", "His", "02", "1", "600000.1")

# 0 基，含首不含尾。三个信号 35280 / 35400 / 35405 落在窗口中后段。
SLICE_LO = 35220
SLICE_HI = 35450

SRC = (
    "ST1:=DATE=20170810 AND HOUR=9 AND MINUTE=31;\r\n"
    "ST3:=DATE=20170810 AND HOUR=13 AND MINUTE=1;\r\n"
    "ST2:=DATE=20170810 AND HOUR=13 AND MINUTE=6;\r\n"
    "DRAWTEXT(ST2,12.80,'买入价 12.72'),COLORCYAN;\r\n"
    "DRAWTEXT(ST3,12.70,'止损价 12.70'),COLORRED;\r\n"
    "DRAWTEXT(ST1,12.78,'状态1 12.72'),COLORYELLOW;\r\n"
    "DRAWICON(ST2,L,1);\r\n"
    "WNMRSHOW:C;\r\n"
)


def backup(src):
    rel = os.path.relpath(src, INSTALL)
    dst = os.path.join(BACKUP, rel)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if not os.path.exists(dst):
        shutil.copy2(src, dst)
        print("backup", rel)
    else:
        print("backup exists", rel)


def enc(s):
    b = s.encode("gbk")
    if len(b) < 255:
        return bytes([len(b)]) + b
    return bytes([0xFF]) + len(b).to_bytes(4, "little") + b


def main():
    backup(USER_TA)
    backup(PAGE)
    backup(DATA)

    raw = open(USER_TA, "rb").read()
    if raw[-2:] != bytes.fromhex("1b7a"):
        raise SystemExit("UserTA end marker changed")
    if b"WNMRSHOW" in raw:
        print("WNMRSHOW already present, rewrite from backup")
        raw = open(os.path.join(BACKUP, "TAF", "UserTA.taf"), "rb").read()
    name_at = raw.find(b"TESTCHBI1")
    src_end = raw.find(b"TESTCHBI:VAR1;") + len(b"TESTCHBI:VAR1;")
    trailer = raw[src_end:name_at and src_end + 37]
    if len(trailer) != 37:
        raise SystemExit("trailer %d" % len(trailer))
    cat = raw[raw.find(b"TESTMA") + 6 + 1:raw.find(b"TESTMA") + 6 + 1 + 13]
    # category sits right after empty title
    # re-read from known offset used by both records: bytes after title-len 0
    cat_i = raw.find(bytes([0x0D]) + "技术指标/缠论".encode("gbk"))
    if cat_i < 0:
        raise SystemExit("category not found")
    cat = raw[cat_i + 1:cat_i + 1 + 13]
    if cat.decode("gbk") != "技术指标/缠论":
        raise SystemExit("bad cat")

    rec = b"".join([
        enc("WNMRSHOW"),
        enc(""),
        enc("技术指标/缠论"),
        enc("0.0.0"),
        enc(""),
        enc(SRC),
    ]) + trailer
    body = raw[:-2] + rec + raw[-2:]
    # count at offset 8
    count = struct.unpack_from("<I", body, 8)[0]
    print("old count", count, "src bytes", len(SRC.encode("gbk")))
    body = body[:8] + struct.pack("<I", count + 1) + body[12:]
    # stamp edit date/time
    now = time.localtime()
    ymd = now.tm_year * 10000 + now.tm_mon * 100 + now.tm_mday
    hms = now.tm_hour * 10000 + now.tm_min * 100 + now.tm_sec
    body = body[:12] + struct.pack("<II", ymd, hms) + body[20:]
    open(USER_TA, "wb").write(body)
    print("UserTA", len(body), "count", struct.unpack_from("<I", body, 8)[0])

    page = open(PAGE, "r", encoding="utf-8").read()
    page2 = page.replace('<Win Higth="4" Study="MA"/>', '<Win Higth="4" Study="WNMRSHOW"/>', 1)
    page2 = page2.replace('<Win Higth="1" Study="TESTCHBI1"/>', '<Win Higth="1" Study="WNMRSHOW"/>', 1)
    if page2 == page:
        raise SystemExit("page pattern not found")
    open(PAGE, "w", encoding="utf-8", newline="\r\n").write(page2)
    print("page updated")

    data = open(DATA, "rb").read()
    n = (len(data) - 68) // 36
    if n < SLICE_HI:
        raise SystemExit("bars %d" % n)
    chunk = data[:68] + data[68 + SLICE_LO * 36:68 + SLICE_HI * 36]
    open(DATA, "wb").write(chunk)
    print("data sliced", SLICE_LO, SLICE_HI, "bars", (len(chunk) - 68) // 36)


if __name__ == "__main__":
    main()
