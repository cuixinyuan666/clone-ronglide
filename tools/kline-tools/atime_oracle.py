# -*- coding: utf-8 -*-
"""atime 预言机: 准备候选路径 / 检查哪个被软件读取。
  python atime_oracle.py prepare  : 建候选文件并把 atime 打到 2000-01-01
  python atime_oracle.py check    : 报告各候选文件 atime
"""
import os, sys, shutil, time

APP = r"D:\a_ronglide\缠中说禅"
SRC = r"C:\Users\Administrator\Downloads\1min"
MARK = 946684800  # 2000-01-01

CANDS = [
    ("Dat/Min/01/000001.min", "02#000001#1"),
    ("Dat/Min/02/000001.min", "02#000001#1"),
    ("Dat/Min/1/000001.min",  "02#000001#1"),
    ("Dat/Min/2/000001.min",  "02#000001#1"),
    ("Dat/Min/SH/000001.min", "02#000001#1"),
    ("Dat/Min/SZ/000001.min", "02#000001#1"),
    ("Dat/Min/000001.min",    "02#000001#1"),
    ("Dat/Min/000001/000001.min", "02#000001#1"),
    ("Dat/Min/01/600000.min", "02#600000#1"),
    ("Dat/Min/02/600000.min", "02#600000#1"),
    ("Dat/Min/SH/600000.min", "02#600000#1"),
    ("Dat/Min/600000.min",    "02#600000#1"),
]


def prepare():
    for rel, src in CANDS:
        dst = os.path.join(APP, rel.replace("/", os.sep))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if not os.path.exists(dst):
            shutil.copy2(os.path.join(SRC, src), dst)
        os.utime(dst, (MARK, MARK))
        print("prepared", rel)


def check():
    print(f"{'file':46s} {'atime':26s} read?")
    for rel, src in CANDS:
        p = os.path.join(APP, rel.replace("/", os.sep))
        if not os.path.exists(p):
            print(f"{rel:46s} MISSING")
            continue
        st = os.stat(p)
        read = "NO" if abs(st.st_atime - MARK) < 5 else "YES"
        t = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_atime))
        print(f"{rel:46s} {t:26s} {read}")


if sys.argv[1] == "prepare":
    prepare()
else:
    check()
