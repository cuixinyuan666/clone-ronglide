# -*- coding: utf-8 -*-
"""
SysTA.taf 公式库解析器 —— 提取全部公式的名称/标题/分类/版本/描述/源码。

格式（实测 2026-10-16 逆向）:
  记录 = [1B nlen][name GBK] [1B tlen][title GBK] [1B clen][category GBK]
         [1B vlen][version GBK] [dlen][desc GBK] [slen][src GBK]
  其中 [xlen] 为 1 字节长度；当该字节=0xFF 时，后随 u32 LE 长度。
  回溯定位：以版本串为锚点，用不动点法解出前后各长度字节。

用法:
  python extract_taf.py [SysTA.taf路径] [-o 输出json]
"""
import json
import re
import sys

DEFAULT_TAF = r"D:\a_ronglide\缠中说禅\TAF\SysTA.taf"


def is_valid_str(b: bytes) -> bool:
    """GBK 可解码且无控制字符"""
    try:
        s = b.decode("gbk")
    except UnicodeDecodeError:
        return False
    return all((ch.isprintable() or ch in "\r\n\t") for ch in s)


def solve_len_back(data: bytes, end: int, maxl: int = 255):
    """解出"[len][str]"中 str 结束于 end 的结构: 找 l 使 data[end-1-l]==l 且可解码。
    允许 l==0（空串，如无标题的记录）。返回 (start_of_len_byte, length) 或 None"""
    for l in range(0, maxl + 1):
        if end - 1 - l < 0:
            break
        if data[end - 1 - l] == l and is_valid_str(data[end - l : end]):
            return (end - 1 - l, l)
    return None


def read_len(data: bytes, p: int):
    """[1B 长度] 或 [0xFF + u32 LE 长度]。返回 (len, next_pos)"""
    b = data[p]
    if b == 0xFF:
        return int.from_bytes(data[p + 1 : p + 5], "little"), p + 5
    return b, p + 1


def parse_record(data: bytes, vpos: int):
    """vpos = 版本串长度字节位置。返回 dict 或 None"""
    try:
        vlen = data[vpos]
        version = data[vpos + 1 : vpos + 1 + vlen].decode("gbk")
        if not re.fullmatch(r"\d+\.\d+(\.\d+)*", version):
            return None
        # 描述段
        p = vpos + 1 + vlen
        dlen, p = read_len(data, p)
        desc = data[p : p + dlen].decode("gbk", "replace")
        p += dlen
        # 源码段
        slen, p = read_len(data, p)
        src = data[p : p + slen].decode("gbk", "replace")
        # 回溯 metadata
        r1 = solve_len_back(data, vpos)  # category
        if not r1:
            return None
        cpos, clen = r1
        r2 = solve_len_back(data, cpos)  # title
        if not r2:
            return None
        tpos, tlen = r2
        r3 = solve_len_back(data, tpos)  # name
        if not r3:
            return None
        npos, nlen = r3
        name = data[npos + 1 : npos + 1 + nlen].decode("gbk")
        title = data[tpos + 1 : tpos + 1 + tlen].decode("gbk")
        cat = data[cpos + 1 : cpos + 1 + clen].decode("gbk")
        return {
            "name": name,
            "title": title,
            "category": cat,
            "version": version,
            "desc": desc,
            "source": src,
            "offset": npos,
        }
    except Exception:
        return None


def main():
    taf = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else DEFAULT_TAF
    out = None
    if "-o" in sys.argv:
        out = sys.argv[sys.argv.index("-o") + 1]
    data = open(taf, "rb").read()
    # 锚点: 长度字节 + 版本串 (0.x / 1.x / 2.x 等)
    anchors = [m.start() for m in re.finditer(rb"[\x01-\x0a]\d+\.\d+(?:\.\d+)*", data)]
    records = []
    seen = set()
    for a in anchors:
        if a in seen:
            continue
        rec = parse_record(data, a)
        if rec and rec["source"].strip():
            seen.add(a)
            records.append(rec)
    # 去重（同名+同源码只留一条）
    uniq, keys = [], set()
    for r in records:
        k = (r["name"], r["source"][:80])
        if k in keys:
            continue
        keys.add(k)
        uniq.append(r)
    print("anchors:", len(anchors), " parsed:", len(records), " unique:", len(uniq))
    cats = {}
    for r in uniq:
        cats[r["category"]] = cats.get(r["category"], 0) + 1
    for c, n in sorted(cats.items(), key=lambda x: -x[1]):
        print(f"  cat {c!r}: {n}")
    if out:
        json.dump(uniq, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        print("written", out)


if __name__ == "__main__":
    main()
