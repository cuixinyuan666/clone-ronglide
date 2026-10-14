#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
融立德(缠中说禅) 免费行情引擎 / Free Quote Feed Engine for RongLiDe
====================================================================
把免费行情源(Sina / Eastmoney)的数据拉取下来, 写成融立德 "系统 -> 数据导入/导出"
(或 "功能 -> 数据导入") 菜单能吃的 CSV 文本文件。

前置: 软件服务器已停服, 本工具用第三方免费行情 API 替代。
      (免费源经本机代理 127.0.0.1:19828 访问; 也可不填, 走系统默认代理)

用法:
  python ronglide_free_feed.py --source-folder "C:/Users/Administrator/Downloads/1min"
      # 自动从 02#代码#1 文件名提取股票清单, 拉取日线 + 1分钟, 输出到 ./output_csv

  python ronglide_free_feed.py --codes 600000,000001 --periods day,1min --start 20200101
      # 手动指定股票与周期

输出: output_csv/<code>_<period>.csv
  daily : 日期,开盘,最高,最低,收盘,成交量,成交额
  分钟  : 日期,时间,开盘,最高,最低,收盘,成交量,成交额

导入软件: 系统菜单 -> 数据导入/导出 -> 导入 -> 选 CSV -> 按对话框映射列
          (也可走 功能 -> 0508历史数据 导入你现有的 02#代码#1 原生文件)
"""

import os
import sys
import time
import json
import argparse
import urllib.request
import urllib.parse

# ------------------------- 配置 -------------------------
# 代理(本机出口). 留空 "" 则使用系统/环境变量代理.
PROXY = "http://127.0.0.1:19828"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"

# CSV 列顺序 (可按软件导入对话框要求调整)
DAY_COLS = ["日期", "开盘", "最高", "最低", "收盘", "成交量", "成交额"]
MIN_COLS = ["日期", "时间", "开盘", "最高", "最低", "收盘", "成交量", "成交额"]
DELIMITER = ","          # 分隔符: 逗号 或 "\t"(制表符)
WRITE_HEADER = False     # 融立德多数文本导入不需要表头, 默认 False

# 请求节流(Eastmoney 易限流)
SLEEP_PER_REQ = 0.6
MAX_RETRY = 3


# ------------------------- 工具 -------------------------
def proxy_opener():
    if PROXY:
        handler = urllib.request.ProxyHandler({"http": PROXY, "https": PROXY})
        return urllib.request.build_opener(handler)
    return urllib.request.build_opener()


OPENER = proxy_opener()


def http_get_json(url):
    last_err = None
    for attempt in range(1, MAX_RETRY + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with OPENER.open(req, timeout=30) as resp:
                raw = resp.read().decode("utf-8", "ignore")
            if not raw or raw.strip() in ("", "null", "{}"):
                time.sleep(SLEEP_PER_REQ * attempt)
                continue
            return json.loads(raw)
        except Exception as e:  # noqa
            last_err = e
            time.sleep(SLEEP_PER_REQ * attempt)
    print(f"  [warn] 请求失败 {url[:80]}... : {last_err}")
    return None


def market_of(code):
    """6 开头=上交所(sh), 其余=深交所(sz)"""
    return "sh" if code.startswith("6") else "sz"


# ------------------------- 数据源: 新浪 -------------------------
def sina_kline(code, scale, datalen=8000):
    """
    Sina getKLineData.
    scale: 240=日线, 5/15/30/60=分钟, 1=1分钟(新浪通常不返回)
    返回 list of dict: {date, time, open, high, low, close, volume}
    """
    sym = market_of(code) + code
    url = (f"https://money.finance.sina.com.cn/quotes_service/api/json_v2.php/"
           f"CN_MarketData.getKLineData?symbol={sym}&scale={scale}&ma=no&datalen={datalen}")
    data = http_get_json(url)
    if not data:
        return []
    out = []
    for row in data:
        day = row.get("day", "")
        if " " in day:
            date, t = day.split(" ", 1)
        else:
            date, t = day, "00:00:00"
        out.append({
            "date": date,
            "time": t,
            "open": row.get("open", ""),
            "high": row.get("high", ""),
            "low": row.get("low", ""),
            "close": row.get("close", ""),
            "volume": row.get("volume", ""),
        })
    return out


# ------------------------- 数据源: Eastmoney(1分钟兜底) -------------------------
def em_kline(code, klt, beg="19900101", end="20500101"):
    """
    Eastmoney kline. klt: 101=日线, 1=1分钟, 5=5分钟...
    返回 list of dict: {date, time, open, high, low, close, volume, amount}
    """
    mkt = "1" if code.startswith("6") else "0"
    secid = f"{mkt}.{code}"
    url = (f"https://push2his.eastmoney.com/api/qt/stock/kline/get?"
           f"secid={secid}&fields1=f1&fields2=f51,f52,f53,f54,f55,f56,f57"
           f"&klt={klt}&fqt=1&beg={beg}&end={end}")
    data = http_get_json(url)
    try:
        klines = data["data"]["klines"]
    except Exception:  # noqa
        return []
    out = []
    for kl in klines:
        parts = kl.split(",")
        # date[,time], open, close, high, low, volume, amount
        if " " in parts[0]:
            date, t = parts[0].split(" ", 1)
        else:
            date, t = parts[0], "00:00:00"
        o, c, h, l, v = parts[1], parts[2], parts[3], parts[4], parts[5]
        amt = parts[6] if len(parts) > 6 else ""
        out.append({"date": date, "time": t, "open": o, "high": h,
                    "low": l, "close": c, "volume": v, "amount": amt})
    return out


# ------------------------- 周期映射 -------------------------
# period -> (sina_scale, em_klt)
PERIOD_MAP = {
    "day":   (240, 101),
    "5min":  (5, 5),
    "15min": (15, 15),
    "30min": (30, 30),
    "60min": (60, 60),
    "1min":  (1, 1),
}


def fetch_period(code, period):
    sina_scale, em_klt = PERIOD_MAP[period]
    rows = sina_kline(code, sina_scale)
    if period == "1min" and not rows:
        # 新浪无 1 分钟, 转 Eastmoney
        rows = em_kline(code, em_klt)
    if not rows and period != "1min":
        # 新浪失败再试 Eastmoney
        rows = em_kline(code, em_klt)
    return rows


def approx_amount(volume, close):
    try:
        return str(round(float(volume) * float(close)))
    except Exception:  # noqa
        return "0"


def write_csv(path, cols, rows, is_min):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    lines = []
    if WRITE_HEADER:
        lines.append(DELIMITER.join(cols))
    for r in rows:
        if is_min:
            line = [r["date"], r["time"], r["open"], r["high"], r["low"],
                    r["close"], r["volume"],
                    r.get("amount") or approx_amount(r["volume"], r["close"])]
        else:
            line = [r["date"], r["open"], r["high"], r["low"], r["close"],
                    r["volume"],
                    r.get("amount") or approx_amount(r["volume"], r["close"])]
        lines.append(DELIMITER.join(line))
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return len(lines)


# ------------------------- 股票清单提取 -------------------------
def codes_from_folder(folder):
    codes = []
    if not folder or not os.path.isdir(folder):
        return codes
    for fn in os.listdir(folder):
        # 02#600000#1  -> 600000
        if "#" in fn:
            parts = fn.split("#")
            if len(parts) >= 2 and parts[1].isdigit():
                codes.append(parts[1])
    return sorted(set(codes))


# ------------------------- 主流程 -------------------------
def main():
    ap = argparse.ArgumentParser(description="融立德免费行情引擎")
    ap.add_argument("--codes", help="逗号分隔股票代码, 如 600000,000001")
    ap.add_argument("--source-folder", help="含 02#代码#1 文件的目录, 自动提取代码")
    ap.add_argument("--periods", default="day,1min", help="day,1min,5min,15min,30min,60min")
    ap.add_argument("--out", default="./output_csv", help="输出目录")
    ap.add_argument("--end", default="20500101", help="结束日期 YYYYMMDD")
    ap.add_argument("--start", default="19900101", help="开始日期 YYYYMMDD (日线/分钟回溯起点)")
    args = ap.parse_args()

    codes = []
    if args.codes:
        codes += [c.strip() for c in args.codes.split(",") if c.strip()]
    if args.source_folder:
        codes += codes_from_folder(args.source_folder)
    codes = sorted(set(codes))
    if not codes:
        print("未指定任何股票代码。用 --codes 或 --source-folder。")
        sys.exit(1)

    periods = [p.strip() for p in args.periods.split(",") if p.strip()]
    print(f"股票: {len(codes)} 只 | 周期: {periods} | 输出: {args.out}")

    for code in codes:
        for period in periods:
            if period not in PERIOD_MAP:
                print(f"  跳过未知周期 {period}")
                continue
            print(f"  拉取 {code} {period} ...", end="", flush=True)
            if period == "1min":
                rows = em_kline(code, 1, beg=args.start, end=args.end)
            else:
                rows = fetch_period(code, period)
                if not rows and period != "1min":
                    rows = em_kline(code, PERIOD_MAP[period][1], beg=args.start, end=args.end)
            if not rows:
                print(f" 无数据")
                continue
            is_min = period != "day"
            path = os.path.join(args.out, f"{code}_{period}.csv")
            n = write_csv(path, MIN_COLS if is_min else DAY_COLS, rows, is_min)
            print(f" OK {n} 条 -> {path}")
            time.sleep(SLEEP_PER_REQ)

    print("完成。把 output_csv 下的 CSV 用软件 '数据导入' 菜单导入即可。")


if __name__ == "__main__":
    main()
