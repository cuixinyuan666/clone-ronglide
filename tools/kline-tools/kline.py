#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自建 K 线看板 (融立德替代方案 · 路线C)
=====================================
用免费行情源(新浪/Eastmoney)拉数据, 在本地用纯 Canvas 渲染 K 线图.
不依赖任何前端库, 不依赖已停服的融立德服务器.

两种用法
--------
1) 本地服务(推荐, 可交互换股):
     python kline.py --serve            # 启动后浏览器打开 http://127.0.0.1:8765
     python kline.py --serve --port 9000

2) 导出单文件 HTML(可双击打开, 数据内嵌, 离线可用):
     python kline.py 600000 -o kline_600000.html
     python kline.py 000001 --mkt sh --period 5min -o kline_000001_5min.html
     python kline.py 600000 --open      # 生成后自动用浏览器打开

参数
----
  code            股票/指数代码, 如 600000(浦发) 000001(平安银行) 399001(深证成指)
  --mkt           auto|sh|sz  (默认 auto: 6/9开头=sh, 其余=sz; 指数请显式指定)
  --period        day|60min|30min|15min|5min|1min  (默认 day)
  --proxy         出口代理, 默认 http://127.0.0.1:19828, 传 "" 表示不用代理

数据源
------
  日线/5-60分钟 : 新浪 getKLineData (实时, 免token)
  1分钟         : Eastmoney (新浪不提供1分钟历史), 带节流重试
"""

import os
import sys
import json
import time
import argparse
import threading
import webbrowser
import urllib.request
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ----------------------------- 配置 -----------------------------
DEFAULT_PROXY = "http://127.0.0.1:19828"
USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")
SLEEP_PER_REQ = 0.4
MAX_RETRY = 3
DEFAULT_PORT = 8765

PERIODS = {
    "day":   {"label": "日线",  "sina": 240, "em": 101},
    "60min": {"label": "60分",  "sina": 60,  "em": 60},
    "30min": {"label": "30分",  "sina": 30,  "em": 30},
    "15min": {"label": "15分",  "sina": 15,  "em": 15},
    "5min":  {"label": "5分",   "sina": 5,   "em": 5},
    "1min":  {"label": "1分",   "sina": None, "em": 1},
}

PROXY = DEFAULT_PROXY


def make_opener():
    if PROXY:
        return urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": PROXY, "https": PROXY}))
    return urllib.request.build_opener()


OPENER = make_opener()


def http_get(url, referer=None):
    headers = {"User-Agent": USER_AGENT}
    if referer:
        headers["Referer"] = referer
    req = urllib.request.Request(url, headers=headers)
    with OPENER.open(req, timeout=30) as resp:
        return resp.read()


def http_get_json(url):
    last = None
    for attempt in range(1, MAX_RETRY + 1):
        try:
            raw = http_get(url).decode("utf-8", "ignore")
            if not raw or raw.strip() in ("", "null", "{}", "()"):
                time.sleep(SLEEP_PER_REQ * attempt)
                continue
            return json.loads(raw)
        except Exception as e:  # noqa
            last = e
            time.sleep(SLEEP_PER_REQ * attempt)
    print(f"  [warn] 请求失败: {url[:70]}... {last}", file=sys.stderr)
    return None


def resolve_market(code, mkt="auto"):
    if mkt in ("sh", "sz"):
        return mkt
    return "sh" if code[0] in ("6", "9", "5") else "sz"


# ----------------------------- 数据源 -----------------------------
def sina_kline(code, scale):
    sym = resolve_market(code) + code
    url = ("https://money.finance.sina.com.cn/quotes_service/api/json_v2.php/"
           f"CN_MarketData.getKLineData?symbol={sym}&scale={scale}&ma=no&datalen=8000")
    data = http_get_json(url)
    if not data:
        return []
    out = []
    for row in data:
        day = row.get("day", "")
        date, t = (day.split(" ", 1) + ["00:00:00"])[:2] if " " in day else (day, "00:00:00")
        out.append([date, t, row.get("open", ""), row.get("high", ""),
                    row.get("low", ""), row.get("close", ""), row.get("volume", ""), ""])
    return out


def em_kline(code, klt, mkt="auto"):
    m = "1" if resolve_market(code, mkt) == "sh" else "0"
    url = ("https://push2his.eastmoney.com/api/qt/stock/kline/get?"
           f"secid={m}.{code}&fields1=f1&fields2=f51,f52,f53,f54,f55,f56,f57"
           f"&klt={klt}&fqt=1&beg=19900101&end=20500101")
    data = http_get_json(url)
    try:
        klines = data["data"]["klines"]
    except Exception:  # noqa
        return []
    out = []
    for kl in klines:
        p = kl.split(",")
        if " " in p[0]:
            date, t = p[0].split(" ", 1)
        else:
            date, t = p[0], "00:00:00"
        o, c, h, l, v = p[1], p[2], p[3], p[4], p[5]
        amt = p[6] if len(p) > 6 else ""
        out.append([date, t, o, h, l, c, v, amt])
    return out


def fetch_name(code, mkt="auto"):
    """尽力获取股票名称(失败则返回空)"""
    try:
        sym = resolve_market(code, mkt) + code
        raw = http_get(f"https://hq.sinajs.cn/list={sym}",
                       referer="https://finance.sina.com.cn").decode("gbk", "ignore")
        if '="' in raw:
            body = raw.split('="', 1)[1].rstrip('";\n')
            name = body.split(",")[0]
            if name and not name.startswith("var"):
                return name
    except Exception:  # noqa
        pass
    return ""


def fetch(code, period, mkt="auto"):
    cfg = PERIODS.get(period)
    if not cfg:
        raise ValueError(f"未知周期 {period}")
    rows = []
    if cfg["sina"]:
        rows = sina_kline(code, cfg["sina"])
    if not rows:  # 新浪失败 / 1分钟 -> Eastmoney
        rows = em_kline(code, cfg["em"], mkt)
    return rows


# ----------------------------- 前端(内嵌) -----------------------------
HTML_PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>K线看板</title>
<style>
  * { box-sizing: border-box; }
  html, body { margin:0; padding:0; height:100%; background:#12141a; color:#c8ccd6;
    font-family:"Microsoft YaHei",Consolas,monospace; overflow:hidden; }
  #bar { height:46px; display:flex; align-items:center; gap:8px; padding:0 12px;
    background:#1a1d25; border-bottom:1px solid #2a2e39; }
  #bar input { width:110px; height:28px; background:#0e1015; color:#e6e9f0;
    border:1px solid #333a47; border-radius:4px; padding:0 8px; font-size:14px; }
  #bar .tabs { display:flex; gap:2px; margin-left:6px; }
  #bar .tabs button { height:28px; padding:0 10px; background:#0e1015; color:#9aa3b2;
    border:1px solid #333a47; border-radius:4px; cursor:pointer; font-size:13px; }
  #bar .tabs button.on { background:#2b5cff; color:#fff; border-color:#2b5cff; }
  #bar .go { height:28px; padding:0 14px; background:#2b5cff; color:#fff; border:0;
    border-radius:4px; cursor:pointer; font-size:13px; }
  #bar .mkt { height:28px; background:#0e1015; color:#9aa3b2; border:1px solid #333a47;
    border-radius:4px; font-size:13px; }
  #title { margin-left:10px; font-size:14px; color:#e6e9f0; }
  #title b { color:#ffb020; }
  #status { margin-left:auto; font-size:12px; color:#6b7484; }
  #wrap { position:relative; width:100%; height:calc(100% - 46px); }
  canvas { display:block; width:100%; height:100%; cursor:crosshair; }
  #tip { position:absolute; left:0; top:0; pointer-events:none; display:none;
    background:rgba(20,23,30,.94); border:1px solid #3a4252; border-radius:5px;
    padding:7px 10px; font-size:12px; line-height:1.65; white-space:nowrap; z-index:9; }
  #tip .k { color:#8b93a3; }
  .up { color:#ff4d4f; } .dn { color:#3dd68c; }
</style>
</head>
<body>
<div id="bar">
  <input id="code" value="__CODE__" placeholder="代码">
  <select id="mkt" class="mkt">
    <option value="auto">自动</option><option value="sh">沪</option><option value="sz">深</option>
  </select>
  <div class="tabs" id="tabs"></div>
  <button class="go" id="load">加载</button>
  <div id="title"></div>
  <div id="status"></div>
</div>
<div id="wrap">
  <canvas id="cv"></canvas>
  <div id="tip"></div>
</div>
<script>
var PERIODS = __PERIODS__;
var PRESET  = /*__DATA__*/ null;
var bars = [], meta = {code:"", period:"day", name:""};
var view = {start:0, end:0};
var drag = null;

function pad(n){ return n<10?"0"+n:""+n; }

function fmtBar(b, i){
  return {date:b[0], time:b[1], o:+b[2], h:+b[3], l:+b[4], c:+b[5], v:+b[6]||0};
}

function setData(rows, m){
  meta = m || meta;
  bars = rows.map(fmtBar);
  var n = bars.length;
  var show = Math.min(n, 240);
  view.start = n - show; view.end = n;
  document.getElementById('title').innerHTML =
    '<b>' + (meta.name ? meta.name + " " : "") + (meta.code||"") + '</b> · ' +
    (PERIODS[meta.period] || meta.period) + ' · ' + n + ' 根';
  render();
}

function calcMA(n){
  var out = new Array(bars.length).fill(null), s = 0;
  for (var i=0;i<bars.length;i++){
    s += bars[i].c;
    if (i>=n) s -= bars[i-n].c;
    if (i>=n-1) out[i] = s/n;
  }
  return out;
}

function calcMACD(){
  var ema = function(n){ var k=2/(n+1), e=bars[0]?bars[0].c:0, o=[];
    for(var i=0;i<bars.length;i++){ e = bars[i].c*k + e*(1-k); o.push(e); } return o; };
  var e12=ema(12), e26=ema(26), dif=[], dea=[], macd=[];
  for(var i=0;i<bars.length;i++) dif.push(e12[i]-e26[i]);
  var k=2/(9+1), d=0;
  for(var i=0;i<dif.length;i++){ d = dif[i]*k + d*(1-k); dea.push(d); macd.push((dif[i]-d)*2); }
  return {dif:dif, dea:dea, macd:macd};
}

var CV = document.getElementById('cv'), CTX = CV.getContext('2d');
var W=0, H=0, DPR = window.devicePixelRatio || 1;

function resize(){
  var r = CV.parentNode.getBoundingClientRect();
  W = r.width; H = r.height;
  CV.width = W*DPR; CV.height = H*DPR;
  CTX.setTransform(DPR,0,0,DPR,0,0);
  render();
}
window.addEventListener('resize', resize);

function render(){
  CTX.clearRect(0,0,W,H);
  if (!bars.length){ CTX.fillStyle="#5b6373"; CTX.font="14px sans-serif";
    CTX.fillText("无数据", W/2-24, H/2); return; }

  var s = Math.max(0, Math.floor(view.start)), e = Math.min(bars.length, Math.ceil(view.end));
  if (e - s < 5) return;
  var seg = bars.slice(s, e), n = seg.length;

  var padL=10, padR=64, padT=22;
  var hC = (H-padT)*0.60, hV = (H-padT)*0.16, hM = (H-padT)*0.24;
  var yC = padT, yV = padT+hC+6, yM = yV+hV+6;

  var lo = Infinity, hi = -Infinity, vmax = 0;
  for (var i=0;i<n;i++){ lo=Math.min(lo,seg[i].l); hi=Math.max(hi,seg[i].h); vmax=Math.max(vmax,seg[i].v); }
  if (!isFinite(lo)) { lo=0; hi=1; }
  var rg = (hi-lo)||1; lo-=rg*0.05; hi+=rg*0.05;

  var plotW = W-padL-padR;
  var bw = plotW/n;
  var cw = Math.max(1, Math.min(bw*0.72, 26));

  var x = function(i){ return padL + i*bw + bw/2; };
  var yP = function(p){ return yC + (hi-p)/(hi-lo)*hC; };

  // ---- 网格与价格轴 ----
  CTX.strokeStyle="#232833"; CTX.lineWidth=1; CTX.font="11px Consolas"; CTX.fillStyle="#6b7484";
  for (var g=0; g<=4; g++){
    var yy = yC + hC*g/4;
    CTX.beginPath(); CTX.moveTo(padL,yy); CTX.lineTo(W-padR,yy); CTX.stroke();
    var pv = hi - (hi-lo)*g/4;
    CTX.fillText(pv.toFixed(2), W-padR+6, yy+4);
  }
  // ---- 均线 ----
  var mas = [[5,"#f6c343"],[10,"#4dabf7"],[20,"#d17ce4"],[60,"#3dd68c"]];
  var full = {}; mas.forEach(function(m){ full[m[0]] = calcMA(m[0]); });
  mas.forEach(function(m){
    var arr = full[m[0]]; CTX.strokeStyle=m[1]; CTX.lineWidth=1; CTX.beginPath();
    var started=false;
    for (var i=0;i<n;i++){ var v=arr[s+i]; if(v==null) continue;
      var px=x(i), py=yP(v); started?CTX.lineTo(px,py):(CTX.moveTo(px,py),started=true); }
    CTX.stroke();
  });
  // ---- K 线 ----
  for (var i=0;i<n;i++){
    var b=seg[i], up=b.c>=b.o, col = up ? "#ff4d4f" : "#3dd68c";
    CTX.strokeStyle=col; CTX.fillStyle=col; CTX.lineWidth=1;
    var px=x(i);
    CTX.beginPath(); CTX.moveTo(px, yP(b.h)); CTX.lineTo(px, yP(b.l)); CTX.stroke();
    var yo=yP(b.o), yc=yP(b.c), top=Math.min(yo,yc), hgt=Math.max(1,Math.abs(yc-yo));
    if (up) { CTX.fillRect(px-cw/2, top, cw, hgt); }
    else {
      CTX.fillStyle="#12141a"; CTX.fillRect(px-cw/2, top, cw, hgt);
      CTX.strokeRect(px-cw/2+0.5, top+0.5, cw-1, hgt-1);
    }
  }
  // ---- 成交量 ----
  CTX.strokeStyle="#232833"; CTX.beginPath();
  CTX.moveTo(padL,yV+hV); CTX.lineTo(W-padR,yV+hV); CTX.stroke();
  for (var i=0;i<n;i++){
    var b=seg[i], up=b.c>=b.o;
    CTX.fillStyle = up ? "rgba(255,77,79,.85)" : "rgba(61,214,140,.85)";
    var hh = vmax ? (b.v/vmax)*(hV-6) : 0;
    CTX.fillRect(x(i)-cw/2, yV+hV-hh, cw, Math.max(1,hh));
  }
  CTX.fillStyle="#6b7484"; CTX.font="11px Consolas";
  CTX.fillText("VOL", padL+2, yV+12);

  // ---- MACD ----
  var md = calcMACD();
  var mmax = 0; for (var i=s;i<e;i++){ mmax=Math.max(mmax, Math.abs(md.dif[i]), Math.abs(md.dea[i]), Math.abs(md.macd[i])); }
  mmax = mmax||1;
  var ym = function(v){ return yM + hM/2 - v/mmax*(hM/2-4); };
  CTX.strokeStyle="#232833"; CTX.beginPath();
  CTX.moveTo(padL, yM+hM/2); CTX.lineTo(W-padR, yM+hM/2); CTX.stroke();
  for (var i=0;i<n;i++){
    var v = md.macd[s+i];
    CTX.fillStyle = v>=0 ? "rgba(255,77,79,.9)" : "rgba(61,214,140,.9)";
    var y0 = ym(0), y1 = ym(v);
    CTX.fillRect(x(i)-cw/2, Math.min(y0,y1), cw, Math.max(1,Math.abs(y1-y0)));
  }
  [[md.dif,"#f6c343"],[md.dea,"#4dabf7"]].forEach(function(pair){
    CTX.strokeStyle=pair[1]; CTX.lineWidth=1; CTX.beginPath();
    for (var i=0;i<n;i++){ var px=x(i), py=ym(pair[0][s+i]); i?CTX.lineTo(px,py):CTX.moveTo(px,py); }
    CTX.stroke();
  });
  CTX.fillStyle="#6b7484"; CTX.fillText("MACD(12,26,9)", padL+2, yM+12);

  // ---- 时间轴 ----
  CTX.fillStyle="#6b7484";
  var step = Math.max(1, Math.floor(n/8));
  for (var i=0;i<n;i+=step){
    var lbl = seg[i].date;
    CTX.fillText(lbl.slice(5), x(i)-16, H-6);
  }
  CV._geo = {padL:padL, padR:padR, n:n, bw:bw, s:s, e:e, seg:seg, yP:yP, hi:hi, lo:lo,
             yC:yC, hC:hC, ym:ym, md:md};
}

// ---- 交互 ----
CV.addEventListener('wheel', function(ev){
  ev.preventDefault();
  if (!bars.length) return;
  var g = CV._geo; if(!g) return;
  var rect = CV.getBoundingClientRect();
  var mx = ev.clientX-rect.left;
  var anchor = g.s + Math.floor((mx-g.padL)/g.bw);
  var span = view.end - view.start;
  var k = ev.deltaY > 0 ? 1.15 : 0.87;
  var nspan = Math.max(20, Math.min(bars.length, span*k));
  var ratio = span>0 ? (anchor-view.start)/span : 0.5;
  view.start = anchor - nspan*ratio;
  view.end   = view.start + nspan;
  clampView(); render();
}, {passive:false});

CV.addEventListener('mousedown', function(ev){
  drag = {x:ev.clientX, start:view.start, end:view.end};
});
window.addEventListener('mousemove', function(ev){
  if (drag){
    var g = CV._geo; if(!g) return;
    var d = (ev.clientX-drag.x)/g.bw;
    view.start = drag.start - d; view.end = drag.end - d;
    clampView(); render();
    return;
  }
  var tip = document.getElementById('tip'), g = CV._geo;
  if (!g || !bars.length) return;
  var rect = CV.getBoundingClientRect();
  var mx = ev.clientX-rect.left, my = ev.clientY-rect.top;
  if (mx < g.padL || mx > W-g.padR || my > yVH()){ tip.style.display="none"; render(); return; }
  var i = Math.floor((mx-g.padL)/g.bw);
  if (i<0 || i>=g.n) { tip.style.display="none"; return; }
  render();
  var b = g.seg[i], px = g.padL + i*g.bw + g.bw/2;
  var prev = (g.s+i-1>=0) ? bars[g.s+i-1].c : b.o;
  var chg = prev ? (b.c-prev)/prev*100 : 0;
  var cls = chg>=0 ? "up" : "dn";
  tip.innerHTML =
    '<span class="k">日期</span> ' + b.date + ' ' + (b.time!=="00:00:00"?b.time:"") + '<br>' +
    '<span class="k">开</span> ' + b.o.toFixed(2) + '  <span class="k">高</span> ' + b.h.toFixed(2) + '<br>' +
    '<span class="k">低</span> ' + b.l.toFixed(2) + '  <span class="k">收</span> ' + b.c.toFixed(2) + '<br>' +
    '<span class="k">涨跌</span> <span class="'+cls+'">' + (chg>=0?"+":"") + chg.toFixed(2) + '%</span><br>' +
    '<span class="k">量</span> ' + fmtVol(b.v) + '<br>' +
    '<span class="k">DIF</span> ' + (g.md.dif[g.s+i]||0).toFixed(3) + '  <span class="k">DEA</span> ' + (g.md.dea[g.s+i]||0).toFixed(3);
  tip.style.display = "block";
  var tw = tip.offsetWidth, th = tip.offsetHeight;
  tip.style.left = Math.min(W-tw-8, Math.max(4, px+14)) + "px";
  tip.style.top  = Math.min(H-th-8, Math.max(4, my+14)) + "px";
  // 十字线
  CTX.save(); CTX.strokeStyle="#8b93a3"; CTX.setLineDash([4,3]); CTX.lineWidth=1;
  CTX.beginPath(); CTX.moveTo(px,0); CTX.lineTo(px,H-18); CTX.stroke();
  CTX.beginPath(); CTX.moveTo(g.padL,my); CTX.lineTo(W-g.padR,my); CTX.stroke();
  CTX.restore();
});
window.addEventListener('mouseup', function(){ drag=null; });
CV.addEventListener('mouseleave', function(){ document.getElementById('tip').style.display='none'; });

function yVH(){ var g = CV._geo; return g ? (H - 18) : H; }
function fmtVol(v){
  if (v >= 1e8) return (v/1e8).toFixed(2)+"亿";
  if (v >= 1e4) return (v/1e4).toFixed(2)+"万";
  return v.toFixed(0);
}
function clampView(){
  var n = bars.length;
  var span = Math.min(Math.max(20, view.end-view.start), n);
  if (view.start < 0){ view.start = 0; }
  if (view.start + span > n){ view.start = n - span; }
  if (view.start < 0) view.start = 0;
  view.end = view.start + span;
}

// ---- 周期按钮 ----
var STATIC_MODE = !!PRESET;
(function(){
  var box = document.getElementById('tabs');
  Object.keys(PERIODS).forEach(function(k){
    var b = document.createElement('button');
    b.textContent = PERIODS[k]; b.dataset.p = k;
    b.onclick = function(){
      if (STATIC_MODE){
        document.getElementById('status').textContent =
          "静态文件仅含当前周期 · 用 --serve 启动服务即可随意切换";
        return;
      }
      load(k);
    };
    box.appendChild(b);
  });
})();

function markTabs(p){
  [].forEach.call(document.querySelectorAll('#tabs button'), function(b){
    b.className = (b.dataset.p===p) ? "on" : "";
  });
}

function load(period){
  var code = document.getElementById('code').value.trim();
  var mkt  = document.getElementById('mkt').value;
  if (!code) return;
  period = period || meta.period || "day";
  document.getElementById('status').textContent = "加载中...";
  var url = "/api/kline?code=" + encodeURIComponent(code) + "&period=" + period + "&mkt=" + mkt;
  fetch(url).then(function(r){ return r.json(); }).then(function(j){
    if (j.error){ document.getElementById('status').textContent = "错误: " + j.error; return; }
    document.getElementById('status').textContent =
      "更新 " + new Date().toLocaleTimeString() + (j.rows.length ? "" : " (无数据)");
    markTabs(period);
    setData(j.rows, {code:j.code, period:period, name:j.name||""});
  }).catch(function(e){ document.getElementById('status').textContent = "失败: " + e; });
}

document.getElementById('load').onclick = function(){
  if (STATIC_MODE){
    document.getElementById('status').textContent =
      "静态文件 · 用 --serve 启动服务即可换股/换周期";
    return;
  }
  load(meta.period);
};
document.getElementById('code').addEventListener('keydown', function(e){ if(e.key==="Enter") load(meta.period); });

// 启动
(function(){
  markTabs(meta.period);
  if (PRESET){ setData(PRESET.rows, PRESET); }
  else { load("day"); }
  resize();
})();
</script>
</body>
</html>
"""


def build_page(code, period, mkt, rows, name):
    payload = {"code": code, "period": period, "mkt": mkt, "name": name, "rows": rows}
    page = HTML_PAGE.replace("__PERIODS__", json.dumps(
        {k: v["label"] for k, v in PERIODS.items()}, ensure_ascii=False))
    page = page.replace("/*__DATA__*/ null", json.dumps(payload, ensure_ascii=False))
    page = page.replace("__CODE__", code)
    return page


def build_live_page(code):
    page = HTML_PAGE.replace("__PERIODS__", json.dumps(
        {k: v["label"] for k, v in PERIODS.items()}, ensure_ascii=False))
    page = page.replace("__CODE__", code)
    return page


# ----------------------------- 服务模式 -----------------------------
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # 静音
        pass

    def _send(self, body, ctype="text/html; charset=utf-8", code=200):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/api/kline":
            q = urllib.parse.parse_qs(u.query)
            code = (q.get("code", [""])[0] or "").strip()
            period = q.get("period", ["day"])[0]
            mkt = q.get("mkt", ["auto"])[0]
            try:
                rows = fetch(code, period, mkt)
                name = fetch_name(code, mkt)
                self._send(json.dumps({"code": code, "period": period,
                                       "name": name, "rows": rows},
                                      ensure_ascii=False),
                           "application/json; charset=utf-8")
            except Exception as e:  # noqa
                self._send(json.dumps({"error": str(e)}, ensure_ascii=False),
                           "application/json; charset=utf-8")
        elif u.path in ("/", "/index.html"):
            self._send(build_live_page("600000"))
        else:
            self._send("not found", "text/plain", 404)


def serve(port, open_browser=True):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}/"
    print(f"K线看板已启动: {url}")
    print("按 Ctrl+C 停止")
    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")


# ----------------------------- 主流程 -----------------------------
def main():
    global PROXY
    ap = argparse.ArgumentParser(description="自建K线看板(融立德替代)")
    ap.add_argument("code", nargs="?", default="600000", help="股票代码")
    ap.add_argument("--mkt", default="auto", choices=["auto", "sh", "sz"])
    ap.add_argument("--period", default="day", choices=list(PERIODS.keys()))
    ap.add_argument("-o", "--out", help="输出 HTML 路径(单文件, 离线可用)")
    ap.add_argument("--open", action="store_true", help="生成后用浏览器打开")
    ap.add_argument("--serve", action="store_true", help="启动本地服务(可交互换股)")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--proxy", default=DEFAULT_PROXY, help='出口代理, 传 "" 表示不用')
    args = ap.parse_args()

    PROXY = args.proxy
    global OPENER
    OPENER = make_opener()

    if args.serve:
        serve(args.port)
        return

    print(f"拉取 {args.code} {args.period} ...")
    rows = fetch(args.code, args.period, args.mkt)
    if not rows:
        print("未取到数据(检查代码/网络/代理)")
        sys.exit(2)
    name = fetch_name(args.code, args.mkt)
    print(f"OK {len(rows)} 根  {rows[0][0]} ~ {rows[-1][0]}  {name}")

    out = args.out or f"kline_{args.code}_{args.period}.html"
    with open(out, "w", encoding="utf-8") as f:
        f.write(build_page(args.code, args.period, args.mkt, rows, name))
    print(f"已生成: {os.path.abspath(out)}")
    if args.open:
        webbrowser.open("file:///" + os.path.abspath(out).replace("\\", "/"))


if __name__ == "__main__":
    main()
