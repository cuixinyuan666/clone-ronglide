# -*- coding: utf-8 -*-
import ctypes
import time
import win32api
import win32con
import win32gui

ctypes.windll.user32.SetProcessDPIAware()
u32 = ctypes.windll.user32

def click(x, y, wait=0.4):
    win32api.SetCursorPos((int(x), int(y)))
    time.sleep(0.06)
    win32api.mouse_event(2, 0, 0, 0, 0)
    time.sleep(0.03)
    win32api.mouse_event(4, 0, 0, 0, 0)
    time.sleep(wait)

def get_text(h):
    n = u32.SendMessageW(h, 0x0E, 0, 0)
    buf = ctypes.create_unicode_buffer(max(n + 1, 2))
    u32.SendMessageW(h, 0x0D, n + 1, buf)
    return buf.value

click(930, 266, 0.4)   # 用户
click(648, 311, 0.3)   # expand 技术指标
click(820, 375, 0.3)   # 缠论 or nearby row
click(1447, 305, 0.8)  # 新建

editor = None
def cb(h, _):
    global editor
    if win32gui.IsWindowVisible(h) and win32gui.GetWindowText(h) == "指标公式编辑器":
        editor = h
win32gui.EnumWindows(cb, None)
print("editor", hex(editor) if editor else None)
if not editor:
    raise SystemExit(2)

# find code richedit and compile/output by walking
code = out = comp = name = ok = None
def ch(c, _):
    global code, out, comp, name, ok
    cls = win32gui.GetClassName(c)
    t = win32gui.GetWindowText(c)
    r = win32gui.GetWindowRect(c)
    if cls == "RichEdit20A":
        # the larger one higher on screen is the code, lower is output
        if code is None or r[1] < win32gui.GetWindowRect(code)[1]:
            if code is not None and (out is None or r[1] < win32gui.GetWindowRect(out)[1]):
                out = code
            code = c
        else:
            out = c
    if cls == "Edit" and name is None and r[1] < 300:
        name = c
    if cls == "Button" and t == "编译":
        comp = c
    if cls == "Button" and t == "确定":
        ok = c
win32gui.EnumChildWindows(editor, ch, None)
print("name", hex(name) if name else None, "code", hex(code) if code else None, "out", hex(out) if out else None, "comp", hex(comp) if comp else None)

SRC = (
    "DRAWTEXT(CURRBARSCOUNT=23155,H,'买入价 12.72'),COLORCYAN;\r\n"
    "DRAWTEXT(CURRBARSCOUNT=23160,L,'止损价 12.70'),COLORRED;\r\n"
    "DRAWTEXT(CURRBARSCOUNT=23280,H,'状态1 12.72'),COLORYELLOW;\r\n"
    "WNMRSHOW:C;"
)
u32.SendMessageW(name, win32con.WM_SETTEXT, 0, "WNMRSHOW")
u32.SendMessageW(code, win32con.WM_SETTEXT, 0, SRC)
time.sleep(0.3)
u32.SendMessageW(comp, win32con.BM_CLICK, 0, 0)
time.sleep(1.0)
msg = get_text(out) if out else ""
open(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\compile2.txt", "w", encoding="utf-8").write(msg)
print("compile", msg[:200])
if "成功" in msg:
    u32.SendMessageW(ok, win32con.BM_CLICK, 0, 0)
    print("saved")
