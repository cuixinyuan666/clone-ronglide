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
    time.sleep(0.07)
    win32api.mouse_event(2, 0, 0, 0, 0)
    time.sleep(0.04)
    win32api.mouse_event(4, 0, 0, 0, 0)
    time.sleep(wait)

def get_text(h):
    n = u32.SendMessageW(h, 0x0E, 0, 0)
    buf = ctypes.create_unicode_buffer(max(n + 1, 1))
    u32.SendMessageW(h, 0x0D, n + 1, buf)
    return buf.value

click(800, 343, 0.25)
click(1447, 305, 0.8)

editor = None
def cb(h, _):
    global editor
    if win32gui.IsWindowVisible(h) and win32gui.GetWindowText(h) == "指标公式编辑器":
        editor = h
win32gui.EnumWindows(cb, None)
print("editor", hex(editor) if editor else None)
if not editor:
    msgs = []
    def cb2(h, _):
        if win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "#32770":
            msgs.append(win32gui.GetWindowText(h))
    win32gui.EnumWindows(cb2, None)
    open(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\newfail.txt", "w", encoding="utf-8").write("\n".join(msgs))
    raise SystemExit(2)

name = code = out = comp = ok = None
edits = []
riches = []
def ch(c, _):
    cls = win32gui.GetClassName(c)
    t = win32gui.GetWindowText(c)
    if cls == "Edit":
        edits.append(c)
    if cls == "RichEdit20A":
        riches.append(c)
    global comp, ok
    if cls == "Button" and t == "编译":
        comp = c
    if cls == "Button" and t == "确定":
        ok = c
win32gui.EnumChildWindows(editor, ch, None)
edits.sort(key=lambda h: win32gui.GetWindowRect(h)[1])
riches.sort(key=lambda h: win32gui.GetWindowRect(h)[1])
name = edits[0]
code = riches[0]
out = riches[1] if len(riches) > 1 else None
print("name", hex(name), "code", hex(code), "comp", hex(comp) if comp else None)

SRC = (
    "DRAWTEXT(DATE=20170810 AND HOUR=13 AND MINUTE=6,H,'买入价 12.72'),COLORCYAN;\r\n"
    "DRAWTEXT(DATE=20170810 AND HOUR=13 AND MINUTE=1,L,'止损价 12.70'),COLORRED;\r\n"
    "DRAWTEXT(DATE=20170810 AND HOUR=9 AND MINUTE=31,H,'状态1 12.72'),COLORYELLOW;\r\n"
    "WNMRSHOW:C;"
)
u32.SendMessageW(name, win32con.WM_SETTEXT, 0, "WNMRSHOW")
u32.SendMessageW(code, win32con.WM_SETTEXT, 0, SRC)
time.sleep(0.3)
u32.SendMessageW(comp, win32con.BM_CLICK, 0, 0)
time.sleep(1.0)
msg = get_text(out) if out else ""
open(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\compile3.txt", "w", encoding="utf-8").write(msg)
print("COMPILE", msg[:300])
if "成功" in msg and ok:
    u32.SendMessageW(ok, win32con.BM_CLICK, 0, 0)
    time.sleep(0.6)
    print("saved", win32gui.IsWindow(editor))
