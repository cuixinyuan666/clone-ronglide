# -*- coding: utf-8 -*-
import ctypes
import time
import win32api
import win32con
import win32gui
from PIL import ImageGrab

ctypes.windll.user32.SetProcessDPIAware()
u32 = ctypes.windll.user32

def blockers():
    def cb(hwnd, _):
        if not win32gui.IsWindowVisible(hwnd):
            return
        cls = win32gui.GetClassName(hwnd)
        if cls in ("CLASSNAME_RLD_CZSC_MAINAPP", "Progman", "Shell_TrayWnd", "WorkerW", "#32770"):
            return
        if win32gui.GetParent(hwnd):
            return
        r = win32gui.GetWindowRect(hwnd)
        if r[2] - r[0] > 500 and r[3] - r[1] > 300 and -200 < r[0] < 500:
            win32gui.ShowWindow(hwnd, win32con.SW_MINIMIZE)
    win32gui.EnumWindows(cb, None)

def find_main():
    res = []
    win32gui.EnumWindows(lambda h, _: res.append(h) if win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "CLASSNAME_RLD_CZSC_MAINAPP" else None, None)
    return res[0] if res else None

def foreground(h):
    fg = u32.GetForegroundWindow()
    t1 = ctypes.windll.kernel32.GetCurrentThreadId()
    t2 = u32.GetWindowThreadProcessId(fg, None)
    u32.AttachThreadInput(t1, t2, True)
    try:
        u32.SwitchToThisWindow(h, True)
    finally:
        u32.AttachThreadInput(t1, t2, False)

def click(x, y, wait=0.45):
    win32api.SetCursorPos((int(x), int(y)))
    time.sleep(0.06)
    win32api.mouse_event(2, 0, 0, 0, 0)
    time.sleep(0.03)
    win32api.mouse_event(4, 0, 0, 0, 0)
    time.sleep(wait)

blockers()
h = find_main()
foreground(h)
click(544, 36, 0.4)
click(680, 271, 0.8)
click(1447, 471, 0.6)  # 查找
# find dialog edit
edit = None
ok = None
def cb(hwnd, _):
    global edit, ok
    if win32gui.IsWindowVisible(hwnd) and win32gui.GetClassName(hwnd) == "#32770" and hwnd != 0:
        t = win32gui.GetWindowText(hwnd)
        if "查找" in t or t == "":
            pass
win32gui.EnumWindows(lambda hwnd, _: None, None)
# pick newest small dialog's edit
found = []
def cb2(hwnd, _):
    if win32gui.IsWindowVisible(hwnd) and win32gui.GetClassName(hwnd) == "#32770":
        r = win32gui.GetWindowRect(hwnd)
        if 200 < (r[2]-r[0]) < 800 and "公式管理器" not in win32gui.GetWindowText(hwnd) and "指标" not in win32gui.GetWindowText(hwnd):
            found.append(hwnd)
win32gui.EnumWindows(cb2, None)
print("small", [hex(x) for x in found], [win32gui.GetWindowText(x) for x in found])
if not found:
    ImageGrab.grab().save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\findmiss.png")
    raise SystemExit(1)
dlg = found[-1]
eds, oks = [], []
def ch(c, _):
    cls = win32gui.GetClassName(c)
    if cls == "Edit":
        eds.append(c)
    if cls == "Button" and win32gui.GetWindowText(c) in ("确定", "确认"):
        oks.append(c)
win32gui.EnumChildWindows(dlg, ch, None)
print("edits", [hex(e) for e in eds], "ok", [hex(o) for o in oks])
u32.SendMessageW(eds[0], win32con.WM_SETTEXT, 0, "WNMRSHOW")
time.sleep(0.2)
u32.SendMessageW(oks[0], win32con.BM_CLICK, 0, 0)
time.sleep(0.5)
click(1447, 359, 0.8)  # 修改
ImageGrab.grab().save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\mod.png")
print("mod shot")
