# -*- coding: utf-8 -*-
import ctypes
import time
import win32api
import win32con
import win32gui
from PIL import ImageGrab

ctypes.windll.user32.SetProcessDPIAware()
u32 = ctypes.windll.user32

def find_main():
    res = []
    win32gui.EnumWindows(lambda h, _: res.append(h) if win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "CLASSNAME_RLD_CZSC_MAINAPP" else None, None)
    return res[0] if res else None

def foreground(h):
    for _ in range(6):
        if u32.GetForegroundWindow() == h:
            return True
        fg = u32.GetForegroundWindow()
        t1 = ctypes.windll.kernel32.GetCurrentThreadId()
        t2 = u32.GetWindowThreadProcessId(fg, None)
        u32.AttachThreadInput(t1, t2, True)
        try:
            win32gui.ShowWindow(h, win32con.SW_SHOWMAXIMIZED)
            try:
                win32gui.SetForegroundWindow(h)
            except Exception:
                pass
            u32.SwitchToThisWindow(h, True)
        finally:
            u32.AttachThreadInput(t1, t2, False)
        time.sleep(0.25)
    return True

def click(x, y, wait=0.4):
    win32api.SetCursorPos((int(x), int(y)))
    time.sleep(0.12)
    win32api.mouse_event(2, 0, 0, 0, 0)
    time.sleep(0.05)
    win32api.mouse_event(4, 0, 0, 0, 0)
    time.sleep(wait)

def minimize_blockers():
    def cb(hwnd, _):
        if not win32gui.IsWindowVisible(hwnd):
            return
        cls = win32gui.GetClassName(hwnd)
        if cls in ("CLASSNAME_RLD_CZSC_MAINAPP", "Progman", "Shell_TrayWnd", "WorkerW"):
            return
        if win32gui.GetParent(hwnd):
            return
        r = win32gui.GetWindowRect(hwnd)
        if r[2] - r[0] > 500 and r[3] - r[1] > 300 and r[0] > -200 and r[0] < 500:
            print("min", cls, repr(win32gui.GetWindowText(hwnd))[:40], flush=True)
            win32gui.ShowWindow(hwnd, win32con.SW_MINIMIZE)
    win32gui.EnumWindows(cb, None)

h = find_main()
minimize_blockers()
time.sleep(0.3)
foreground(h)
click(544, 36, 0.45)
click(680, 271, 1.2)

def dump():
    def cb(hwnd, _):
        if not win32gui.IsWindowVisible(hwnd):
            return
        t = win32gui.GetWindowText(hwnd)
        c = win32gui.GetClassName(hwnd)
        if t or c.startswith("#32770") or c.startswith("#32768"):
            print(hex(hwnd), c, repr(t)[:40], win32gui.GetWindowRect(hwnd))
    win32gui.EnumWindows(cb, None)

dump()
ImageGrab.grab().save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\fm.png")
print("shot")
