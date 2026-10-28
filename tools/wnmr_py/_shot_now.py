# -*- coding: utf-8 -*-
import ctypes
import time
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

blockers()
time.sleep(0.3)
h = find_main()
print("main", hex(h) if h else None)
if h:
    fg = u32.GetForegroundWindow()
    t1 = ctypes.windll.kernel32.GetCurrentThreadId()
    t2 = u32.GetWindowThreadProcessId(fg, None)
    u32.AttachThreadInput(t1, t2, True)
    try:
        win32gui.ShowWindow(h, win32con.SW_SHOWMAXIMIZED)
        u32.SwitchToThisWindow(h, True)
    finally:
        u32.AttachThreadInput(t1, t2, False)
    time.sleep(0.4)
    print("rect", win32gui.GetWindowRect(h))
im = ImageGrab.grab()
im.save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\now.png")
im.crop((60, 120, 1400, 260)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\now_head.png")
print("shot")
