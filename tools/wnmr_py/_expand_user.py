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

def fg(h):
    f = u32.GetForegroundWindow()
    t1 = ctypes.windll.kernel32.GetCurrentThreadId()
    t2 = u32.GetWindowThreadProcessId(f, None)
    u32.AttachThreadInput(t1, t2, True)
    try:
        u32.SwitchToThisWindow(h, True)
    finally:
        u32.AttachThreadInput(t1, t2, False)

def click(x, y, n=1, wait=0.35):
    win32api.SetCursorPos((int(x), int(y)))
    time.sleep(0.05)
    for _ in range(n):
        win32api.mouse_event(2, 0, 0, 0, 0)
        time.sleep(0.04)
        win32api.mouse_event(4, 0, 0, 0, 0)
        time.sleep(0.08)
    time.sleep(wait)

blockers()
h = find_main()
fg(h)
click(544, 36, 1, 0.35)
click(680, 271, 1, 0.6)
click(930, 266, 1, 0.3)
click(760, 309, 2, 0.5)
ImageGrab.grab().crop((600, 180, 1200, 700)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\tree2.png")
print("shot")
