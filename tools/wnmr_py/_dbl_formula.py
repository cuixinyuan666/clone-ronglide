# -*- coding: utf-8 -*-
import ctypes
import time
import win32api
import win32con
import win32gui
from PIL import ImageGrab

ctypes.windll.user32.SetProcessDPIAware()
u32 = ctypes.windll.user32

def click(x, y, n=1, wait=0.4):
    win32api.SetCursorPos((int(x), int(y)))
    time.sleep(0.08)
    for _ in range(n):
        win32api.mouse_event(2, 0, 0, 0, 0)
        time.sleep(0.04)
        win32api.mouse_event(4, 0, 0, 0, 0)
        time.sleep(0.08)
    time.sleep(wait)

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

blockers()
click(900, 375, n=2, wait=1.0)
ImageGrab.grab().save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\dbl.png")
print("shot")
