# -*- coding: utf-8 -*-
import ctypes
import time
import win32api
import win32con
import win32gui
from PIL import ImageGrab

ctypes.windll.user32.SetProcessDPIAware()

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
time.sleep(0.2)

def click(x, y, wait=0.5):
    win32api.SetCursorPos((int(x), int(y)))
    time.sleep(0.08)
    win32api.mouse_event(2, 0, 0, 0, 0)
    time.sleep(0.04)
    win32api.mouse_event(4, 0, 0, 0, 0)
    time.sleep(wait)

click(860, 232, 0.6)
ImageGrab.grab().crop((600, 180, 1200, 640)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\user_try.png")
print("shot")
