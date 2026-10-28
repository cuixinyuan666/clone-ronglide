# -*- coding: utf-8 -*-
import ctypes
import time
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
time.sleep(0.3)
# focus formula manager if present
def cb(h, _):
    if win32gui.IsWindowVisible(h) and win32gui.GetWindowText(h) == "公式管理器":
        win32gui.SetForegroundWindow(h)
        print("fm", hex(h), win32gui.GetWindowRect(h))
win32gui.EnumWindows(cb, None)
time.sleep(0.3)
ImageGrab.grab().save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\after_save.png")
print("shot")
