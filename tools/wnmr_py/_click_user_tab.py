# -*- coding: utf-8 -*-
import ctypes
import time
import win32api
import win32con
import win32gui
from PIL import ImageGrab

ctypes.windll.user32.SetProcessDPIAware()

def click(x, y, wait=0.6):
    win32api.SetCursorPos((int(x), int(y)))
    time.sleep(0.1)
    win32api.mouse_event(2, 0, 0, 0, 0)
    time.sleep(0.05)
    win32api.mouse_event(4, 0, 0, 0, 0)
    time.sleep(wait)

dlg = None
def cb(h, _):
    global dlg
    if win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "#32770" and "公式" in win32gui.GetWindowText(h):
        dlg = h
win32gui.EnumWindows(cb, None)
print("dlg", hex(dlg) if dlg else None, win32gui.GetWindowText(dlg) if dlg else "")
if not dlg:
    raise SystemExit(1)
win32gui.SetForegroundWindow(dlg)
click(930, 266, 0.8)
ImageGrab.grab().save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\fm_user.png")
print("shot")
