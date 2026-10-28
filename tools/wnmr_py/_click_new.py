# -*- coding: utf-8 -*-
import ctypes
import time
import win32api
import win32gui
from PIL import ImageGrab

ctypes.windll.user32.SetProcessDPIAware()

def click(x, y, wait=0.8):
    win32api.SetCursorPos((int(x), int(y)))
    time.sleep(0.08)
    win32api.mouse_event(2, 0, 0, 0, 0)
    time.sleep(0.05)
    win32api.mouse_event(4, 0, 0, 0, 0)
    time.sleep(wait)

click(1447, 305, 1.0)
ImageGrab.grab().save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\fm_newdlg.png")

def cb(h, _):
    if not win32gui.IsWindowVisible(h):
        return
    c = win32gui.GetClassName(h)
    t = win32gui.GetWindowText(h)
    if c == "#32770" or t:
        print("TOP", hex(h), c, repr(t)[:50], win32gui.GetWindowRect(h))
win32gui.EnumWindows(cb, None)
