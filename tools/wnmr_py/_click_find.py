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
    time.sleep(0.08)
    win32api.mouse_event(2, 0, 0, 0, 0)
    time.sleep(0.04)
    win32api.mouse_event(4, 0, 0, 0, 0)
    time.sleep(wait)

click(1447, 473, 0.8)
ImageGrab.grab().save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\fm_find.png")

def cb(h, _):
    if win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "#32770":
        print("dlg", hex(h), repr(win32gui.GetWindowText(h)), win32gui.GetWindowRect(h))
        def ch(c, __):
            print(" ", hex(c), win32gui.GetClassName(c), repr(win32gui.GetWindowText(c))[:40], win32gui.GetWindowRect(c))
        win32gui.EnumChildWindows(h, ch, None)
win32gui.EnumWindows(cb, None)
