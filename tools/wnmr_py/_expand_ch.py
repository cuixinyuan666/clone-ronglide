# -*- coding: utf-8 -*-
import ctypes
import time
import win32api
import win32gui
from PIL import ImageGrab

ctypes.windll.user32.SetProcessDPIAware()

def click(x, y, n=1, wait=0.5):
    win32api.SetCursorPos((int(x), int(y)))
    time.sleep(0.08)
    for _ in range(n):
        win32api.mouse_event(2, 0, 0, 0, 0)
        time.sleep(0.05)
        win32api.mouse_event(4, 0, 0, 0, 0)
        time.sleep(0.12)
    time.sleep(wait)

dlg = None
def cb(h, _):
    global dlg
    if win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "#32770":
        t = win32gui.GetWindowText(h)
        if t:
            dlg = h
            print("dlg", hex(h), t)
win32gui.EnumWindows(cb, None)
click(760, 311, n=2, wait=0.7)
ImageGrab.grab().save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\fm_ch.png")
print("shot")
