# -*- coding: utf-8 -*-
import ctypes
import time
import win32api
from PIL import ImageGrab

ctypes.windll.user32.SetProcessDPIAware()

def click(x, y, wait=0.5):
    win32api.SetCursorPos((int(x), int(y)))
    time.sleep(0.08)
    win32api.mouse_event(2, 0, 0, 0, 0)
    time.sleep(0.04)
    win32api.mouse_event(4, 0, 0, 0, 0)
    time.sleep(wait)

click(648, 270, 0.6)
ImageGrab.grab().save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\fm_exp.png")
print("shot")
