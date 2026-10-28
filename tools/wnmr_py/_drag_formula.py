# -*- coding: utf-8 -*-
import ctypes
import time
import win32api
from PIL import ImageGrab

ctypes.windll.user32.SetProcessDPIAware()

win32api.SetCursorPos((900, 375))
time.sleep(0.15)
win32api.mouse_event(2, 0, 0, 0, 0)  # left down
time.sleep(0.2)
for i in range(1, 16):
    x = 900 + (400 - 900) * i // 15
    y = 375 + (480 - 375) * i // 15
    win32api.SetCursorPos((x, y))
    time.sleep(0.03)
time.sleep(0.1)
win32api.mouse_event(4, 0, 0, 0, 0)  # left up
time.sleep(0.8)
ImageGrab.grab().save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\drag.png")
print("shot")
