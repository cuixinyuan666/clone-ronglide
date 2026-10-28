# -*- coding: utf-8 -*-
import time
import win32api
from PIL import ImageGrab

def drag(x1, y, x2):
    win32api.SetCursorPos((x1, y))
    time.sleep(0.04)
    win32api.mouse_event(2, 0, 0, 0, 0)
    time.sleep(0.05)
    for i in range(1, 14):
        win32api.SetCursorPos((x1 + (x2 - x1) * i // 13, y))
        time.sleep(0.012)
    time.sleep(0.04)
    win32api.mouse_event(4, 0, 0, 0, 0)
    time.sleep(0.18)

for _ in range(10):
    drag(1550, 430, 250)
time.sleep(0.25)
ImageGrab.grab().crop((40, 1120, 1700, 1245)).save(
    r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\aug2_axis.png"
)
print("panned")
