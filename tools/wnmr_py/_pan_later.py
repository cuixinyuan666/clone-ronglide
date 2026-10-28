# -*- coding: utf-8 -*-
import time
import win32api
import win32gui
import ctypes
from PIL import ImageGrab
from collections import Counter

ctypes.windll.user32.SetProcessDPIAware()

def drag(x1, y, x2):
    win32api.SetCursorPos((x1, y))
    time.sleep(0.05)
    win32api.mouse_event(2, 0, 0, 0, 0)
    time.sleep(0.05)
    for i in range(1, 11):
        win32api.SetCursorPos((x1 + (x2 - x1) * i // 10, y))
        time.sleep(0.018)
    time.sleep(0.04)
    win32api.mouse_event(4, 0, 0, 0, 0)
    time.sleep(0.3)

for _ in range(2):
    drag(1500, 450, 400)
time.sleep(0.3)
im = ImageGrab.grab()
im.crop((40, 1100, 1700, 1250)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\aug_axis.png")
px = im.load()
pts = []
for y in range(1000, 1240, 2):
    for x in range(80, 1650, 2):
        r, g, b = px[x, y][:3]
        if r > 220 and g < 80 and b < 80:
            pts.append(x)
print("reds", len(pts))
if pts:
    print(Counter(x // 40 * 40 for x in pts).most_common(6))
