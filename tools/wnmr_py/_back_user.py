# -*- coding: utf-8 -*-
import ctypes
import time
import win32api
import win32con
import win32gui
from PIL import ImageGrab

ctypes.windll.user32.SetProcessDPIAware()
u32 = ctypes.windll.user32

def click(x, y, wait=0.5):
    win32api.SetCursorPos((int(x), int(y)))
    time.sleep(0.08)
    win32api.mouse_event(2, 0, 0, 0, 0)
    time.sleep(0.04)
    win32api.mouse_event(4, 0, 0, 0, 0)
    time.sleep(wait)

# dismiss 请选择指标类型
for h in (0x5809ca,):
    if win32gui.IsWindow(h):
        u32.SendMessageW(h, win32con.BM_CLICK, 0, 0)
        print("dismissed")
time.sleep(0.4)
click(930, 266, 0.5)
ImageGrab.grab().save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\fm_user2.png")
print("shot")
