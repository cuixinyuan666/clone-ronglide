# -*- coding: utf-8 -*-
import ctypes
import time
import win32con
import win32gui
from PIL import ImageGrab

ctypes.windll.user32.SetProcessDPIAware()
u32 = ctypes.windll.user32
edit = 0x480a20
ok = 0x3d0ae2
u32.SendMessageW(edit, win32con.WM_SETTEXT, 0, "WNMRSHOW")
time.sleep(0.2)
u32.SendMessageW(ok, win32con.BM_CLICK, 0, 0)
time.sleep(0.8)
ImageGrab.grab().save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\fm_found.png")

def cb(h, _):
    if win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "#32770":
        print("dlg", hex(h), repr(win32gui.GetWindowText(h)), win32gui.GetWindowRect(h))
win32gui.EnumWindows(cb, None)
print("done")
