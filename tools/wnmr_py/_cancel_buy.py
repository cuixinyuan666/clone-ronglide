# -*- coding: utf-8 -*-
import ctypes
import time
import win32con
import win32gui
from PIL import ImageGrab

ctypes.windll.user32.SetProcessDPIAware()
u32 = ctypes.windll.user32
u32.SendMessageW(0x4d096a, win32con.BM_CLICK, 0, 0)
time.sleep(0.6)
im = ImageGrab.grab()
im.save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\after_cancel.png")
im.crop((100, 520, 1900, 820)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\after_cancel_axis.png")
print("alive", win32gui.IsWindow(0xd00994))
