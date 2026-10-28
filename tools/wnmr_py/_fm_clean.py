# -*- coding: utf-8 -*-
import ctypes
import time
import win32con
import win32gui
from PIL import ImageGrab

ctypes.windll.user32.SetProcessDPIAware()
u32 = ctypes.windll.user32
dlg = None
def cb(h, _):
    global dlg
    if win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "#32770" and win32gui.GetWindowText(h) == "缠中说禅":
        dlg = h
win32gui.EnumWindows(cb, None)
print("msg", hex(dlg) if dlg else None)
if dlg:
    btn = []
    def ch(c, _):
        if win32gui.GetClassName(c) == "Button":
            btn.append(c)
    win32gui.EnumChildWindows(dlg, ch, None)
    if btn:
        u32.SendMessageW(btn[0], win32con.BM_CLICK, 0, 0)
time.sleep(0.4)
ImageGrab.grab().crop((600, 170, 1500, 700)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\fm_clean.png")
print("shot")
