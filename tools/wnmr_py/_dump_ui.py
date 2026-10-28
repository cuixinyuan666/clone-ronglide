# -*- coding: utf-8 -*-
import os
import win32gui
from PIL import ImageGrab

out = r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots"
os.makedirs(out, exist_ok=True)
ImageGrab.grab().save(os.path.join(out, "boot.png"))
print("saved")

def cb(h, _):
    if not win32gui.IsWindowVisible(h):
        return
    t = win32gui.GetWindowText(h)
    c = win32gui.GetClassName(h)
    if c == "#32770" or "RLD" in c or t:
        print("TOP", hex(h), c, repr(t)[:70], win32gui.GetWindowRect(h))
        if c == "#32770":
            def ch(x, __):
                print("  ", hex(x), win32gui.GetClassName(x), repr(win32gui.GetWindowText(x))[:60], win32gui.GetWindowRect(x))
            win32gui.EnumChildWindows(h, ch, None)

win32gui.EnumWindows(cb, None)
