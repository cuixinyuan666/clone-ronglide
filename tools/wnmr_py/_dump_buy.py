# -*- coding: utf-8 -*-
import ctypes
import time
import win32con
import win32gui
from PIL import ImageGrab

ctypes.windll.user32.SetProcessDPIAware()
lines = []

def cb(h, _):
    if not win32gui.IsWindowVisible(h):
        return
    t = win32gui.GetWindowText(h)
    c = win32gui.GetClassName(h)
    if c == "#32770":
        lines.append("DLG %s %r %s" % (hex(h), t, win32gui.GetWindowRect(h)))
        def ch(x, __):
            lines.append("  %s %s %r %s" % (hex(x), win32gui.GetClassName(x), win32gui.GetWindowText(x)[:60], win32gui.GetWindowRect(x)))
        win32gui.EnumChildWindows(h, ch, None)

win32gui.EnumWindows(cb, None)
open(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\buy.txt", "w", encoding="utf-8").write("\n".join(lines))
print("n", len(lines))
