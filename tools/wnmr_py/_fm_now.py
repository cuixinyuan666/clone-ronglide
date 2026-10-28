# -*- coding: utf-8 -*-
import ctypes
import win32gui
from PIL import ImageGrab

ctypes.windll.user32.SetProcessDPIAware()
ImageGrab.grab().crop((600, 170, 1600, 900)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\fm_now.png")
lines = []
def cb(h, _):
    if win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "#32770":
        lines.append("%s %r %s" % (hex(h), win32gui.GetWindowText(h), win32gui.GetWindowRect(h)))
win32gui.EnumWindows(cb, None)
open(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\fm_now.txt", "w", encoding="utf-8").write("\n".join(lines))
print(lines)
