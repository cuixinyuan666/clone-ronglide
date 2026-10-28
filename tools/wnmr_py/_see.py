# -*- coding: utf-8 -*-
import ctypes
import win32gui
import win32process
from PIL import ImageGrab

ctypes.windll.user32.SetProcessDPIAware()

lines = []
def cb(h, _):
    if not win32gui.IsWindowVisible(h):
        return
    if win32gui.GetParent(h):
        return
    r = win32gui.GetWindowRect(h)
    if r[2] - r[0] < 40:
        return
    lines.append(f"{hex(h)} {win32gui.GetClassName(h)} {win32gui.GetWindowText(h)!r} {r}")
win32gui.EnumWindows(cb, None)
open(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\wins.txt", "w", encoding="utf-8").write("\n".join(lines))
ImageGrab.grab().crop((0, 0, 1400, 900)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\now.png")
print(len(lines))
