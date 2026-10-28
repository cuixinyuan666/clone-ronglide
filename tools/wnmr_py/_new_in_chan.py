# -*- coding: utf-8 -*-
import ctypes
import time
import win32api
import win32gui
from PIL import ImageGrab

ctypes.windll.user32.SetProcessDPIAware()

def click(x, y, wait=0.45):
    win32api.SetCursorPos((int(x), int(y)))
    time.sleep(0.08)
    win32api.mouse_event(2, 0, 0, 0, 0)
    time.sleep(0.04)
    win32api.mouse_event(4, 0, 0, 0, 0)
    time.sleep(wait)

click(820, 343, 0.4)   # 缠论 folder
click(1447, 305, 1.0)  # 新建
ImageGrab.grab().save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\editor.png")
lines = []

def cb(h, _):
    if win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "#32770":
        lines.append("DLG %s %r %s" % (hex(h), win32gui.GetWindowText(h), win32gui.GetWindowRect(h)))
        def ch(c, __):
            lines.append("  %s %s %r %s" % (hex(c), win32gui.GetClassName(c), win32gui.GetWindowText(c)[:40], win32gui.GetWindowRect(c)))
        win32gui.EnumChildWindows(h, ch, None)

win32gui.EnumWindows(cb, None)
open(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\editor.txt", "w", encoding="utf-8").write("\n".join(lines))
print("dialogs", len([x for x in lines if x.startswith('DLG')]))
