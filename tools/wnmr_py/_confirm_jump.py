# -*- coding: utf-8 -*-
import ctypes
import time
import win32api
import win32gui
from PIL import ImageGrab

ctypes.windll.user32.SetProcessDPIAware()

dlg = None
def find_dlg(hwnd, _):
    global dlg
    if win32gui.IsWindowVisible(hwnd) and win32gui.GetWindowText(hwnd) == "跳转到":
        dlg = hwnd
win32gui.EnumWindows(find_dlg, None)
print("dlg", hex(dlg) if dlg else None)
if not dlg:
    raise SystemExit(2)
ok = None
def ch(c, _):
    global ok
    if win32gui.GetClassName(c) == "Button" and win32gui.GetWindowText(c) == "确定":
        ok = c
win32gui.EnumChildWindows(dlg, ch, None)
r = win32gui.GetWindowRect(ok)
cx, cy = (r[0] + r[2]) // 2, (r[1] + r[3]) // 2
print("ok", r)
win32api.SetCursorPos((cx, cy))
time.sleep(0.08)
win32api.mouse_event(2, 0, 0, 0, 0)
time.sleep(0.04)
win32api.mouse_event(4, 0, 0, 0, 0)
time.sleep(1.2)
im = ImageGrab.grab()
im.save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\jumped.png")
im.crop((80, 160, 1700, 280)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\jumped_head.png")
im.crop((80, 900, 1700, 1280)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\jumped_axis.png")
print("closed", not win32gui.IsWindow(dlg))
