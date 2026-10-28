# -*- coding: utf-8 -*-
import ctypes
import time
import win32api
import win32gui
from PIL import ImageGrab

ctypes.windll.user32.SetProcessDPIAware()
u32 = ctypes.windll.user32

def find_main():
    res = []
    win32gui.EnumWindows(lambda h, _: res.append(h) if win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "CLASSNAME_RLD_CZSC_MAINAPP" else None, None)
    return res[0]

def fg(h):
    f = u32.GetForegroundWindow()
    t1 = ctypes.windll.kernel32.GetCurrentThreadId()
    t2 = u32.GetWindowThreadProcessId(f, None)
    u32.AttachThreadInput(t1, t2, True)
    try:
        u32.SwitchToThisWindow(h, True)
    finally:
        u32.AttachThreadInput(t1, t2, False)

def drag(x1, y, x2):
    win32api.SetCursorPos((x1, y))
    time.sleep(0.05)
    win32api.mouse_event(2, 0, 0, 0, 0)
    time.sleep(0.05)
    for i in range(1, 9):
        win32api.SetCursorPos((x1 + (x2 - x1) * i // 8, y))
        time.sleep(0.015)
    time.sleep(0.05)
    win32api.mouse_event(4, 0, 0, 0, 0)
    time.sleep(0.3)

fg(find_main())
time.sleep(0.15)
drag(600, 480, 1100)
im = ImageGrab.grab()
im.crop((60, 1100, 900, 1240)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\pan2_left.png")
print("panned")
