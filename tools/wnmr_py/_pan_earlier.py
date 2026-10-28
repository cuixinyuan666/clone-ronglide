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
    steps = 12
    for i in range(1, steps + 1):
        x = x1 + (x2 - x1) * i // steps
        win32api.SetCursorPos((x, y))
        time.sleep(0.015)
    time.sleep(0.05)
    win32api.mouse_event(4, 0, 0, 0, 0)
    time.sleep(0.25)

fg(find_main())
time.sleep(0.2)
for _ in range(4):
    drag(500, 480, 1500)
time.sleep(0.3)
im = ImageGrab.grab()
im.crop((80, 1080, 1750, 1260)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\pan_axis.png")
print("panned")
