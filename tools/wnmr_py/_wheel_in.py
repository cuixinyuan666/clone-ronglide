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

fg(find_main())
time.sleep(0.2)
win32api.SetCursorPos((1000, 450))
time.sleep(0.1)
for _ in range(12):
    win32api.mouse_event(0x0800, 0, 0, 120, 0)
    time.sleep(0.08)
time.sleep(0.4)
im = ImageGrab.grab()
im.crop((60, 1100, 1700, 1250)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\wheel_axis.png")
print("wheeled")
