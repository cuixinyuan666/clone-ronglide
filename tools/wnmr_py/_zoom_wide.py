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
    return res[0] if res else None

def foreground(h):
    fg = u32.GetForegroundWindow()
    t1 = ctypes.windll.kernel32.GetCurrentThreadId()
    t2 = u32.GetWindowThreadProcessId(fg, None)
    u32.AttachThreadInput(t1, t2, True)
    try:
        u32.SwitchToThisWindow(h, True)
    finally:
        u32.AttachThreadInput(t1, t2, False)

h = find_main()
foreground(h)
win32api.SetCursorPos((1000, 450))
time.sleep(0.1)
win32api.mouse_event(2, 0, 0, 0, 0)
time.sleep(0.04)
win32api.mouse_event(4, 0, 0, 0, 0)
time.sleep(0.1)
for _ in range(80):
    win32api.keybd_event(0x28, 0, 0, 0)
    time.sleep(0.008)
    win32api.keybd_event(0x28, 0, 2, 0)
    time.sleep(0.02)
time.sleep(0.4)
# click left side of the plot to pin a tooltip
win32api.SetCursorPos((280, 420))
time.sleep(0.2)
win32api.mouse_event(2, 0, 0, 0, 0)
time.sleep(0.04)
win32api.mouse_event(4, 0, 0, 0, 0)
time.sleep(0.8)
im = ImageGrab.grab()
im.save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\wide.png")
im.crop((60, 150, 1000, 750)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\wide_left.png")
print("done")
