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

def key(vk):
    win32api.keybd_event(vk, 0, 0, 0)
    time.sleep(0.02)
    win32api.keybd_event(vk, 0, 2, 0)

fg(find_main())
time.sleep(0.2)
key(0x1B)  # close tooltip
time.sleep(0.25)
# one wide drag on the price plot
x1, y, x2 = 700, 400, 1600
win32api.SetCursorPos((x1, y))
time.sleep(0.08)
win32api.mouse_event(2, 0, 0, 0, 0)
time.sleep(0.08)
for i in range(1, 16):
    win32api.SetCursorPos((x1 + (x2 - x1) * i // 15, y))
    time.sleep(0.02)
time.sleep(0.08)
win32api.mouse_event(4, 0, 0, 0, 0)
time.sleep(0.4)
key(0x1B)
time.sleep(0.2)
win32api.SetCursorPos((160, 400))
time.sleep(0.7)
im = ImageGrab.grab()
im.crop((40, 220, 620, 620)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\after_drag.png")
im.crop((60, 1100, 1600, 1250)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\after_drag_axis.png")
print("done")
