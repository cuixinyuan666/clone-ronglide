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

def drag():
    win32api.SetCursorPos((1100, 500))
    time.sleep(0.012)
    win32api.mouse_event(2, 0, 0, 0, 0)
    for i in range(1, 8):
        win32api.SetCursorPos((1100 + 60 * i, 500))
        time.sleep(0.01)
    win32api.mouse_event(4, 0, 0, 0, 0)

h = find_main()
foreground(h)
win32api.keybd_event(0x1B, 0, 0, 0)
time.sleep(0.05)
win32api.keybd_event(0x1B, 0, 2, 0)
time.sleep(0.2)
for _ in range(40):
    drag()
time.sleep(0.2)
win32api.SetCursorPos((400, 480))
time.sleep(0.7)
im = ImageGrab.grab()
im.crop((80, 200, 900, 700)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\pan6_tip.png")
print("done")
