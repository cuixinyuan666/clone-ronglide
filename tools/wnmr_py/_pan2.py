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

def key(vk, n, gap=0.02):
    for _ in range(n):
        win32api.keybd_event(vk, 0, 0, 0)
        time.sleep(0.008)
        win32api.keybd_event(vk, 0, 2, 0)
        time.sleep(gap)

def drag():
    win32api.SetCursorPos((280, 450))
    time.sleep(0.02)
    win32api.mouse_event(2, 0, 0, 0, 0)
    for i in range(1, 16):
        win32api.SetCursorPos((280 + 70 * i, 450))
        time.sleep(0.01)
    win32api.mouse_event(4, 0, 0, 0, 0)

h = find_main()
foreground(h)
win32api.SetCursorPos((900, 450))
time.sleep(0.05)
win32api.mouse_event(2, 0, 0, 0, 0)
time.sleep(0.03)
win32api.mouse_event(4, 0, 0, 0, 0)
key(0x28, 50, 0.02)
for _ in range(40):
    drag()
time.sleep(0.3)
win32api.SetCursorPos((220, 420))
time.sleep(0.6)
im = ImageGrab.grab()
im.save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\pan2.png")
im.crop((80, 250, 700, 620)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\pan2_tip.png")
print("done")
