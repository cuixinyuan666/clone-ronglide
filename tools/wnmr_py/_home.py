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

def key(vk, n=1, gap=0.02):
    for _ in range(n):
        win32api.keybd_event(vk, 0, 0, 0)
        time.sleep(0.008)
        win32api.keybd_event(vk, 0, 2, 0)
        time.sleep(gap)

h = find_main()
foreground(h)
win32api.SetCursorPos((900, 400))
time.sleep(0.05)
win32api.mouse_event(2, 0, 0, 0, 0)
time.sleep(0.03)
win32api.mouse_event(4, 0, 0, 0, 0)
time.sleep(0.1)
key(0x24, 1, 0.2)  # Home
time.sleep(0.8)
im = ImageGrab.grab()
im.save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\home.png")
im.crop((80, 500, 1800, 780)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\home_axis.png")
print("home")
