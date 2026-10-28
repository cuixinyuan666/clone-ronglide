# -*- coding: utf-8 -*-
import ctypes
import time
import win32api
import win32gui
from PIL import ImageGrab

ctypes.windll.user32.SetProcessDPIAware()
u32 = ctypes.windll.user32
VK_DOWN = 0x28

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
    time.sleep(0.015)
    win32api.keybd_event(vk, 0, 2, 0)
    time.sleep(0.04)

fg(find_main())
time.sleep(0.2)
win32api.SetCursorPos((1400, 480))
time.sleep(0.05)
win32api.mouse_event(2, 0, 0, 0, 0)
time.sleep(0.03)
win32api.mouse_event(4, 0, 0, 0, 0)
time.sleep(0.2)
for i in range(25):
    key(VK_DOWN)
time.sleep(0.4)
im = ImageGrab.grab()
im.crop((80, 1050, 1750, 1280)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\zoom1_axis.png")
im.crop((80, 180, 900, 260)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\zoom1_head.png")
print("zoomed")
