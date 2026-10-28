# -*- coding: utf-8 -*-
import ctypes
import time
import win32api
import win32gui
from PIL import ImageGrab

ctypes.windll.user32.SetProcessDPIAware()
u32 = ctypes.windll.user32
VK_LEFT = 0x25

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
    time.sleep(0.008)
    win32api.keybd_event(vk, 0, 2, 0)
    time.sleep(0.012)

fg(find_main())
time.sleep(0.15)
# focus the date axis, not a candle
win32api.SetCursorPos((800, 1210))
time.sleep(0.05)
win32api.mouse_event(2, 0, 0, 0, 0)
time.sleep(0.03)
win32api.mouse_event(4, 0, 0, 0, 0)
time.sleep(0.15)
for _ in range(80):
    key(VK_LEFT)
time.sleep(0.3)
ImageGrab.grab().crop((80, 1120, 900, 1240)).save(
    r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\leftkey_axis.png"
)
print("left")
