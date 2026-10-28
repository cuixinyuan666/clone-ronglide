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
    time.sleep(0.01)
    win32api.keybd_event(vk, 0, 2, 0)
    time.sleep(0.025)

def drag(x1, y, x2):
    win32api.SetCursorPos((x1, y))
    time.sleep(0.05)
    win32api.mouse_event(2, 0, 0, 0, 0)
    time.sleep(0.06)
    for i in range(1, 11):
        win32api.SetCursorPos((x1 + (x2 - x1) * i // 10, y))
        time.sleep(0.02)
    time.sleep(0.05)
    win32api.mouse_event(4, 0, 0, 0, 0)
    time.sleep(0.25)

fg(find_main())
time.sleep(0.12)
win32api.SetCursorPos((800, 1210))
time.sleep(0.04)
win32api.mouse_event(2, 0, 0, 0, 0)
time.sleep(0.02)
win32api.mouse_event(4, 0, 0, 0, 0)
time.sleep(0.08)
for _ in range(16):
    key(0x28)  # zoom out
time.sleep(0.3)
# drag left so the view moves later, toward August
for _ in range(3):
    drag(1400, 450, 500)
time.sleep(0.3)
ImageGrab.grab().crop((40, 1100, 1700, 1250)).save(
    r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\toward_aug.png"
)
print("moved")
