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
    time.sleep(0.012)
    win32api.keybd_event(vk, 0, 2, 0)
    time.sleep(0.04)

fg(find_main())
time.sleep(0.15)
# text start measured near x=700
win32api.SetCursorPos((700, 480))
time.sleep(0.1)
for _ in range(14):
    key(0x26)
time.sleep(0.4)
im = ImageGrab.grab()
im.crop((40, 1080, 1700, 1250)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\zin_axis.png")
im.crop((400, 980, 1200, 1240)).resize((1600, 520), 0).save(
    r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\zin_text.png"
)
print("zoomed in")
