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

h = find_main()
fg = u32.GetForegroundWindow()
t1 = ctypes.windll.kernel32.GetCurrentThreadId()
t2 = u32.GetWindowThreadProcessId(fg, None)
u32.AttachThreadInput(t1, t2, True)
try:
    u32.SwitchToThisWindow(h, True)
finally:
    u32.AttachThreadInput(t1, t2, False)
time.sleep(0.2)
win32api.SetCursorPos((700, 480))
time.sleep(1.0)
im = ImageGrab.grab()
im.crop((200, 300, 1100, 900)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\hover.png")
print("shot")
