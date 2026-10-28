# -*- coding: utf-8 -*-
"""Zoom out to the whole year, then zoom in at the label x and see which date stays."""
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
    time.sleep(0.02)

fg(find_main())
time.sleep(0.15)
win32api.SetCursorPos((900, 1200))
time.sleep(0.04)
win32api.mouse_event(2, 0, 0, 0, 0)
time.sleep(0.02)
win32api.mouse_event(4, 0, 0, 0, 0)
time.sleep(0.1)
for _ in range(45):
    key(0x28)  # zoom out
time.sleep(0.35)
im = ImageGrab.grab()
px = im.load()
# label sits in the lower pane: yellow pixels with a red neighbor, y 1000-1230
best = None
bestn = 0
for x0 in range(200, 1500, 8):
    n = 0
    for y in range(1080, 1220, 2):
        r, g, b = px[x0, y][:3]
        if r > 200 and g > 180 and b < 60:
            n += 1
    if n > bestn:
        bestn = n
        best = x0
print("label x", best, "yellow rows", bestn)
im.crop((60, 1140, 700, 1240)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\pre_zoom_left.png")
if best:
    win32api.SetCursorPos((best, 500))
    time.sleep(0.15)
    for _ in range(8):
        key(0x26)  # zoom in
    time.sleep(0.35)
im = ImageGrab.grab()
im.crop((60, 1140, 800, 1240)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\post_zoom_left.png")
im.crop((1100, 1140, 1800, 1240)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\post_zoom_right.png")
print("done")
