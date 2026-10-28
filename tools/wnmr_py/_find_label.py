# -*- coding: utf-8 -*-
import ctypes
import time
import win32api
import win32gui
from PIL import ImageGrab
from collections import Counter

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
    time.sleep(0.008)
    win32api.keybd_event(vk, 0, 2, 0)
    time.sleep(0.015)

fg(find_main())
time.sleep(0.15)
win32api.SetCursorPos((900, 1200))
time.sleep(0.04)
win32api.mouse_event(2, 0, 0, 0, 0)
time.sleep(0.02)
win32api.mouse_event(4, 0, 0, 0, 0)
time.sleep(0.1)
for _ in range(50):
    key(0x28)
time.sleep(0.4)
im = ImageGrab.grab()
px = im.load()
pts = []
for y in range(1080, 1230):
    for x in range(100, 1550):
        r, g, b = px[x, y][:3]
        if (r > 210 and g > 180 and b < 70) or (r > 210 and g < 90 and b < 90) or (b > 200 and g > 180 and r < 90):
            pts.append((x, y))
print("pts", len(pts))
if pts:
    xs = Counter(x // 15 * 15 for x, y in pts)
    print(xs.most_common(8))
    cx = xs.most_common(1)[0][0] + 7
    ys = [y for x, y in pts if abs(x - cx) < 30]
    cy = sorted(ys)[len(ys) // 2] if ys else 1150
    print("center", cx, cy)
    c = im.crop((cx - 80, cy - 40, cx + 160, cy + 40))
    c.resize((c.size[0] * 3, c.size[1] * 3), 0).save(
        r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\label_zoom.png"
    )
    win32api.SetCursorPos((cx, 420))
    time.sleep(0.7)
    ImageGrab.grab().crop((cx - 40, 250, cx + 420, 620)).save(
        r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\label_tip.png"
    )
print("ok")
