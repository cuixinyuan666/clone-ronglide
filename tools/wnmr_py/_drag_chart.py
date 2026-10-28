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

def blockers():
    def cb(hwnd, _):
        if not win32gui.IsWindowVisible(hwnd):
            return
        cls = win32gui.GetClassName(hwnd)
        if cls in ("CLASSNAME_RLD_CZSC_MAINAPP", "Progman", "Shell_TrayWnd", "WorkerW", "#32770"):
            return
        if win32gui.GetParent(hwnd):
            return
        r = win32gui.GetWindowRect(hwnd)
        if r[2] - r[0] > 500 and r[3] - r[1] > 300 and -200 < r[0] < 500:
            win32gui.ShowWindow(hwnd, win32con.SW_MINIMIZE)
    win32gui.EnumWindows(cb, None)

def click(x, y, wait=0.45):
    win32api.SetCursorPos((int(x), int(y)))
    time.sleep(0.05)
    win32api.mouse_event(2, 0, 0, 0, 0)
    time.sleep(0.03)
    win32api.mouse_event(4, 0, 0, 0, 0)
    time.sleep(wait)

def drag_right():
    win32api.SetCursorPos((350, 430))
    time.sleep(0.05)
    win32api.mouse_event(2, 0, 0, 0, 0)
    time.sleep(0.05)
    for i in range(1, 13):
        win32api.SetCursorPos((350 + 90 * i, 430))
        time.sleep(0.015)
    win32api.mouse_event(4, 0, 0, 0, 0)
    time.sleep(0.05)

h = find_main()
blockers()
foreground(h)
click(70, 244, 0.7)
click(400, 199, 0.4)
click(70, 460, 0.9)
# zoom out a bit
for _ in range(20):
    win32api.keybd_event(0x28, 0, 0, 0)
    time.sleep(0.01)
    win32api.keybd_event(0x28, 0, 2, 0)
    time.sleep(0.03)
for _ in range(25):
    drag_right()
time.sleep(0.5)
im = ImageGrab.grab()
im.save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\dragged.png")
im.crop((60, 140, 1600, 250)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\dragged_head.png")
im.crop((80, 220, 1700, 760)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\dragged_body.png")
print("done")
