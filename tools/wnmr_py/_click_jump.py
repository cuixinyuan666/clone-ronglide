# -*- coding: utf-8 -*-
import ctypes
import time
import win32api
import win32gui
from PIL import ImageGrab

ctypes.windll.user32.SetProcessDPIAware()
u32 = ctypes.windll.user32

def blockers():
    def cb(hwnd, _):
        if not win32gui.IsWindowVisible(hwnd):
            return
        cls = win32gui.GetClassName(hwnd)
        if cls in ("CLASSNAME_RLD_CZSC_MAINAPP", "Progman", "Shell_TrayWnd", "WorkerW"):
            return
        if win32gui.GetParent(hwnd):
            return
        r = win32gui.GetWindowRect(hwnd)
        if r[2] - r[0] > 500 and r[3] - r[1] > 300 and -200 < r[0] < 500:
            import win32con
            win32gui.ShowWindow(hwnd, win32con.SW_MINIMIZE)
    win32gui.EnumWindows(cb, None)

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

blockers()
h = find_main()
fg(h)
time.sleep(0.25)
win32api.SetCursorPos((700, 420))
time.sleep(0.08)
win32api.mouse_event(8, 0, 0, 0, 0)
time.sleep(0.04)
win32api.mouse_event(16, 0, 0, 0, 0)
time.sleep(0.45)
# 跳转到 measured at crop (80, 369) of menu opened at (680, 400)
win32api.SetCursorPos((760, 769))
time.sleep(0.08)
win32api.mouse_event(2, 0, 0, 0, 0)
time.sleep(0.04)
win32api.mouse_event(4, 0, 0, 0, 0)
time.sleep(0.7)
im = ImageGrab.grab()
im.crop((500, 250, 1700, 1100)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\jump_dlg.png")
print("shot")
