# -*- coding: utf-8 -*-
import ctypes
import time
import win32api
import win32con
import win32gui
from PIL import ImageGrab

ctypes.windll.user32.SetProcessDPIAware()
u32 = ctypes.windll.user32

def find_main():
    res = []
    win32gui.EnumWindows(lambda h, _: res.append(h) if win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "CLASSNAME_RLD_CZSC_MAINAPP" else None, None)
    return res[0] if res else None

def close_welcome():
    def cb(h, _):
        if win32gui.IsWindowVisible(h) and "欢迎" in win32gui.GetWindowText(h):
            print("close", hex(h), win32gui.GetWindowText(h)[:40])
            win32gui.PostMessage(h, win32con.WM_CLOSE, 0, 0)
    win32gui.EnumWindows(cb, None)

def foreground(h):
    for _ in range(8):
        if u32.GetForegroundWindow() == h:
            return True
        fg = u32.GetForegroundWindow()
        t1 = ctypes.windll.kernel32.GetCurrentThreadId()
        t2 = u32.GetWindowThreadProcessId(fg, None)
        u32.AttachThreadInput(t1, t2, True)
        try:
            win32gui.ShowWindow(h, win32con.SW_SHOWMAXIMIZED)
            try:
                win32gui.SetForegroundWindow(h)
            except Exception:
                pass
            if u32.GetForegroundWindow() != h:
                u32.SwitchToThisWindow(h, True)
        finally:
            u32.AttachThreadInput(t1, t2, False)
        time.sleep(0.3)
    return u32.GetForegroundWindow() == h

def click(x, y, wait=0.8):
    win32api.SetCursorPos((int(x), int(y)))
    time.sleep(0.15)
    win32api.mouse_event(2, 0, 0, 0, 0)
    time.sleep(0.06)
    win32api.mouse_event(4, 0, 0, 0, 0)
    time.sleep(wait)

def minimize_blockers():
    def cb(hwnd, _):
        if not win32gui.IsWindowVisible(hwnd):
            return
        if win32gui.GetClassName(hwnd) == "CLASSNAME_RLD_CZSC_MAINAPP":
            return
        if win32gui.GetParent(hwnd):
            return
        r = win32gui.GetWindowRect(hwnd)
        if r[2] - r[0] > 500 and r[3] - r[1] > 300 and r[0] > -200:
            print("min", win32gui.GetClassName(hwnd), repr(win32gui.GetWindowText(hwnd))[:50], r, flush=True)
            win32gui.ShowWindow(hwnd, win32con.SW_MINIMIZE)
    win32gui.EnumWindows(cb, None)

h = find_main()
print("main", hex(h) if h else None)
close_welcome()
minimize_blockers()
time.sleep(0.5)
foreground(h)
time.sleep(0.4)
ImageGrab.grab().save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\focused.png")
click(544, 36, 0.9)
pops = []
def cb(hwnd, _):
    if win32gui.IsWindowVisible(hwnd) and win32gui.GetClassName(hwnd).startswith("#32768"):
        pops.append((hex(hwnd), win32gui.GetWindowRect(hwnd)))
win32gui.EnumWindows(cb, None)
print("popups", pops)
ImageGrab.grab().save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\menu_func.png")
print("shot")
