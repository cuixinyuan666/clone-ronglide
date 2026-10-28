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

def foreground(h):
    fg = u32.GetForegroundWindow()
    t1 = ctypes.windll.kernel32.GetCurrentThreadId()
    t2 = u32.GetWindowThreadProcessId(fg, None)
    u32.AttachThreadInput(t1, t2, True)
    try:
        win32gui.ShowWindow(h, win32con.SW_SHOWMAXIMIZED)
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

def click(x, y, wait=0.7):
    win32api.SetCursorPos((int(x), int(y)))
    time.sleep(0.08)
    win32api.mouse_event(2, 0, 0, 0, 0)
    time.sleep(0.04)
    win32api.mouse_event(4, 0, 0, 0, 0)
    time.sleep(wait)

def wizard(main, text):
    win32gui.PostMessage(main, 0x100, 0x39, 1)
    time.sleep(0.8)
    wiz = None
    def cb(h, _):
        nonlocal wiz
        if win32gui.IsWindowVisible(h) and "键盘精灵" in win32gui.GetWindowText(h):
            wiz = h
    win32gui.EnumWindows(cb, None)
    if not wiz:
        print("no wizard")
        return
    edit, lst = [], []
    win32gui.EnumChildWindows(wiz, lambda h, _: edit.append(h) if win32gui.GetClassName(h) == "Edit" else None, None)
    win32gui.EnumChildWindows(wiz, lambda h, _: lst.append(h) if win32gui.GetClassName(h) == "ListBox" else None, None)
    ctypes.windll.user32.SendMessageW(edit[0], win32con.WM_SETTEXT, 0, text)
    time.sleep(0.5)
    n = win32gui.SendMessage(lst[0], 0x018B, 0, 0)
    print("wizard", text, n)
    if n > 0:
        win32gui.SendMessage(lst[0], 0x0186, 0, 0)
        win32gui.PostMessage(edit[0], 0x100, 0x0D, 1)
        win32gui.PostMessage(edit[0], 0x101, 0x0D, 1)
    time.sleep(1.5)

h = find_main()
blockers()
foreground(h)
click(70, 244, 1.0)
click(400, 199, 0.6)
click(70, 460, 1.2)
wizard(h, "91")
time.sleep(2)
ImageGrab.grab().save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\full91.png")
print("saved")
