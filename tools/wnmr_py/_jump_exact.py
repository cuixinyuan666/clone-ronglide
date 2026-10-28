# -*- coding: utf-8 -*-
import ctypes
import time
import win32api
import win32con
import win32gui
from ctypes import wintypes
from PIL import ImageGrab

ctypes.windll.user32.SetProcessDPIAware()
u32 = ctypes.windll.user32
u32.GetMenuStringW.argtypes = [wintypes.HMENU, wintypes.UINT, wintypes.LPWSTR, ctypes.c_int, wintypes.UINT]
u32.GetMenuStringW.restype = ctypes.c_int
u32.GetMenuItemCount.argtypes = [wintypes.HMENU]
u32.GetMenuItemCount.restype = ctypes.c_int
u32.GetMenuItemRect.argtypes = [wintypes.HWND, wintypes.HMENU, wintypes.UINT, ctypes.POINTER(wintypes.RECT)]
u32.GetMenuItemRect.restype = wintypes.BOOL
MN_GETHMENU = 0x01E1
MF_BYPOSITION = 0x0400

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

# close 区间统计
def close_stat(h, _):
    if win32gui.IsWindowVisible(h) and "区间统计" in win32gui.GetWindowText(h):
        win32gui.PostMessage(h, win32con.WM_CLOSE, 0, 0)
        print("closed stat", hex(h))
win32gui.EnumWindows(close_stat, None)
time.sleep(0.4)

blockers()
h = find_main()
fg(h)
time.sleep(0.2)
win32api.SetCursorPos((700, 420))
time.sleep(0.08)
win32api.mouse_event(8, 0, 0, 0, 0)
time.sleep(0.04)
win32api.mouse_event(16, 0, 0, 0, 0)
time.sleep(0.35)

popups = []
def find_popup(hwnd, _):
    if win32gui.IsWindowVisible(hwnd) and win32gui.GetClassName(hwnd) == "#32768":
        popups.append(hwnd)
win32gui.EnumWindows(find_popup, None)
print("popups", [hex(p) for p in popups])
target = None
lines = []
for p in popups:
    hmenu = u32.SendMessageW(p, MN_GETHMENU, 0, 0)
    n = u32.GetMenuItemCount(hmenu)
    lines.append(f"menu {hex(hmenu)} n={n}")
    for i in range(n):
        buf = ctypes.create_unicode_buffer(128)
        u32.GetMenuStringW(hmenu, i, buf, 128, MF_BYPOSITION)
        rc = wintypes.RECT()
        ok = u32.GetMenuItemRect(p, hmenu, i, ctypes.byref(rc))
        lines.append(f"{i} {buf.value!r} rect {rc.left},{rc.top},{rc.right},{rc.bottom} ok={ok}")
        if "跳转" in buf.value:
            target = ((rc.left + rc.right) // 2, (rc.top + rc.bottom) // 2)
open(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\menu_items.txt", "w", encoding="utf-8").write("\n".join(lines))
print("target", target)
if target:
    win32api.SetCursorPos(target)
    time.sleep(0.08)
    win32api.mouse_event(2, 0, 0, 0, 0)
    time.sleep(0.04)
    win32api.mouse_event(4, 0, 0, 0, 0)
    time.sleep(0.7)
im = ImageGrab.grab()
im.crop((400, 200, 1800, 1200)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\jump2.png")
print("shot")
