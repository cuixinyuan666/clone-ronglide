# -*- coding: utf-8 -*-
"""Retype 2017/08/10, Tab to commit, Enter to confirm."""
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
VK_RIGHT = 0x27
VK_TAB = 0x09
VK_RETURN = 0x0D
VK_ESCAPE = 0x1B

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

def click(x, y, wait=0.25):
    win32api.SetCursorPos((int(x), int(y)))
    time.sleep(0.05)
    win32api.mouse_event(2, 0, 0, 0, 0)
    time.sleep(0.03)
    win32api.mouse_event(4, 0, 0, 0, 0)
    time.sleep(wait)

def key(vk, wait=0.07):
    win32api.keybd_event(vk, 0, 0, 0)
    time.sleep(0.02)
    win32api.keybd_event(vk, 0, 2, 0)
    time.sleep(wait)

blockers()
h = find_main()
fg(h)
time.sleep(0.3)
win32api.SetCursorPos((900, 500))
time.sleep(0.1)
win32api.mouse_event(2, 0, 0, 0, 0)
time.sleep(0.03)
win32api.mouse_event(4, 0, 0, 0, 0)
time.sleep(0.2)
win32api.SetCursorPos((700, 420))
time.sleep(0.08)
win32api.mouse_event(8, 0, 0, 0, 0)
time.sleep(0.04)
win32api.mouse_event(16, 0, 0, 0, 0)
time.sleep(0.35)
target = None
def find_popup(hwnd, _):
    global target
    if not (win32gui.IsWindowVisible(hwnd) and win32gui.GetClassName(hwnd) == "#32768"):
        return
    hmenu = u32.SendMessageW(hwnd, MN_GETHMENU, 0, 0)
    n = u32.GetMenuItemCount(hmenu)
    for i in range(n):
        buf = ctypes.create_unicode_buffer(64)
        u32.GetMenuStringW(hmenu, i, buf, 64, MF_BYPOSITION)
        if buf.value == "跳转到":
            rc = wintypes.RECT()
            u32.GetMenuItemRect(hwnd, hmenu, i, ctypes.byref(rc))
            target = ((rc.left + rc.right) // 2, (rc.top + rc.bottom) // 2)
win32gui.EnumWindows(find_popup, None)
print("item", target)
if not target:
    ImageGrab.grab().crop((600, 300, 1200, 900)).save(
        r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\no_menu.png"
    )
    raise SystemExit(2)
click(*target, 0.5)
dlg = None
def find_dlg(hwnd, _):
    global dlg
    if win32gui.IsWindowVisible(hwnd) and win32gui.GetWindowText(hwnd) == "跳转到":
        dlg = hwnd
win32gui.EnumWindows(find_dlg, None)
picker = None
def ch(c, _):
    global picker
    if win32gui.GetClassName(c) == "SysDateTimePick32":
        picker = c
win32gui.EnumChildWindows(dlg, ch, None)
r = win32gui.GetWindowRect(picker)
click(r[0] + 48, (r[1] + r[3]) // 2, 0.15)
for chd in "2017":
    key(ord(chd))
key(VK_RIGHT, 0.1)
for chd in "08":
    key(ord(chd))
key(VK_RIGHT, 0.1)
for chd in "10":
    key(ord(chd))
key(VK_TAB, 0.25)
im = ImageGrab.grab()
im.crop((r[0] - 200, r[1] - 60, r[2] + 40, r[3] + 40)).save(
    r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\jump_tab.png"
)
key(VK_RETURN, 0.3)
time.sleep(1.0)
im = ImageGrab.grab()
im.crop((80, 980, 1500, 1220)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\jump_enter_axis.png")
print("dlg alive", win32gui.IsWindow(dlg))
