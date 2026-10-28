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
DTM_SETSYSTEMTIME = 0x1002
GDT_VALID = 0

class SYSTEMTIME(ctypes.Structure):
    _fields_ = [
        ("wYear", wintypes.WORD),
        ("wMonth", wintypes.WORD),
        ("wDayOfWeek", wintypes.WORD),
        ("wDay", wintypes.WORD),
        ("wHour", wintypes.WORD),
        ("wMinute", wintypes.WORD),
        ("wSecond", wintypes.WORD),
        ("wMilliseconds", wintypes.WORD),
    ]

dlg = None
def find_dlg(h, _):
    global dlg
    if win32gui.IsWindowVisible(h) and win32gui.GetWindowText(h) == "跳转到":
        dlg = h
win32gui.EnumWindows(find_dlg, None)
print("dlg", hex(dlg) if dlg else None)
if not dlg:
    raise SystemExit(2)

kids = []
def ch(c, _):
    kids.append((hex(c), win32gui.GetClassName(c), win32gui.GetWindowText(c), win32gui.GetWindowRect(c)))
win32gui.EnumChildWindows(dlg, ch, None)
for k in kids:
    print(k)

picker = None
ok = None
for c, cls, t, r in [(int(k[0], 16), k[1], k[2], k[3]) for k in kids]:
    if "Date" in cls or "SysDate" in cls or cls.startswith("Sys"):
        picker = c
    if cls == "Button" and t == "确定":
        ok = c
print("picker", hex(picker) if picker else None, "ok", hex(ok) if ok else None)

st = SYSTEMTIME(2017, 8, 0, 10, 13, 0, 0, 0)
Send = ctypes.windll.user32.SendMessageW
Send.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, ctypes.c_void_p]
Send.restype = wintypes.LPARAM
if picker:
    ret = Send(picker, DTM_SETSYSTEMTIME, GDT_VALID, ctypes.byref(st))
    print("set", ret, "text", win32gui.GetWindowText(picker))
time.sleep(0.3)
if ok:
    u32.SendMessageW(ok, win32con.BM_CLICK, 0, 0)
time.sleep(1.2)
im = ImageGrab.grab()
im.crop((80, 160, 1600, 980)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\after_jump.png")
print("shot")
