# -*- coding: utf-8 -*-
import ctypes
import win32gui

ctypes.windll.user32.SetProcessDPIAware()
u32 = ctypes.windll.user32

class RECT(ctypes.Structure):
    _fields_ = [("l", ctypes.c_long), ("t", ctypes.c_long), ("r", ctypes.c_long), ("b", ctypes.c_long)]

tab = 0x5509b8
print("tab", win32gui.IsWindow(tab), win32gui.GetWindowRect(tab))
n = u32.SendMessageW(tab, 0x1304, 0, 0)
print("tabs", n)
for i in range(n):
    rc = RECT()
    ok = u32.SendMessageW(tab, 0x130A, i, ctypes.byref(rc))
    print("item", i, "ok", ok, rc.l, rc.t, rc.r, rc.b)
    pt = win32gui.ClientToScreen(tab, ((rc.l + rc.r) // 2, (rc.t + rc.b) // 2))
    print("  screen", pt)
