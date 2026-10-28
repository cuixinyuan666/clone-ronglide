# -*- coding: utf-8 -*-
import ctypes
import win32gui

u32 = ctypes.windll.user32
dlg = 0x3f805bc
print("alive", win32gui.IsWindow(dlg), repr(win32gui.GetWindowText(dlg)), win32gui.GetWindowRect(dlg))

def walk(h, depth=0):
    ch = win32gui.GetWindow(h, 5)  # GW_CHILD
    while ch:
        cls = win32gui.GetClassName(ch)
        txt = win32gui.GetWindowText(ch)
        print("  " * depth + hex(ch), cls, repr(txt)[:50], win32gui.GetWindowRect(ch))
        if cls in ("SysTreeView32", "ListBox", "SysListView32"):
            if cls == "SysTreeView32":
                n = u32.SendMessageW(ch, 0x1105, 0, 0)  # TVM_GETCOUNT
                print("  " * depth + "  tree count", n)
        walk(ch, depth + 1)
        ch = win32gui.GetWindow(ch, 2)  # GW_HWNDNEXT

walk(dlg)
