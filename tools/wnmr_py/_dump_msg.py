# -*- coding: utf-8 -*-
import win32gui

h = 0x2b09c6
lines = []
lines.append("alive %s %r %s" % (win32gui.IsWindow(h), win32gui.GetWindowText(h) if win32gui.IsWindow(h) else "", win32gui.GetWindowRect(h) if win32gui.IsWindow(h) else ""))

def ch(c, _):
    lines.append("%s %s %r %s" % (hex(c), win32gui.GetClassName(c), win32gui.GetWindowText(c)[:80], win32gui.GetWindowRect(c)))

if win32gui.IsWindow(h):
    win32gui.EnumChildWindows(h, ch, None)
open(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\msg.txt", "w", encoding="utf-8").write("\n".join(lines))
print("lines", len(lines))
