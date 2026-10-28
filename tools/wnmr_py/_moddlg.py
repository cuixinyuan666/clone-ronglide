# -*- coding: utf-8 -*-
import win32gui

lines = []
def cb(h, _):
    if win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "#32770":
        lines.append("DLG %s %r %s" % (hex(h), win32gui.GetWindowText(h), win32gui.GetWindowRect(h)))
win32gui.EnumWindows(cb, None)
open(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\moddlg.txt", "w", encoding="utf-8").write("\n".join(lines))
print(len(lines))
