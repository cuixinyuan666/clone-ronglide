# -*- coding: utf-8 -*-
import win32gui
h = 0x524064c
lines = [repr(win32gui.GetWindowText(h)), str(win32gui.GetWindowRect(h))]
def ch(c, _):
    lines.append("%s %s %r" % (win32gui.GetClassName(c), win32gui.GetWindowRect(c), win32gui.GetWindowText(c)[:80]))
win32gui.EnumChildWindows(h, ch, None)
open(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\msg2.txt", "w", encoding="utf-8").write("\n".join(lines))
print("ok")
