# -*- coding: utf-8 -*-
import ctypes
import time
import win32api
import win32con
import win32gui

ctypes.windll.user32.SetProcessDPIAware()
u32 = ctypes.windll.user32

def click(x, y, wait=0.4):
    win32api.SetCursorPos((int(x), int(y)))
    time.sleep(0.06)
    win32api.mouse_event(2, 0, 0, 0, 0)
    time.sleep(0.03)
    win32api.mouse_event(4, 0, 0, 0, 0)
    time.sleep(wait)

# dismiss
dlg = 0x524064c
btn = []
def ch(c, _):
    if win32gui.GetClassName(c) == "Button":
        btn.append(c)
if win32gui.IsWindow(dlg):
    win32gui.EnumChildWindows(dlg, ch, None)
    if btn:
        u32.SendMessageW(btn[0], win32con.BM_CLICK, 0, 0)
        print("dismissed", hex(btn[0]))
time.sleep(0.3)
click(760, 309, 0.3)  # select 技术指标
click(1447, 305, 0.8)  # 新建
editor = None
def cb(h, _):
    global editor
    if win32gui.IsWindowVisible(h) and win32gui.GetWindowText(h) == "指标公式编辑器":
        editor = h
win32gui.EnumWindows(cb, None)
print("editor", hex(editor) if editor else None)
msgs = []
def cb2(h, _):
    if win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "#32770":
        msgs.append(win32gui.GetWindowText(h))
win32gui.EnumWindows(cb2, None)
open(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\after_new.txt", "w", encoding="utf-8").write("\n".join(msgs))
print("dialogs", len(msgs))
