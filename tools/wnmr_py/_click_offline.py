# -*- coding: utf-8 -*-
import ctypes
import time
import win32con
import win32gui
import win32api
from PIL import ImageGrab

ctypes.windll.user32.SetProcessDPIAware()
u32 = ctypes.windll.user32

def find_offline():
    found = []
    def walk(h, depth):
        if depth > 6:
            return
        ch = win32gui.GetWindow(h, 5)
        while ch:
            try:
                if win32gui.GetClassName(ch) == "Button" and "脱机运行" in win32gui.GetWindowText(ch):
                    found.append(ch)
            except Exception:
                pass
            walk(ch, depth + 1)
            ch = win32gui.GetWindow(ch, 2)
    tops = []
    win32gui.EnumWindows(lambda h, _: tops.append(h), None)
    for h in tops:
        walk(h, 0)
    return found

def find_main():
    res = []
    def cb(h, _):
        if win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "CLASSNAME_RLD_CZSC_MAINAPP":
            res.append(h)
    win32gui.EnumWindows(cb, None)
    return res

btns = find_offline()
print("buttons", [hex(b) for b in btns])
if not btns:
    raise SystemExit(1)
b = btns[0]
parent = win32gui.GetParent(b)
print("parent", hex(parent), win32gui.GetWindowRect(parent))
win32gui.ShowWindow(parent, win32con.SW_RESTORE)
win32gui.SetWindowPos(parent, win32con.HWND_TOPMOST, 0, 0, 0, 0, win32con.SWP_NOMOVE | win32con.SWP_NOSIZE)
time.sleep(0.3)
r = win32gui.GetWindowRect(b)
cx, cy = (r[0] + r[2]) // 2, (r[1] + r[3]) // 2
print("click", cx, cy, "text", win32gui.GetWindowText(b))
win32api.SetCursorPos((cx, cy))
time.sleep(0.2)
win32api.mouse_event(2, 0, 0, 0, 0)
time.sleep(0.08)
win32api.mouse_event(4, 0, 0, 0, 0)
time.sleep(0.4)
win32gui.SendMessage(b, win32con.BM_CLICK, 0, 0)
for i in range(40):
    time.sleep(1)
    mains = find_main()
    still = find_offline()
    print("t", i, "main", [hex(m) for m in mains], "offline", bool(still), flush=True)
    if mains:
        win32gui.SetWindowPos(parent, win32con.HWND_NOTOPMOST, 0, 0, 0, 0, win32con.SWP_NOMOVE | win32con.SWP_NOSIZE)
        ImageGrab.grab().save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\after_login.png")
        print("MAIN UP", win32gui.GetWindowRect(mains[0]), win32gui.GetWindowText(mains[0]))
        break
else:
    ImageGrab.grab().save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\after_login.png")
    print("still no main")
