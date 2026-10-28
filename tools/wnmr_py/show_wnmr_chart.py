# -*- coding: utf-8 -*-
"""注入符号表，打开 600000 的 1 分钟图，并截全屏。"""
import ctypes
import os
import sys
import time

import frida
import win32api
import win32con
import win32gui
from PIL import ImageGrab

TOOLS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(TOOLS, ".."))
from inject_symtab import JS as SYMTAB_JS, SYM

OUT = os.path.join(TOOLS, "wnmr_in_app.png")
SHOTS = os.path.join(TOOLS, "_shots")
os.makedirs(SHOTS, exist_ok=True)

ctypes.windll.user32.SetProcessDPIAware()
WM_KEYDOWN, WM_KEYUP = 0x100, 0x101
VK_RETURN = 0x0D


def shot(name):
    path = os.path.join(SHOTS, name)
    ImageGrab.grab().save(path)
    print("shot", path, flush=True)
    return path


def find_main():
    res = []

    def cb(h, _):
        if win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "CLASSNAME_RLD_CZSC_MAINAPP":
            res.append(h)

    win32gui.EnumWindows(cb, None)
    return res[0] if res else None


def pid_of(hwnd):
    pid = ctypes.c_ulong(0)
    ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return pid.value


def foreground(h):
    u32 = ctypes.windll.user32
    for _ in range(12):
        if u32.GetForegroundWindow() == h:
            return True
        fg = u32.GetForegroundWindow()
        t1 = ctypes.windll.kernel32.GetCurrentThreadId()
        t2 = u32.GetWindowThreadProcessId(fg, None)
        u32.AttachThreadInput(t1, t2, True)
        try:
            win32gui.ShowWindow(h, win32con.SW_SHOWMAXIMIZED)
            try:
                win32gui.SetForegroundWindow(h)
            except Exception:
                pass
            if u32.GetForegroundWindow() != h:
                u32.SwitchToThisWindow(h, True)
        finally:
            u32.AttachThreadInput(t1, t2, False)
        time.sleep(0.35)
    return u32.GetForegroundWindow() == h


def click(x, y, wait=1.0):
    win32api.SetCursorPos((int(x), int(y)))
    time.sleep(0.2)
    win32api.mouse_event(2, 0, 0, 0, 0)
    time.sleep(0.08)
    win32api.mouse_event(4, 0, 0, 0, 0)
    time.sleep(wait)


def inject(pid):
    session = frida.attach(pid)
    script = session.create_script(SYMTAB_JS)
    script.on("message", lambda m, d: print("SYM", m.get("payload", m), flush=True))
    script.load()
    api = script.exports_sync
    api.init()
    r = api.get_market(2)
    if not r or r.get("raw") in (None, "0x0"):
        api.add_market(2)
        r = api.get_market(2)
    mkt = r.get("raw") if r else None
    print("market", r, flush=True)
    if mkt and mkt != "0x0":
        print("loadSymtab", api.load_symtab(mkt), flush=True)
        print("getSymbol", api.get_symbol(list(SYM)), flush=True)
    session.detach()


def wizard(main, text):
    win32gui.PostMessage(main, WM_KEYDOWN, 0x39, 1)
    time.sleep(1.0)
    wiz = None

    def cb(h, _):
        nonlocal wiz
        if win32gui.IsWindowVisible(h) and "键盘精灵" in win32gui.GetWindowText(h):
            wiz = h

    win32gui.EnumWindows(cb, None)
    if not wiz:
        print("no wizard", flush=True)
        return False
    edit, lst = [], []
    win32gui.EnumChildWindows(wiz, lambda h, _: edit.append(h) if win32gui.GetClassName(h) == "Edit" else None, None)
    win32gui.EnumChildWindows(wiz, lambda h, _: lst.append(h) if win32gui.GetClassName(h) == "ListBox" else None, None)
    if not edit or not lst:
        print("wizard children missing", flush=True)
        return False
    ctypes.windll.user32.SendMessageW(edit[0], win32con.WM_SETTEXT, 0, text)
    time.sleep(0.8)
    n = win32gui.SendMessage(lst[0], 0x018B, 0, 0)
    print("wizard", text, "count", n, flush=True)
    if n <= 0:
        return False
    win32gui.SendMessage(lst[0], 0x0186, 0, 0)
    time.sleep(0.2)
    win32gui.PostMessage(edit[0], WM_KEYDOWN, VK_RETURN, 1)
    win32gui.PostMessage(edit[0], WM_KEYUP, VK_RETURN, 1)
    time.sleep(0.6)
    if win32gui.IsWindowVisible(wiz):
        win32gui.PostMessage(wiz, win32con.WM_COMMAND, 1, 0)
    time.sleep(1.5)
    return True


def main():
    h = find_main()
    if not h:
        print("NO MAIN")
        return 1
    print("main", hex(h), win32gui.GetWindowRect(h), flush=True)
    foreground(h)
    win32gui.ShowWindow(h, win32con.SW_SHOWMAXIMIZED)
    time.sleep(0.8)
    inject(pid_of(h))
    foreground(h)
    l, t, r, b = win32gui.GetWindowRect(h)
    print("rect", l, t, r, b, flush=True)
    click(l + 38, t + 120, 1.2)
    shot("01_zixuan.png")
    click(l + 80, t + 200, 1.5)
    shot("02_row.png")
    click(l + 38, t + 231, 1.5)
    shot("03_tech.png")
    click(l + 99, t + 73, 1.2)
    wizard(h, "91")
    time.sleep(2.0)
    shot("04_kline.png")
    ImageGrab.grab().save(OUT)
    print("saved", OUT, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
