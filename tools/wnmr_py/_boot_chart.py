# -*- coding: utf-8 -*-
"""重启并打开 600000 的 1 分钟技术分析图。"""
import ctypes
import os
import subprocess
import sys
import time

import frida
import win32api
import win32con
import win32gui
from PIL import ImageGrab

ctypes.windll.user32.SetProcessDPIAware()
u32 = ctypes.windll.user32
APP = r"D:\a_ronglide\缠中说禅\MainApp.exe"
SHOT = r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots"
sys.path.insert(0, r"D:\a_ronglide\clone-ronglide\tools")
from inject_symtab import JS as SYMTAB_JS, SYM


def click(x, y, wait=0.5):
    win32api.SetCursorPos((int(x), int(y)))
    time.sleep(0.08)
    win32api.mouse_event(2, 0, 0, 0, 0)
    time.sleep(0.04)
    win32api.mouse_event(4, 0, 0, 0, 0)
    time.sleep(wait)


def find_main():
    res = []
    win32gui.EnumWindows(lambda h, _: res.append(h) if win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "CLASSNAME_RLD_CZSC_MAINAPP" else None, None)
    return res[0] if res else None


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


def close_welcome():
    def cb(h, _):
        if win32gui.IsWindowVisible(h) and "欢迎" in win32gui.GetWindowText(h):
            win32gui.PostMessage(h, win32con.WM_CLOSE, 0, 0)
    win32gui.EnumWindows(cb, None)


def foreground(h):
    for _ in range(6):
        if u32.GetForegroundWindow() == h:
            return
        fg = u32.GetForegroundWindow()
        t1 = ctypes.windll.kernel32.GetCurrentThreadId()
        t2 = u32.GetWindowThreadProcessId(fg, None)
        u32.AttachThreadInput(t1, t2, True)
        try:
            win32gui.ShowWindow(h, win32con.SW_SHOWMAXIMIZED)
            u32.SwitchToThisWindow(h, True)
        finally:
            u32.AttachThreadInput(t1, t2, False)
        time.sleep(0.2)


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


def inject(hwnd):
    pid = ctypes.c_ulong(0)
    u32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    session = frida.attach(pid.value)
    script = session.create_script(SYMTAB_JS)
    script.load()
    api = script.exports_sync
    api.init()
    r = api.get_market(2)
    if not r or r.get("raw") in (None, "0x0"):
        api.add_market(2)
        r = api.get_market(2)
    print("symtab", api.load_symtab(r["raw"]), "sym", api.get_symbol(list(SYM)).get("ok"), flush=True)
    session.detach()


def wizard(main, text):
    win32gui.PostMessage(main, 0x100, 0x39, 1)
    time.sleep(0.7)
    wiz = None

    def cb(h, _):
        nonlocal wiz
        if win32gui.IsWindowVisible(h) and "键盘精灵" in win32gui.GetWindowText(h):
            wiz = h

    win32gui.EnumWindows(cb, None)
    if not wiz:
        print("no wizard")
        return
    edit, lst = [], []
    win32gui.EnumChildWindows(wiz, lambda h, _: edit.append(h) if win32gui.GetClassName(h) == "Edit" else None, None)
    win32gui.EnumChildWindows(wiz, lambda h, _: lst.append(h) if win32gui.GetClassName(h) == "ListBox" else None, None)
    ctypes.windll.user32.SendMessageW(edit[0], win32con.WM_SETTEXT, 0, text)
    time.sleep(0.4)
    n = win32gui.SendMessage(lst[0], 0x018B, 0, 0)
    print("wizard", text, n, flush=True)
    if n > 0:
        win32gui.SendMessage(lst[0], 0x0186, 0, 0)
        win32gui.PostMessage(edit[0], 0x100, 0x0D, 1)
        win32gui.PostMessage(edit[0], 0x101, 0x0D, 1)
    time.sleep(1.2)


def main():
    subprocess.run(["taskkill", "/F", "/IM", "MainApp.exe"], capture_output=True)
    time.sleep(1)
    subprocess.Popen([APP], cwd=os.path.dirname(APP))
    btn = None
    for _ in range(50):
        btns = find_offline()
        if btns:
            btn = btns[0]
            break
        time.sleep(1)
    if not btn:
        print("no offline")
        return 1
    r = win32gui.GetWindowRect(btn)
    click((r[0] + r[2]) // 2, (r[1] + r[3]) // 2, 0.8)
    h = None
    for _ in range(30):
        close_welcome()
        h = find_main()
        if h:
            break
        time.sleep(1)
    if not h:
        print("no main")
        return 1
    time.sleep(1)
    close_welcome()
    inject(h)
    blockers()
    foreground(h)
    close_welcome()
    click(70, 244, 0.8)
    click(400, 199, 0.4)
    click(70, 460, 1.0)
    wizard(h, "91")
    time.sleep(1.5)
    ImageGrab.grab().save(os.path.join(SHOT, "restart_chart.png"))
    print("saved", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
