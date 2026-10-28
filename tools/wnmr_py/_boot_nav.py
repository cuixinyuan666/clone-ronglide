# -*- coding: utf-8 -*-
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


def click(x, y, wait=0.6):
    win32api.SetCursorPos((int(x), int(y)))
    time.sleep(0.12)
    win32api.mouse_event(2, 0, 0, 0, 0)
    time.sleep(0.05)
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
            print("close welcome", hex(h), flush=True)
            win32gui.PostMessage(h, win32con.WM_CLOSE, 0, 0)
    win32gui.EnumWindows(cb, None)


def foreground(h):
    for _ in range(8):
        if u32.GetForegroundWindow() == h:
            return
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
            u32.SwitchToThisWindow(h, True)
        finally:
            u32.AttachThreadInput(t1, t2, False)
        time.sleep(0.25)


def minimize_blockers():
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
    print("market", r, flush=True)
    print("symtab", api.load_symtab(r["raw"]), flush=True)
    print("symbol", api.get_symbol(list(SYM)).get("ok"), flush=True)
    session.detach()


def main():
    subprocess.run(["taskkill", "/F", "/IM", "MainApp.exe"], capture_output=True)
    time.sleep(1)
    print("start", flush=True)
    subprocess.Popen([APP], cwd=os.path.dirname(APP))
    btn = None
    for i in range(60):
        btns = find_offline()
        if btns:
            btn = btns[0]
            break
        time.sleep(1)
    if not btn:
        print("no offline")
        return 1
    r = win32gui.GetWindowRect(btn)
    print("offline", r, flush=True)
    click((r[0] + r[2]) // 2, (r[1] + r[3]) // 2, 1.0)
    h = None
    for i in range(40):
        close_welcome()
        h = find_main()
        if h:
            break
        time.sleep(1)
    if not h:
        print("no main")
        ImageGrab.grab().save(os.path.join(SHOT, "boot2.png"))
        return 1
    print("main", hex(h), win32gui.GetWindowRect(h), flush=True)
    time.sleep(1.5)
    close_welcome()
    time.sleep(0.5)
    inject(h)
    minimize_blockers()
    foreground(h)
    close_welcome()
    click(70, 316, 1.2)
    ImageGrab.grab().save(os.path.join(SHOT, "zixuan.png"))
    print("shot zixuan", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
