# -*- coding: utf-8 -*-
import os, sys, time, subprocess, ctypes, frida
import win32gui, win32con, win32api
from PIL import ImageGrab

TOOLS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TOOLS)
from inject_symtab import JS as SYMTAB_JS, SYM

OUT = os.path.join(TOOLS, "_wnmr_shown_251025.png")
LOG = os.path.join(TOOLS, "_bypass_251025_out.log")


def live_pid():
    import psutil
    for p in frida.get_local_device().enumerate_processes():
        if p.name.lower() != "mainapp.exe":
            continue
        try:
            if psutil.Process(p.pid).num_handles() > 50:
                return p.pid
        except Exception:
            pass
    return None


def inject_symtab(pid):
    s = frida.attach(pid)
    sc = s.create_script(SYMTAB_JS)
    sc.load()
    api = sc.exports_sync
    api.init()
    api.add_market(2)
    m = api.get_market(2)
    api.load_symtab(m["raw"])
    api.get_symbol(list(SYM))
    s.detach()


def start_hooks(pid):
    open(LOG, "w").close()
    subprocess.Popen(
        [sys.executable, os.path.join(TOOLS, "inject_authorize_bypass.py"), str(pid)],
        stdout=open(LOG, "a", encoding="utf-8"),
        stderr=subprocess.STDOUT,
    )
    for name in ("inject_cmd_perm_bypass.py", "inject_func_perm_bypass.py"):
        subprocess.Popen(
            [sys.executable, os.path.join(TOOLS, name), str(pid)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    for _ in range(40):
        time.sleep(0.5)
        if os.path.isfile(LOG) and "[READY]" in open(LOG, encoding="utf-8", errors="replace").read():
            return True
    return False


def click(x, y, w=1.0):
    win32api.SetCursorPos((int(x), int(y)))
    time.sleep(0.2)
    win32api.mouse_event(2, 0, 0, 0, 0)
    time.sleep(0.06)
    win32api.mouse_event(4, 0, 0, 0, 0)
    time.sleep(w)


def setup_kline(h):
    win32gui.ShowWindow(h, win32con.SW_SHOWMAXIMIZED)
    time.sleep(1)
    l, t, r, b = win32gui.GetWindowRect(h)
    click(l + 38, t + 120, 1)
    click(l + 80, t + 200, 1.2)
    click(l + 38, t + 231, 1)
    click(l + 99, t + 73, 2.5)
    win32gui.PostMessage(h, 0x100, 0x39, 1)
    time.sleep(1)
    wiz = win32gui.FindWindow(None, "键盘精灵")
    if wiz:
        edit, lst = [], []
        win32gui.EnumChildWindows(wiz, lambda ch, _: edit.append(ch) if win32gui.GetClassName(ch) == "Edit" else None, None)
        win32gui.EnumChildWindows(wiz, lambda ch, _: lst.append(ch) if win32gui.GetClassName(ch) == "ListBox" else None, None)
        if edit and lst:
            ctypes.windll.user32.SendMessageW(edit[0], win32con.WM_SETTEXT, 0, "91")
            time.sleep(0.8)
            win32gui.SendMessage(lst[0], 0x186, 0, 0)
            win32gui.PostMessage(edit[0], 0x100, 0x0D, 1)
            time.sleep(2)


def dismiss_buy():
    d = win32gui.FindWindow(None, "购买")
    if d and win32gui.IsWindowVisible(d):
        btns = []
        win32gui.EnumChildWindows(
            d,
            lambda ch, _: btns.append(ch)
            if win32gui.GetClassName(ch) == "Button" and "取消" in win32gui.GetWindowText(ch)
            else None,
            None,
        )
        if btns:
            win32gui.SendMessage(btns[0], win32con.BM_CLICK, 0, 0)
            time.sleep(0.4)


def apply_wnmr(h):
    ctypes.windll.user32.SwitchToThisWindow(h, True)
    time.sleep(0.3)
    dismiss_buy()
    click(594, 33, 0.8)
    click(710, 645, 8)


def main():
    ctypes.windll.user32.SetProcessDPIAware()
    pid = live_pid()
    if not pid:
        print("no MainApp")
        return 1
    print("pid", pid)
    inject_symtab(pid)
    if not start_hooks(pid):
        print("authorize not ready")
        return 2
    h = win32gui.FindWindow("CLASSNAME_RLD_CZSC_MAINAPP", None)
    setup_kline(h)
    apply_wnmr(h)
    time.sleep(2)
    h2 = win32gui.FindWindow("CLASSNAME_RLD_CZSC_MAINAPP", None)
    if h2:
        r = win32gui.GetWindowRect(h2)
        ImageGrab.grab(bbox=r).save(OUT)
    else:
        ImageGrab.grab().save(OUT)
    buy = win32gui.FindWindow(None, "购买")
    print("purchase", bool(buy and win32gui.IsWindowVisible(buy)))
    print("saved", OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
