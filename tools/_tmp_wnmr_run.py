# -*- coding: utf-8 -*-
"""One-shot: symtab + K线 + authorize bypass + menu + screenshot. PID explicit."""
import os, sys, time, ctypes, subprocess
import frida
import win32gui, win32con, win32api
from PIL import ImageGrab

TOOLS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TOOLS)
from inject_symtab import JS as SYMTAB_JS, SYM

OUT = os.path.join(TOOLS, "_wnmr_shown_251025.png")
BYPASS_LOG = os.path.join(TOOLS, "_bypass_251025_out.log")
WM_KEYDOWN, WM_KEYUP, WM_CHAR = 0x100, 0x101, 0x102
VK_RETURN = 0x0D


def live_mainapp_pid():
    best = None
    for p in frida.get_local_device().enumerate_processes():
        if p.name.lower() != "mainapp.exe":
            continue
        try:
            import psutil
            h = psutil.Process(p.pid).num_handles()
        except Exception:
            h = 1
        if h > 10:
            best = p.pid
    if not best:
        for p in frida.get_local_device().enumerate_processes():
            if p.name.lower() == "mainapp.exe":
                return p.pid
    return best


def inject_symtab(pid):
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
    if mkt and mkt != "0x0":
        print("loadSymtab", api.load_symtab(mkt), flush=True)
        print("getSymbol", api.get_symbol(list(SYM)), flush=True)
    session.detach()


def start_perm_bypass(pid):
    log = os.path.join(TOOLS, "_perm_bypass_251025.log")
    if os.path.isfile(log) and "[READY]" in open(log, encoding="utf-8", errors="replace").read():
        print("perm bypass ready", flush=True)
        return True
    subprocess.Popen(
        [sys.executable, os.path.join(TOOLS, "inject_perm_bypass.py"), str(pid)],
        stdout=open(log, "w", encoding="utf-8"),
        stderr=subprocess.STDOUT,
        creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
    )
    for _ in range(20):
        time.sleep(0.5)
        if os.path.isfile(log) and "[READY]" in open(log, encoding="utf-8", errors="replace").read():
            print("perm bypass READY", flush=True)
            return True
    return False


def start_bypass(pid):
    if os.path.isfile(BYPASS_LOG):
        t = open(BYPASS_LOG, encoding="utf-8", errors="replace").read()
        if "[READY]" in t:
            print("bypass already READY", flush=True)
            return True
        os.remove(BYPASS_LOG)
    subprocess.Popen(
        [sys.executable, os.path.join(TOOLS, "inject_authorize_bypass.py"), str(pid)],
        stdout=open(BYPASS_LOG, "w", encoding="utf-8"),
        stderr=subprocess.STDOUT,
        creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
    )
    for _ in range(30):
        time.sleep(0.5)
        if os.path.isfile(BYPASS_LOG):
            t = open(BYPASS_LOG, encoding="utf-8", errors="replace").read()
            if "[READY]" in t:
                print("bypass READY", flush=True)
                return True
    print("bypass NOT ready", open(BYPASS_LOG, encoding="utf-8", errors="replace").read(), flush=True)
    return False


def find_main():
    res = []
    def cb(h, _):
        if win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "CLASSNAME_RLD_CZSC_MAINAPP":
            res.append(h)
    win32gui.EnumWindows(cb, None)
    return res[0] if res else None


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
        time.sleep(0.4)
    return u32.GetForegroundWindow() == h


def click(x, y, wait=1.0):
    win32api.SetCursorPos((int(x), int(y)))
    time.sleep(0.25)
    win32api.mouse_event(2, 0, 0, 0, 0)
    time.sleep(0.08)
    win32api.mouse_event(4, 0, 0, 0, 0)
    time.sleep(wait)


def dismiss_purchase():
    def cb(h, _):
        if win32gui.IsWindowVisible(h) and win32gui.GetWindowText(h) == "购买":
            r = win32gui.GetWindowRect(h)
            print("purchase dlg", hex(h), r, flush=True)
            # 取消 button ~ right side of dialog center
            cx = (r[0] + r[2]) // 2 + 60
            cy = (r[1] + r[3]) // 2 + 55
            click(cx, cy, 0.8)
    win32gui.EnumWindows(cb, None)


def popup_menus():
    out = []
    def cb(h, _):
        if win32gui.IsWindowVisible(h) and win32gui.GetClassName(h).startswith("#32768"):
            out.append(win32gui.GetWindowRect(h))
    win32gui.EnumWindows(cb, None)
    return out


def minimize_blockers():
    for title in ("Cursor", "OpenCode", "WorkBuddy"):
        def cb(h, _):
            if win32gui.IsWindowVisible(h) and title in win32gui.GetWindowText(h):
                win32gui.ShowWindow(h, win32con.SW_MINIMIZE)
        win32gui.EnumWindows(cb, None)


def scr(main, cx, cy):
    return win32gui.ClientToScreen(main, (cx, cy))


def wrect(main):
    return win32gui.GetWindowRect(main)


def click_chan_wnmr_xd(main):
    l, t, r, b = wrect(main)
    for dx in (260, 280, 300, 240, 220):
        mx, my = l + dx, t + 52
        print("click 缠论 try", mx, my, flush=True)
        click(mx, my, 0.7)
        ms = popup_menus()
        if ms:
            break
    else:
        print("popups", ms, flush=True)
        return False
    print("popups", ms, flush=True)
    ml, mt, mr, mb = ms[-1]
    mh = mb - mt
    # 无脑买入线段: index 16 of 19 rows (incl separators), 0-based row 15
    n_rows = 19
    row = 15  # 0-based -> 16th row = 无脑买入线段
    y = mt + int(mh * (row + 0.5) / n_rows)
    x = ml + 80
    print("click item", x, y, flush=True)
    click(x, y, 3.0)
    return True


def wizard_cmd(main, text):
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
    ctypes.windll.user32.SendMessageW(edit[0], win32con.WM_SETTEXT, 0, text)
    time.sleep(1.0)
    n = win32gui.SendMessage(lst[0], 0x018B, 0, 0)
    print(f'wizard "{text}" count={n}', flush=True)
    if n <= 0:
        return False
    win32gui.SendMessage(lst[0], 0x0186, 0, 0)
    time.sleep(0.2)
    win32gui.PostMessage(edit[0], WM_KEYDOWN, VK_RETURN, 1)
    win32gui.PostMessage(edit[0], WM_KEYUP, VK_RETURN, 1)
    time.sleep(0.8)
    if win32gui.IsWindowVisible(wiz):
        win32gui.PostMessage(wiz, win32con.WM_COMMAND, 1, 0)
    time.sleep(2)
    return True


def show_kline(main):
    l, t, r, b = wrect(main)
    click(l + 38, t + 120, 1.2)   # 自选
    click(l + 80, t + 200, 1.5)   # 600000 行
    click(l + 38, t + 231, 1.5)   # 技术
    click(l + 99, t + 73, 2.5)    # 1分钟
    if not wizard_cmd(main, "91"):
        wizard_cmd(main, "91")
    time.sleep(3)


def main():
    ctypes.windll.user32.SetProcessDPIAware()
    pid = live_mainapp_pid()
    print("pid", pid, flush=True)
    if not pid:
        print("NO MainApp")
        return 1
    main_h = find_main()
    print("main", hex(main_h) if main_h else None, flush=True)
    minimize_blockers()
    foreground(main_h)
    win32gui.ShowWindow(main_h, win32con.SW_SHOWMAXIMIZED)
    time.sleep(1)
    inject_symtab(pid)
    foreground(main_h)
    # self-select list: click 600000 row if visible
    show_kline(main_h)
    time.sleep(2)
    if not start_bypass(pid):
        return 2
    start_perm_bypass(pid)
    dismiss_purchase()
    foreground(main_h)
    click_chan_wnmr_xd(main_h)
    dismiss_purchase()
    time.sleep(2)
    ImageGrab.grab().save(OUT)
    print("saved", OUT, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
