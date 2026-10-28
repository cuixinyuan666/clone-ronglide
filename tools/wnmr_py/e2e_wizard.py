"""e2e_wizard.py - open the keyboard wizard in MainApp and run a command (default 91).
Usage: python e2e_wizard.py [command]
"""
import ctypes
import sys
import time

import win32con
import win32gui

from PIL import ImageGrab

WM_KEYDOWN, WM_KEYUP = 0x100, 0x101
VK_RETURN = 0x0D
IDOK = 1


def find_main():
    res = []

    def cb(h, _):
        if win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == 'CLASSNAME_RLD_CZSC_MAINAPP':
            res.append(h)
    win32gui.EnumWindows(cb, None)
    return res[0] if res else None


def find_wizard():
    res = []

    def cb(h, _):
        if win32gui.IsWindowVisible(h) and '键盘精灵' in win32gui.GetWindowText(h):
            res.append(h)
    win32gui.EnumWindows(cb, None)
    return res[0] if res else None


def foreground(hwnd):
    for _ in range(8):
        if win32gui.GetForegroundWindow() == hwnd:
            return True
        fg = win32gui.GetForegroundWindow()
        t1 = ctypes.windll.kernel32.GetCurrentThreadId()
        t2 = ctypes.windll.user32.GetWindowThreadProcessId(fg, None)
        ctypes.windll.user32.AttachThreadInput(t1, t2, True)
        try:
            win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
            try:
                win32gui.SetForegroundWindow(hwnd)
            except Exception:
                pass
            if win32gui.GetForegroundWindow() != hwnd:
                ctypes.windll.user32.SwitchToThisWindow(hwnd, True)
        finally:
            ctypes.windll.user32.AttachThreadInput(t1, t2, False)
        time.sleep(0.4)
    return win32gui.GetForegroundWindow() == hwnd


def shot(name):
    img = ImageGrab.grab()
    path = r'D:\a_ronglide\clone-ronglide\tools\_e2e_%s.png' % name
    img.save(path)
    print('shot', path, flush=True)


def main():
    command = sys.argv[1] if len(sys.argv) > 1 else '91'
    main_h = find_main()
    print('main', hex(main_h), flush=True)
    print('fg', foreground(main_h), flush=True)
    time.sleep(0.5)

    win32gui.PostMessage(main_h, WM_KEYDOWN, 0x39, 1)  # '9'
    time.sleep(1.0)
    wiz = find_wizard()
    if not wiz:
        print('no wizard opened', flush=True)
        return 1
    print('wizard', hex(wiz), flush=True)

    edit, lst = [], []
    win32gui.EnumChildWindows(
        wiz, lambda h, _: edit.append(h) if win32gui.GetClassName(h) == 'Edit' else None, None)
    win32gui.EnumChildWindows(
        wiz, lambda h, _: lst.append(h) if win32gui.GetClassName(h) == 'ListBox' else None, None)
    print('edit', [hex(e) for e in edit], 'list', [hex(l) for l in lst], flush=True)
    ctypes.windll.user32.SendMessageW(edit[0], win32con.WM_SETTEXT, 0, command)
    time.sleep(1.0)

    n = win32gui.SendMessage(lst[0], 0x018B, 0, 0)
    items = []
    for i in range(min(n, 8)):
        sz = win32gui.SendMessage(lst[0], 0x0189, i, 0)
        buf = ctypes.create_unicode_buffer(max(sz + 1, 128))
        win32gui.SendMessage(lst[0], 0x018A, i, buf)
        items.append(buf.value)
    print('listbox count=%d items=%r' % (n, items), flush=True)

    if n > 0:
        win32gui.SendMessage(lst[0], 0x0186, 0, 0)  # LB_SETCURSEL 0
        time.sleep(0.2)
        win32gui.PostMessage(edit[0], WM_KEYDOWN, VK_RETURN, 1)
        win32gui.PostMessage(edit[0], WM_KEYUP, VK_RETURN, 1)
        time.sleep(0.5)
        if find_wizard():
            win32gui.PostMessage(wiz, WM_COMMAND, IDOK, 0)
            time.sleep(0.5)
        if find_wizard():
            win32gui.PostMessage(wiz, WM_KEYDOWN, VK_RETURN, 1)
            win32gui.PostMessage(wiz, WM_KEYUP, VK_RETURN, 1)
    time.sleep(1.5)
    print('wizard still open:', bool(find_wizard()), flush=True)
    shot('wz_%s' % command)
    return 0


if __name__ == '__main__':
    sys.exit(main())
