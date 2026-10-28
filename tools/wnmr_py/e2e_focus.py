"""e2e_focus.py - recover GUI focus:
1) send ESC to any console window stuck in QuickEdit mark mode (title '选择 ...')
2) foreground the MainApp main window
3) optionally screenshot
Usage: python e2e_focus.py [shotname]
"""
import ctypes
import sys
import time

import win32con
import win32gui

from PIL import ImageGrab

u32 = ctypes.windll.user32


def find_windows(pred):
    res = []

    def cb(h, _):
        try:
            if win32gui.IsWindowVisible(h) and pred(h):
                res.append(h)
        except Exception:
            pass
    win32gui.EnumWindows(cb, None)
    return res


def topmost(hwnd, on=True):
    SWP_NOMOVE, SWP_NOSIZE, SWP_NOACTIVATE = 0x0002, 0x0001, 0x0010
    HWND_TOPMOST, HWND_NOTOPMOST = -1, -2
    u32.SetWindowPos(hwnd, HWND_TOPMOST if on else HWND_NOTOPMOST,
                     0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE)


def foreground(hwnd, keep_topmost=True):
    if keep_topmost:
        topmost(hwnd, True)
    for _ in range(8):
        if win32gui.GetForegroundWindow() == hwnd:
            return True
        fg = win32gui.GetForegroundWindow()
        t1 = ctypes.windll.kernel32.GetCurrentThreadId()
        t2 = u32.GetWindowThreadProcessId(fg, None)
        u32.AttachThreadInput(t1, t2, True)
        try:
            if win32gui.IsIconic(hwnd):
                win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
            try:
                win32gui.SetForegroundWindow(hwnd)
            except Exception:
                pass
            if win32gui.GetForegroundWindow() != hwnd:
                u32.SwitchToThisWindow(hwnd, True)
        finally:
            u32.AttachThreadInput(t1, t2, False)
        time.sleep(0.4)
    return win32gui.GetForegroundWindow() == hwnd


def main():
    consoles = find_windows(
        lambda h: win32gui.GetClassName(h) == 'ConsoleWindowClass' and
        '\u9009\u62e9' in win32gui.GetWindowText(h))
    for c in consoles:
        print('console in mark mode:', hex(c), repr(win32gui.GetWindowText(c)), flush=True)
        win32gui.PostMessage(c, win32con.WM_KEYDOWN, win32con.VK_ESCAPE, 0)
        win32gui.PostMessage(c, win32con.WM_KEYUP, win32con.VK_ESCAPE, 0)
        time.sleep(0.3)
    mains = find_windows(lambda h: win32gui.GetClassName(h) == 'CLASSNAME_RLD_CZSC_MAINAPP')
    if not mains:
        print('no MainApp main window')
        return 1
    if 'max' in sys.argv[2:]:
        win32gui.ShowWindow(mains[0], win32con.SW_MAXIMIZE)
        time.sleep(0.8)
    keep_top = 'untop' not in sys.argv[2:]
    ok = foreground(mains[0], keep_topmost=keep_top)
    if not keep_top:
        topmost(mains[0], False)
        print('topmost cleared', hex(mains[0]), flush=True)
    print('foreground MainApp', hex(mains[0]), ok, flush=True)
    time.sleep(0.6)
    if len(sys.argv) > 1:
        img = ImageGrab.grab()
        path = r'D:\a_ronglide\clone-ronglide\tools\_e2e_%s.png' % sys.argv[1]
        img.save(path)
        print('shot', path, flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
