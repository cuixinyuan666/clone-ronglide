# -*- coding: utf-8 -*-
"""离线K线执行链通用工具：定位主窗口、前台化、截图、枚举控件。
用法: shot.py <输出png文件名(不含路径)> [--hwnd 0x...]
"""
import sys, time, os
import win32gui, win32con
from PIL import ImageGrab

OUT_DIR = os.path.dirname(os.path.abspath(__file__))
MAIN_CLASS = 'CLASSNAME_RLD_CZSC_MAINAPP'


def find_main():
    res = []
    def cb(h, _):
        if win32gui.GetClassName(h) == MAIN_CLASS:
            res.append(h)
        return True
    win32gui.EnumWindows(cb, None)
    return res[0] if res else None


def foreground(hwnd):
    try:
        if win32gui.IsIconic(hwnd):
            win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
        win32gui.SetForegroundWindow(hwnd)
        time.sleep(0.6)
        return True
    except Exception as e:
        print('fg fail', e)
        return False


def shot(name, hwnd=None, rect=None):
    h = hwnd or find_main()
    if not h:
        print('main window not found')
        return None
    foreground(h)
    r = rect or win32gui.GetWindowRect(h)
    img = ImageGrab.grab(bbox=r, all_screens=True)
    p = os.path.join(OUT_DIR, name)
    img.save(p)
    print('saved', p, img.size)
    return p


def enum_controls(hwnd=None, depth_limit=3):
    """枚举主窗口子控件：句柄/类名/文本/矩形"""
    h = hwnd or find_main()
    out = []
    def walk(hw, depth):
        if depth > depth_limit:
            return
        c = win32gui.GetWindow(hw, win32con.GW_CHILD)
        while c:
            try:
                cls = win32gui.GetClassName(c)
                txt = win32gui.GetWindowText(c)
                r = win32gui.GetWindowRect(c)
                vis = win32gui.IsWindowVisible(c)
                out.append((c, cls, txt, r, vis, depth))
            except Exception:
                pass
            walk(c, depth + 1)
            try:
                c = win32gui.GetWindow(c, win32con.GW_HWNDNEXT)
            except Exception:
                break
    walk(h, 0)
    return out


if __name__ == '__main__':
    if len(sys.argv) > 1:
        shot(sys.argv[1])
    else:
        h = find_main()
        print('main hwnd', hex(h) if h else None)
