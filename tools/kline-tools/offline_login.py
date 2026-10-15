# -*- coding: utf-8 -*-
"""等待登录窗口出现并点击 [脱机运行]。"""
import sys, time, win32gui, win32con

TIMEOUT = 90

def find_offline_button():
    result = []
    def walk(h, depth):
        if depth > 4: return
        c = win32gui.GetWindow(h, 5)
        while c:
            try:
                if win32gui.GetClassName(c) == 'Button' and '脱机运行' in win32gui.GetWindowText(c):
                    result.append(c)
            except Exception:
                pass
            walk(c, depth + 1)
            try: c = win32gui.GetWindow(c, 2)
            except Exception: break
    tops = []
    def cb(h, top):
        if win32gui.IsWindowVisible(h):
            tops.append(h)
        return True
    win32gui.EnumWindows(cb, None)
    for h in tops:
        walk(h, 0)
    return result

def main():
    deadline = time.time() + TIMEOUT
    while time.time() < deadline:
        btns = find_offline_button()
        if btns:
            win32gui.SendMessage(btns[0], win32con.BM_CLICK, 0, 0)
            print('clicked offline button', hex(btns[0]), flush=True)
            return 0
        time.sleep(1)
    print('offline button not found in %ds' % TIMEOUT, flush=True)
    return 1

if __name__ == '__main__':
    sys.exit(main())
