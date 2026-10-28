# -*- coding: utf-8 -*-
"""wf.py — 窗口焦点 + 点击 通用工具
用法:
  python wf.py focus                  # 把缠中说禅拉到前台(最小化持焦的其它窗口)
  python wf.py click X Y [X Y ...]    # 每次点击前确保前台
  python wf.py shot NAME [crop x1 y1 x2 y2]
"""
import sys, time, ctypes
import win32gui, win32con
from PIL import Image, ImageGrab

u32 = ctypes.windll.user32
u32.SetProcessDPIAware()

def find_main():
    res = []
    def cb(h, _):
        if win32gui.IsWindowVisible(h) and '缠中说禅' in win32gui.GetWindowText(h) and 'RLD' in win32gui.GetClassName(h):
            res.append(h)
    win32gui.EnumWindows(cb, None)
    return res[0] if res else None

def force_focus():
    main = find_main()
    if not main:
        return None
    # 主进程 pid: 属于同进程的窗口(对话框)不做最小化
    app_pid = ctypes.c_ulong(0)
    u32.GetWindowThreadProcessId(main, ctypes.byref(app_pid))
    app_pid = app_pid.value
    for _ in range(12):
        fg = u32.GetForegroundWindow()
        if fg == main:
            return main
        fg_pid = ctypes.c_ulong(0)
        if fg:
            u32.GetWindowThreadProcessId(fg, ctypes.byref(fg_pid))
        if fg and fg_pid.value == app_pid:
            # 前台是应用自己的窗口/对话框 → 应用已激活, 直接返回
            return main
        if fg and fg != main:
            t = win32gui.GetWindowText(fg)
            if t and win32gui.GetWindowLong(fg, -16) & 0x40000000 == 0:
                try:
                    win32gui.ShowWindow(fg, win32con.SW_MINIMIZE)
                except Exception:
                    pass
        time.sleep(0.3)
        fg = u32.GetForegroundWindow()
        t1 = ctypes.windll.kernel32.GetCurrentThreadId()
        t2 = u32.GetWindowThreadProcessId(fg, None)
        u32.AttachThreadInput(t1, t2, True)
        try:
            win32gui.ShowWindow(main, win32con.SW_RESTORE)
            win32gui.ShowWindow(main, win32con.SW_SHOWMAXIMIZED)
            try:
                win32gui.SetForegroundWindow(main)
            except Exception:
                pass
            if u32.GetForegroundWindow() != main:
                u32.SwitchToThisWindow(main, True)
        finally:
            u32.AttachThreadInput(t1, t2, False)
        time.sleep(0.4)
    return main if u32.GetForegroundWindow() == main else None

def click(x, y, wait=1.2):
    u32.SetCursorPos(int(x), int(y))
    time.sleep(0.3)
    u32.mouse_event(2, 0, 0, 0, 0)
    time.sleep(0.1)
    u32.mouse_event(4, 0, 0, 0, 0)
    time.sleep(wait)

OUT = r'D:\a_ronglide\clone-ronglide\tools'

if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'focus'
    if cmd == 'focus':
        m = force_focus()
        print('focus ok:', m is not None, hex(m) if m else '')
    elif cmd == 'click':
        nums = sys.argv[2:]
        pts = [(int(nums[i]), int(nums[i+1])) for i in range(0, len(nums), 2)]
        m = force_focus()          # 只在整串开始时抢一次焦点
        if not m:
            print('FOCUS FAILED'); sys.exit(2)
        print('focus ok', hex(m))
        for (x, y) in pts:
            click(x, y, wait=0.8)
            print('clicked', (x, y))
    elif cmd == 'shot':
        name = sys.argv[2]
        img = ImageGrab.grab()
        img.save(rf'{OUT}\{name}')
        print('shot', name, img.size)
        if len(sys.argv) >= 7:
            x1, y1, x2, y2 = map(int, sys.argv[3:7])
            img.crop((x1, y1, x2, y2)).save(rf'{OUT}\{name.replace(".png", "_crop.png")}')
            print('cropped', (x1, y1, x2, y2))
