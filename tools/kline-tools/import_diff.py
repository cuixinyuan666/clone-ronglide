import os, time, win32gui, win32con, win32api, ctypes

def find_main():
    res = []
    def cb(h, _):
        if win32gui.IsWindowVisible(h) and '缠中说禅' in win32gui.GetWindowText(h):
            if 'RLD' in win32gui.GetClassName(h):
                res.append(h)
    win32gui.EnumWindows(cb, None)
    return res[0] if res else None

def foreground(hwnd):
    for attempt in range(8):
        fg = win32gui.GetForegroundWindow()
        if fg == hwnd:
            return True
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
        time.sleep(0.5)
    return win32gui.GetForegroundWindow() == hwnd

APP = r'D:\a_ronglide\缠中说禅'

def snap(root):
    s = {}
    for dp, dns, fns in os.walk(root):
        for f in fns:
            p = os.path.join(dp, f)
            try:
                st = os.stat(p)
                s[p] = (st.st_mtime, st.st_size)
            except OSError:
                pass
    return s

def diff(a, b, tag):
    for p, v in b.items():
        if p not in a:
            print(f'[{tag}] NEW  {v[1]:>10} {p}')
        elif a[p] != v:
            print(f'[{tag}] CHG  {a[p]} -> {v} {p}')
    for p in a:
        if p not in b:
            print(f'[{tag}] DEL  {p}')

def click(lx, ly, wait=0.6):
    win32api.SetCursorPos((lx, ly)); time.sleep(0.15)
    win32api.mouse_event(win32con.MOUSEEVENTF_LEFTDOWN, 0,0,0,0); time.sleep(0.08)
    win32api.mouse_event(win32con.MOUSEEVENTF_LEFTUP, 0,0,0,0); time.sleep(wait)

main = find_main()
print('main', hex(main))
foreground(main)
time.sleep(0.5)
print('snapshotting...')
a = snap(APP)
print('files:', len(a))

# 找到 import dialog (still open?), else reopen
dlg = None
def find_dlg():
    r = []
    def cb(h, _):
        if win32gui.IsWindowVisible(h) and '数据导入' in win32gui.GetWindowText(h):
            r.append(h)
    win32gui.EnumWindows(cb, None)
    return r[0] if r else None
dlg = find_dlg()
print('dlg', hex(dlg) if dlg else None)
if not dlg:
    raise SystemExit('dialog gone')

# click 导入 again
def btn_click(dlg, label):
    r = []
    def cb(h, _):
        if win32gui.GetClassName(h) == 'Button' and label in win32gui.GetWindowText(h):
            r.append(h)
    win32gui.EnumChildWindows(dlg, cb, None)
    if r:
        win32gui.SendMessage(r[0], win32con.BM_CLICK, 0, 0)
        return True
    return False

print('click 导入:', btn_click(dlg, '导入'))
time.sleep(5)
print('snapshotting 2...')
b = snap(APP)
diff(a, b, 'imp2')

# now start engine (启动) and import again
win32gui.SendMessage(dlg, win32con.WM_CLOSE, 0, 0)
time.sleep(0.8)
rect = win32gui.GetWindowRect(main)
ox, oy = rect[0], rect[1]
print('rect', rect)
click(ox+172, oy+471, 2.5)   # 启动 button offset from old layout
print('clicked 启动')
c = snap(APP)
print('snapshotting 3...')
# reopen dialog
click(ox+210, oy+23, 0.8)    # 系统
click(ox+238, oy+164, 1.2)   # 数据导入
dlg2 = find_dlg()
print('dlg2', hex(dlg2) if dlg2 else None)
if dlg2:
    # set dir again
    e = []
    win32gui.EnumChildWindows(dlg2, lambda h,_: e.append(h) if win32gui.GetClassName(h)=='Edit' else None, None)
    if e:
        win32gui.SendMessage(e[0], win32con.WM_SETTEXT, 0, 'D:\\testimp')
        time.sleep(0.3)
    print('click 导入:', btn_click(dlg2, '导入'))
    time.sleep(5)
    d = snap(APP)
    diff(c, d, 'imp3')
    win32gui.SendMessage(dlg2, win32con.WM_CLOSE, 0, 0)
print('done')
