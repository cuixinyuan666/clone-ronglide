import time, win32gui, win32con, win32api, ctypes
from PIL import ImageGrab

def find_main():
    res = []
    def cb(h, _):
        if win32gui.IsWindowVisible(h) and '缠中说禅' in win32gui.GetWindowText(h) and 'RLD' in win32gui.GetClassName(h):
            res.append(h)
    win32gui.EnumWindows(cb, None)
    return res[0] if res else None

def foreground(hwnd):
    for attempt in range(8):
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

def click(lx, ly, wait=0.6):
    win32api.SetCursorPos((lx, ly)); time.sleep(0.15)
    win32api.mouse_event(win32con.MOUSEEVENTF_LEFTDOWN, 0,0,0,0); time.sleep(0.08)
    win32api.mouse_event(win32con.MOUSEEVENTF_LEFTUP, 0,0,0,0); time.sleep(wait)

def shot(name):
    img = ImageGrab.grab()
    img.save(rf'D:\a_ronglide\clone-ronglide\tools\{name}')
    print('shot', name)

def find_dlg():
    r = []
    def cb(h, _):
        if win32gui.IsWindowVisible(h) and '数据导入' in win32gui.GetWindowText(h):
            r.append(h)
    win32gui.EnumWindows(cb, None)
    return r[0] if r else None

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

# minimize blockers
for title in ('OpenCode', 'WorkBuddy'):
    res = []
    win32gui.EnumWindows(lambda h, _: res.append(h) if win32gui.IsWindowVisible(h) and win32gui.GetWindowText(h) == title else None, None)
    for h in res:
        win32gui.ShowWindow(h, win32con.SW_MINIMIZE)

main = find_main()
print('main', hex(main), win32gui.GetWindowRect(main))
print('fg', foreground(main))
rect = win32gui.GetWindowRect(main)
ox, oy = rect[0], rect[1]
print('rect', rect)

dlg = find_dlg()
if not dlg:
    click(ox+210, oy+23, 0.8)
    click(ox+238, oy+164, 1.5)
    dlg = find_dlg()
print('dlg', hex(dlg) if dlg else None)
if dlg:
    e = []
    win32gui.EnumChildWindows(dlg, lambda h,_: e.append(h) if win32gui.GetClassName(h)=='Edit' else None, None)
    if e:
        ctypes.windll.user32.SendMessageW(e[0], win32con.WM_SETTEXT, 0, 'D:\\testimp')
        time.sleep(0.3)
        print('edit set')
    print('click 导入:', btn_click(dlg, '导入'))
    time.sleep(8)
    st = []
    win32gui.EnumChildWindows(dlg, lambda h,_: st.append(win32gui.GetWindowText(h)) if win32gui.GetClassName(h)=='Static' else None, None)
    print('statics:', st)
    win32gui.PostMessage(dlg, win32con.WM_CLOSE, 0, 0)
    print('closed dlg')

# go to 技术 page and select 1分钟
time.sleep(1)
click(ox+38, oy+231, 2.0)   # 技术 nav (64,257) for normal window
shot('_after_imp1.png')
click(ox+99, oy+73, 2.5)    # 1分钟 (125,99) for normal window
shot('_after_imp2.png')
