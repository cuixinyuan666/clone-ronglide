import win32gui, win32con, win32api, time, ctypes, ctypes.wintypes as wt
from PIL import ImageGrab

MAIN_TITLE = '缠中说禅'

def find_main():
    res = []
    def cb(h, _):
        if win32gui.IsWindowVisible(h) and MAIN_TITLE in win32gui.GetWindowText(h):
            cls = win32gui.GetClassName(h)
            if 'RLD' in cls:
                res.append(h)
    win32gui.EnumWindows(cb, None)
    return res[0] if res else None

def foreground(hwnd):
    fg = win32gui.GetForegroundWindow()
    t1 = ctypes.windll.kernel32.GetCurrentThreadId()
    t2 = ctypes.windll.user32.GetWindowThreadProcessId(fg, None)
    ctypes.windll.user32.AttachThreadInput(t1, t2, True)
    try:
        win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
        win32gui.SetForegroundWindow(hwnd)
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
    print('saved', name, img.size)

main = find_main()
print('main', hex(main) if main else None)
if not main:
    raise SystemExit(1)
print('fg ok', foreground(main))
rect = win32gui.GetWindowRect(main)
print('rect', rect)
ox, oy = rect[0], rect[1]

# 系统 menu (offset 210,23)
click(ox+210, oy+23)
time.sleep(0.5)
shot('_imp_menu.png')

# 数据导入 item (offset 238,164)
click(ox+238, oy+164)
time.sleep(1.0)
shot('_imp_dlg.png')

# find dialog
dlg = None
def find_dlg():
    r = []
    def cb(h, _):
        if win32gui.IsWindowVisible(h):
            t = win32gui.GetWindowText(h)
            if '数据导入' in t:
                r.append(h)
    win32gui.EnumWindows(cb, None)
    return r[0] if r else None
dlg = find_dlg()
print('dlg', hex(dlg) if dlg else None)
if not dlg:
    print('dialog not found, abort')
    raise SystemExit(2)

children = []
def enum_cb(h, _):
    cls = win32gui.GetClassName(h)
    txt = win32gui.GetWindowText(h)
    r = win32gui.GetWindowRect(h)
    children.append((h, cls, txt, r))
win32gui.EnumChildWindows(dlg, enum_cb, None)
for h, cls, txt, r in children:
    print(hex(h), cls, repr(txt), r)

edit = None
btns = []
for h, cls, txt, r in children:
    if cls == 'Edit' and edit is None:
        edit = h
    if cls == 'Button':
        btns.append((h, txt, r))
print('edit', hex(edit) if edit else None)
if edit:
    win32gui.SendMessage(edit, win32con.WM_SETTEXT, 0, 'D:\\testimp')
    time.sleep(0.3)
    print('edit text now:', repr(win32gui.GetWindowText(edit)))

# click 导入 button
imp = None
for h, txt, r in btns:
    if '导入' in txt:
        imp = h
        break
print('导入 btn', hex(imp) if imp else None, [t for _, t, _ in btns])
if imp:
    win32gui.SendMessage(imp, win32con.BM_CLICK, 0, 0)
    print('clicked 导入')
time.sleep(4.0)
shot('_imp_after.png')

# re-enumerate for result messages
children2 = []
win32gui.EnumChildWindows(dlg, lambda h, _: children2.append((h, win32gui.GetClassName(h), win32gui.GetWindowText(h))), None)
for h, cls, txt in children2:
    if cls == 'Static' and txt:
        print('STATIC:', repr(txt))
