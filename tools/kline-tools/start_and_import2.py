import os, time, win32gui, win32con, win32api, ctypes
from PIL import Image, ImageGrab

def find_by_title(sub):
    res = []
    def cb(h, _):
        if win32gui.IsWindowVisible(h) and sub in win32gui.GetWindowText(h):
            res.append(h)
    win32gui.EnumWindows(cb, None)
    return res

def find_main():
    res = []
    def cb(h, _):
        if win32gui.IsWindowVisible(h) and '缠中说禅' in win32gui.GetWindowText(h):
            if 'RLD' in win32gui.GetClassName(h):
                res.append(h)
    win32gui.EnumWindows(cb, None)
    return res[0] if res else None

def click(lx, ly, wait=0.7):
    win32api.SetCursorPos((lx, ly)); time.sleep(0.15)
    win32api.mouse_event(win32con.MOUSEEVENTF_LEFTDOWN, 0,0,0,0); time.sleep(0.08)
    win32api.mouse_event(win32con.MOUSEEVENTF_LEFTUP, 0,0,0,0); time.sleep(wait)

def shot(name):
    ImageGrab.grab().save(rf'D:\a_ronglide\clone-ronglide\tools\{name}')

def find_dlg():
    r = []
    def cb(h, _):
        if win32gui.IsWindowVisible(h) and '数据导入' in win32gui.GetWindowText(h):
            r.append(h)
    win32gui.EnumWindows(cb, None)
    return r[0] if r else None

def btn_click(dlg, label):
    r = []
    win32gui.EnumChildWindows(dlg, lambda h,_: r.append(h) if (win32gui.GetClassName(h)=='Button' and label in win32gui.GetWindowText(h)) else None, None)
    if r:
        win32gui.SendMessage(r[0], win32con.BM_CLICK, 0, 0)
        return True
    return False

# 1. minimize blockers
blockers = []
for sub in ['OpenCode', 'WorkBuddy']:
    for h in find_by_title(sub):
        win32gui.ShowWindow(h, win32con.SW_MINIMIZE)
        blockers.append(h)
print('minimized:', [hex(b) for b in blockers])
time.sleep(1)

# 2. bring app forward, normal size, topmost (mousedown activates)
main = find_main()
print('main', hex(main))
win32gui.ShowWindow(main, win32con.SW_RESTORE)
time.sleep(0.5)
ctypes.windll.user32.SetWindowPos(main, -1, 0, 0, 0, 0, 0x0001 | 0x0002 | 0x0010)
time.sleep(0.8)
print('fg now', hex(win32gui.GetForegroundWindow()))
rect = win32gui.GetWindowRect(main)
ox, oy = rect[0], rect[1]
print('rect', rect)
shot('_prestart.png')

# 3. click 启动 (bottom bar, offset from window origin: (57, 441))
click(ox+57, oy+441, 2.0)
img = ImageGrab.grab()
img.save(r'D:\a_ronglide\clone-ronglide\tools\_after_start2.png')
crop = img.crop((40, 880, 700, 950)).resize((660*3, 70*3), Image.LANCZOS)
crop.save(r'D:\a_ronglide\clone-ronglide\tools\_bar_zoom3.png')

# 4. import
click(ox+210, oy+23, 0.8)
shot('_menu3.png')
click(ox+238, oy+164, 1.5)
dlg = find_dlg()
print('dlg', hex(dlg) if dlg else None)
if dlg:
    e = []
    win32gui.EnumChildWindows(dlg, lambda h,_: e.append(h) if win32gui.GetClassName(h)=='Edit' else None, None)
    if e:
        ctypes.windll.user32.SendMessageW(e[0], win32con.WM_SETTEXT, 0, 'D:\\testimp')
        time.sleep(0.3)
    print('click 导入:', btn_click(dlg, '导入'))
    time.sleep(6)
    st = []
    win32gui.EnumChildWindows(dlg, lambda h,_: st.append(win32gui.GetWindowText(h)) if win32gui.GetClassName(h)=='Static' else None, None)
    print('statics:', [s for s in st])
    win32gui.PostMessage(dlg, win32con.WM_CLOSE, 0, 0)
shot('_after_reimport2.png')

# 5. restore blockers
for b in blockers:
    try:
        win32gui.ShowWindow(b, win32con.SW_RESTORE)
    except Exception:
        pass
print('restored blockers')
