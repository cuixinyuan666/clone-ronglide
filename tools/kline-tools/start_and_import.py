import os, time, win32gui, win32con, win32api, ctypes
from PIL import ImageGrab

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

main = find_main()
print('main', hex(main))
rect = win32gui.GetWindowRect(main)
ox, oy = rect[0], rect[1]
print('rect', rect)
ctypes.windll.user32.SetWindowPos(main, -1, 0,0,0,0, 0x0001|0x0002|0x0010)

# click 启动 (bottom-left, offset 8,471)
click(ox+8, oy+471, 2.5)
shot('_start_clicked.png')

# open import dialog via menu
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
    print('click 导入:', btn_click(dlg, '导入'))
    time.sleep(6)
    st = []
    win32gui.EnumChildWindows(dlg, lambda h,_: st.append(win32gui.GetWindowText(h)) if win32gui.GetClassName(h)=='Static' else None, None)
    print('statics:', [s for s in st])
    win32gui.PostMessage(dlg, win32con.WM_CLOSE, 0, 0)
shot('_after_reimport.png')
print('done')
