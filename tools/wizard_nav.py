import time, win32gui, win32con, win32api, ctypes
from PIL import ImageGrab

WM_KEYDOWN, WM_KEYUP, WM_CHAR = 0x100, 0x101, 0x102
VK_RETURN = 0x0D
IDOK = 1

def find_main():
    res = []
    def cb(h, _):
        if win32gui.IsWindowVisible(h) and '缠中说禅' in win32gui.GetWindowText(h) and 'RLD' in win32gui.GetClassName(h):
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

def shot(name):
    img = ImageGrab.grab()
    img.save(rf'D:\a_ronglide\clone-ronglide\tools\{name}')
    print('shot', name)

def wizard_type(text):
    main = find_main()
    win32gui.PostMessage(main, WM_KEYDOWN, 0x41, 1)
    time.sleep(0.8)
    wiz = find_wizard()
    if not wiz:
        print('no wizard')
        return False
    edit = []
    lst = []
    win32gui.EnumChildWindows(wiz, lambda h, _: edit.append(h) if win32gui.GetClassName(h) == 'Edit' else None, None)
    win32gui.EnumChildWindows(wiz, lambda h, _: lst.append(h) if win32gui.GetClassName(h) == 'ListBox' else None, None)
    print(f'wizard={hex(wiz)} edit={[hex(e) for e in edit]} list={[hex(l) for l in lst]}')
    if edit:
        ctypes.windll.user32.SendMessageW(edit[0], win32con.WM_SETTEXT, 0, text)
        time.sleep(0.8)
    if lst:
        n = win32gui.SendMessage(lst[0], 0x018B, 0, 0)
        print('listbox count:', n)
        if n > 0:
            sz = win32gui.SendMessage(lst[0], 0x0189, 0, 0)
            buf = ctypes.create_unicode_buffer(sz + 1)
            win32gui.SendMessage(lst[0], 0x018A, 0, ctypes.byref(buf))
            print('first item:', buf.value)
            win32gui.SendMessage(lst[0], 0x0186, 0, 0)  # LB_SETCURSEL 0
    # try enter on edit and dialog
    if edit:
        win32gui.PostMessage(edit[0], WM_KEYDOWN, VK_RETURN, 1)
        win32gui.PostMessage(edit[0], WM_KEYUP, VK_RETURN, 1)
    time.sleep(0.4)
    if find_wizard():
        win32gui.PostMessage(wiz, WM_COMMAND, IDOK, 0)
        time.sleep(0.4)
    if find_wizard():
        win32gui.PostMessage(wiz, WM_KEYDOWN, VK_RETURN, 1)
        win32gui.PostMessage(wiz, WM_KEYUP, VK_RETURN, 1)
    time.sleep(0.8)
    return not find_wizard()

main = find_main()
print('main', hex(main), win32gui.GetWindowRect(main))
print('fg', foreground(main))
time.sleep(0.5)

print('--- type 600000 ---')
print('closed:', wizard_type('600000'))
time.sleep(1.0)
shot('_w1.png')

print('--- type 91 ---')
print('closed:', wizard_type('91'))
time.sleep(1.5)
shot('_w2.png')

# dump main child structure to detect page change
kids = []
win32gui.EnumChildWindows(main, lambda ch, _: kids.append(ch), None)
print('main children now:')
for ch in kids:
    cls = win32gui.GetClassName(ch)
    txt = win32gui.GetWindowText(ch)
    r = win32gui.GetWindowRect(ch)
    print(f'  {hex(ch)} [{cls}] {txt!r} {r}')
