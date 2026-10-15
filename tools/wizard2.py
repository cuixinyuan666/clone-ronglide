import time, win32gui, win32con, win32api, ctypes
from PIL import ImageGrab

WM_KEYDOWN, WM_KEYUP = 0x100, 0x101
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

def listbox_dump(lst):
    n = win32gui.SendMessage(lst, 0x018B, 0, 0)
    items = []
    for i in range(min(n, 8)):
        sz = win32gui.SendMessage(lst, 0x0189, i, 0)
        buf = ctypes.create_unicode_buffer(max(sz + 1, 128))
        win32gui.SendMessage(lst, 0x018A, i, buf)
        items.append(buf.value)
    return n, items

def wizard_command(text):
    main = find_main()
    win32gui.PostMessage(main, WM_KEYDOWN, 0x39, 1)  # '9' to open wizard
    time.sleep(1.0)
    wiz = find_wizard()
    if not wiz:
        print('no wizard opened')
        return
    edit, lst = [], []
    win32gui.EnumChildWindows(wiz, lambda h, _: edit.append(h) if win32gui.GetClassName(h) == 'Edit' else None, None)
    win32gui.EnumChildWindows(wiz, lambda h, _: lst.append(h) if win32gui.GetClassName(h) == 'ListBox' else None, None)
    print('wizard', hex(wiz), 'edit', [hex(e) for e in edit], 'list', [hex(l) for l in lst])
    ctypes.windll.user32.SendMessageW(edit[0], win32con.WM_SETTEXT, 0, text)
    time.sleep(1.0)
    n, items = listbox_dump(lst[0])
    print(f'after set "{text}": listbox count={n}')
    for it in items:
        print('   item:', repr(it))
    if n > 0:
        win32gui.SendMessage(lst[0], 0x0186, 0, 0)  # LB_SETCURSEL 0
        time.sleep(0.2)
        win32gui.PostMessage(edit[0], WM_KEYDOWN, VK_RETURN, 1)
        win32gui.PostMessage(edit[0], WM_KEYUP, VK_RETURN, 1)
        time.sleep(0.5)
        if find_wizard():
            win32gui.PostMessage(wiz, WM_COMMAND, IDOK, 0)
            time.sleep(0.5)
        if find_wizard():
            win32gui.PostMessage(wiz, WM_KEYDOWN, VK_RETURN, 1)
            win32gui.PostMessage(wiz, WM_KEYUP, VK_RETURN, 1)
    time.sleep(1.0)
    print('wizard still open:', bool(find_wizard()))

main = find_main()
print('main', hex(main), win32gui.GetWindowRect(main))
print('fg', foreground(main))
time.sleep(0.5)

print('=== command 91 ===')
wizard_command('91')
time.sleep(2.0)
shot('_wz91.png')

print('=== symbol 600000 ===')
wizard_command('600000')
time.sleep(2.0)
shot('_wz600000.png')
