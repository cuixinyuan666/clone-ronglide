import time, sys, win32gui, win32con, win32api, ctypes
from PIL import ImageGrab

VK = {'0': 0x30, '1': 0x31, '6': 0x36, '9': 0x39}
WM_KEYDOWN, WM_KEYUP, WM_CHAR = 0x100, 0x101, 0x102
VK_RETURN = 0x0D

def find_main():
    res = []
    def cb(h, _):
        if win32gui.IsWindowVisible(h) and '缠中说禅' in win32gui.GetWindowText(h) and 'RLD' in win32gui.GetClassName(h):
            res.append(h)
    win32gui.EnumWindows(cb, None)
    return res[0] if res else None

def top_windows():
    out = []
    def cb(h, _):
        if win32gui.IsWindowVisible(h):
            t = win32gui.GetWindowText(h)
            if t:
                out.append((hex(h), win32gui.GetClassName(h), t[:60]))
    win32gui.EnumWindows(cb, None)
    return out

def find_dialog(title_part):
    res = []
    def cb(h, _):
        if win32gui.IsWindowVisible(h) and title_part in win32gui.GetWindowText(h):
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

def post_str(hwnd, s, delay=0.08):
    for ch in s:
        vk = VK.get(ch, ord(ch))
        win32gui.PostMessage(hwnd, WM_KEYDOWN, vk, 1)
        time.sleep(0.03)
        win32gui.PostMessage(hwnd, WM_CHAR, ord(ch), 1)
        time.sleep(0.03)
        win32gui.PostMessage(hwnd, WM_KEYUP, vk, 1)
        time.sleep(delay)

def post_enter(hwnd):
    win32gui.PostMessage(hwnd, WM_KEYDOWN, VK_RETURN, 1)
    time.sleep(0.05)
    win32gui.PostMessage(hwnd, WM_KEYUP, VK_RETURN, 1)

def shot(name):
    img = ImageGrab.grab()
    img.save(rf'D:\a_ronglide\clone-ronglide\tools\{name}')
    print('shot', name)

main = find_main()
print('main', hex(main))
print('fg', foreground(main))
time.sleep(0.5)

# step 1: open wizard by first digit
win32gui.PostMessage(main, WM_KEYDOWN, VK['6'], 1)
time.sleep(1.0)
wiz = None
for (h, cls, title) in top_windows():
    if '键盘' in title or ('#32770' in cls and '缠中' not in title):
        wiz = int(h, 16)
        print('wizard candidate:', h, cls, title)
if wiz:
    kids = []
    win32gui.EnumChildWindows(wiz, lambda ch, _: kids.append(ch), None)
    for ch in kids:
        cls = win32gui.GetClassName(ch)
        r = win32gui.GetWindowRect(ch)
        print('  child', hex(ch), cls, repr(win32gui.GetWindowText(ch)), r)
        if cls == 'ListBox':
            n = win32gui.SendMessage(ch, 0x018B, 0, 0)  # LB_GETCOUNT
            print('   listbox count:', n)

# step 2: type remaining and enter, to wizard if found else main
target = wiz if wiz else main
post_str(target, '00000')
time.sleep(0.5)
if wiz:
    kids = [ch for ch in [] ]
    allk = []
    win32gui.EnumChildWindows(wiz, lambda ch, _: allk.append(ch), None)
    for ch in allk:
        if win32gui.GetClassName(ch) == 'ListBox':
            n = win32gui.SendMessage(ch, 0x018B, 0, 0)
            print('listbox count now:', n)
            if n:
                txt = []
                for i in range(min(n, 5)):
                    ln = win32gui.SendMessage(ch, 0x0189, i, 0)  # LB_GETTEXTLEN
                    buf = ctypes.create_unicode_buffer(ln + 1)
                    win32gui.SendMessage(ch, 0x018A, i, ctypes.byref(buf))  # LB_GETTEXT
                    txt.append(buf.value)
                print('  items:', txt)
post_enter(target)
time.sleep(1.5)
shot('_k1.png')

# step 3: switch period 91 (1-minute)
wiz2 = find_dialog('键盘')
target2 = wiz2 if wiz2 else main
post_str(target2, '91')
time.sleep(0.4)
post_enter(target2)
time.sleep(1.5)
shot('_k2.png')

print('-- windows after --')
for w in top_windows():
    print(w)
