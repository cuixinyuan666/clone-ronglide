import time, sys, os, subprocess, win32gui, win32con, ctypes
from PIL import ImageGrab

APP_DIR = r'D:\a_ronglide\缠中说禅'

def kill_old():
    try:
        import frida
        dev = frida.get_local_device()
        for p in dev.enumerate_processes():
            if p.name.lower() == 'mainapp.exe' and p.pid != 7920:
                subprocess.run(['taskkill', '/F', '/PID', str(p.pid)], capture_output=True)
                print('killed', p.pid, flush=True)
    except Exception as e:
        print('kill via frida failed:', e, flush=True)
        subprocess.run(['taskkill', '/F', '/IM', 'MainApp.exe'], capture_output=True)
    time.sleep(2)

def find_windows(filter_fn):
    res = []
    def cb(h, _):
        try:
            if win32gui.IsWindowVisible(h) and filter_fn(h):
                res.append(h)
        except Exception:
            pass
    win32gui.EnumWindows(cb, None)
    return res

def close_welcome():
    for h in find_windows(lambda h: win32gui.GetClassName(h) == '#32770' and '欢迎' in win32gui.GetWindowText(h)):
        win32gui.PostMessage(h, win32con.WM_CLOSE, 0, 0)
        print('closed welcome', hex(h), flush=True)

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
    win32gui.EnumWindows(lambda h, _: tops.append(h) if win32gui.IsWindowVisible(h) else None, None)
    for h in tops:
        walk(h, 0)
    return result

def main():
    kill_old()
    print('starting MainApp...', flush=True)
    subprocess.Popen([os.path.join(APP_DIR, 'MainApp.exe')], cwd=APP_DIR)
    deadline = time.time() + 90
    logged_in = False
    while time.time() < deadline:
        close_welcome()
        if not logged_in:
            btns = find_offline_button()
            if btns:
                win32gui.SendMessage(btns[0], win32con.BM_CLICK, 0, 0)
                print('clicked offline', hex(btns[0]), flush=True)
                logged_in = True
        mains = find_windows(lambda h: 'CLASSNAME_RLD_CZSC_MAINAPP' == win32gui.GetClassName(h))
        if mains and logged_in:
            time.sleep(3)
            for m in mains:
                print('main window', hex(m), win32gui.GetWindowRect(m), repr(win32gui.GetWindowText(m)), flush=True)
            img = ImageGrab.grab()
            img.save(r'D:\a_ronglide\clone-ronglide\tools\_restarted.png')
            print('saved _restarted.png', flush=True)
            return 0
        time.sleep(1)
    print('TIMEOUT', flush=True)
    return 1

if __name__ == '__main__':
    sys.exit(main())
