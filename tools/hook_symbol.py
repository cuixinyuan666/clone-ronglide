import time, ctypes, sys
import win32gui, win32con
import frida
from PIL import ImageGrab

JS = r'''
var RQD = Process.getModuleByName('rquo.dll');
var LOG = [];
function readSym(p) {
  try {
    var m = p.readU8();
    var code = p.add(8).readCString();
    if (code && code.length >= 1 && m >= 0 && m < 20) return 'm' + m + '/' + code;
  } catch (e) {}
  return null;
}
function candidates(args) {
  var out = [];
  var ps = [args[0], args[1], args[2], args[3]];
  for (var i = 0; i < ps.length; i++) {
    var s = readSym(ps[i]);
    if (s) out.push('[' + i + ']' + s);
  }
  return out.join(' ');
}
Interceptor.attach(RQD.base.add(0x4dcc0), {
  onEnter: function (args) {
    if (LOG.length < 500) LOG.push('count  a0=' + args[0] + ' a1=' + args[1] + ' a2=' + args[2] + ' a3=' + args[3] + ' syms:' + candidates(args));
  }
});
Interceptor.attach(RQD.base.add(0x4ddd0), {
  onEnter: function (args) {
    if (LOG.length < 500) LOG.push('bypos  a1=' + args[1] + ' a2=' + args[2] + ' a3=' + args[3] + ' a4=' + args[4] + ' a5=' + args[5] + ' syms:' + candidates(args));
  },
  onLeave: function (retval) {
    if (retval.toInt32() !== 0 && LOG.length < 500) LOG.push('bypos  RET=' + retval.toInt32() + ' (0x' + (retval.toInt32() >>> 0).toString(16) + ')');
  }
});
rpc.exports = { getlog: function () { return LOG; }, clear: function () { LOG = []; } };
'''

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

def wizard_command(text):
    main = find_main()
    win32gui.PostMessage(main, 0x100, 0x39, 1)
    time.sleep(1.0)
    wiz = find_wizard()
    if not wiz:
        print('no wizard opened')
        return
    edit, lst = [], []
    win32gui.EnumChildWindows(wiz, lambda h, _: edit.append(h) if win32gui.GetClassName(h) == 'Edit' else None, None)
    win32gui.EnumChildWindows(wiz, lambda h, _: lst.append(h) if win32gui.GetClassName(h) == 'ListBox' else None, None)
    ctypes.windll.user32.SendMessageW(edit[0], win32con.WM_SETTEXT, 0, text)
    time.sleep(1.0)
    n = win32gui.SendMessage(lst[0], 0x018B, 0, 0)
    print(f'wizard "{text}" listbox count={n}')
    if n > 0:
        win32gui.SendMessage(lst[0], 0x0186, 0, 0)
        time.sleep(0.2)
        win32gui.PostMessage(edit[0], 0x100, 0x0D, 1)
        win32gui.PostMessage(edit[0], 0x101, 0x0D, 1)
        time.sleep(0.5)
        if find_wizard():
            win32gui.PostMessage(wiz, win32con.WM_COMMAND, 1, 0)
            time.sleep(0.5)
        if find_wizard():
            win32gui.PostMessage(wiz, 0x100, 0x0D, 1)
            win32gui.PostMessage(wiz, 0x101, 0x0D, 1)
    time.sleep(1.5)
    print('wizard still open:', bool(find_wizard()))

main = find_main()
print('main', hex(main), flush=True)
foreground(main)
time.sleep(0.5)

dev = frida.get_local_device()
pid = [p.pid for p in dev.enumerate_processes() if p.name.lower() == 'mainapp.exe' and p.pid != 7920][0]
session = frida.attach(pid)
script = session.create_script(JS)
script.load()
api = script.exports_sync
print('hooks installed on pid', pid, flush=True)

time.sleep(1.0)
api.clear()
print('=== trigger 91 (1min K-line) ===', flush=True)
wizard_command('91')
time.sleep(3.0)

log = api.getlog()
print(f'--- log entries: {len(log)} ---')
for line in log:
    print(line)

img = ImageGrab.grab()
img.save(r'D:\a_ronglide\clone-ronglide\tools\_sym_diag.png')
print('shot _sym_diag.png', flush=True)
session.detach()
print('done', flush=True)
