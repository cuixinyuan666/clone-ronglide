import time, ctypes
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
  },
  onLeave: function (retval) {
    if (LOG.length < 500) LOG.push('count  RET=' + retval.toInt32());
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

def wizard_cmd(text):
    main = find_main()
    win32gui.PostMessage(main, 0x100, 0x39, 1)
    time.sleep(1.0)
    wiz = find_wizard()
    if not wiz:
        print('no wizard'); return False
    edit, lst = [], []
    win32gui.EnumChildWindows(wiz, lambda h, _: edit.append(h) if win32gui.GetClassName(h) == 'Edit' else None, None)
    win32gui.EnumChildWindows(wiz, lambda h, _: lst.append(h) if win32gui.GetClassName(h) == 'ListBox' else None, None)
    ctypes.windll.user32.SendMessageW(edit[0], win32con.WM_SETTEXT, 0, text)
    time.sleep(1.0)
    n = win32gui.SendMessage(lst[0], 0x018B, 0, 0)
    print(f'wizard "{text}": count={n}', flush=True)
    ok = False
    if n > 0:
        win32gui.SendMessage(lst[0], 0x0186, 0, 0)
        time.sleep(0.2)
        win32gui.PostMessage(edit[0], 0x100, 0x0D, 1)
        win32gui.PostMessage(edit[0], 0x101, 0x0D, 1)
        time.sleep(0.8)
        if find_wizard():
            win32gui.PostMessage(wiz, win32con.WM_COMMAND, 1, 0)
            time.sleep(0.8)
        ok = not find_wizard()
    return ok

dev = frida.get_local_device()
pid = [p.pid for p in dev.enumerate_processes() if p.name.lower() == 'mainapp.exe' and p.pid != 7920][0]
session = frida.attach(pid)
script = session.create_script(JS)
script.load()
api = script.exports_sync
print('hooked pid', pid, flush=True)
time.sleep(0.8)

api.clear()
print('=== switch 5min (92) ===', flush=True)
wizard_cmd('92')
time.sleep(3.0)
for line in api.getlog(): print('5m:', line)
img = ImageGrab.grab(); img.save(r'D:\a_ronglide\clone-ronglide\tools\_sw92.png')

api.clear()
print('=== switch 1min (91) ===', flush=True)
wizard_cmd('91')
time.sleep(3.0)
for line in api.getlog(): print('1m:', line)
img = ImageGrab.grab(); img.save(r'D:\a_ronglide\clone-ronglide\tools\_sw91.png')
print('saved shots', flush=True)
session.detach()
