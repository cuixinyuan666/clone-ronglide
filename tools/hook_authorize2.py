# -*- coding: utf-8 -*-
"""扩大观测: 所有 app 模块的 Authorize/License 类导出 + 权限提示弹窗 — 纯观察"""
import frida, sys, time, ctypes

PID = int(sys.argv[1]) if len(sys.argv) > 1 else 13192

JS = r'''
// only hook modules that live in the app folder
const appMods = Process.enumerateModules().filter(m =>
    m.path.toLowerCase().indexOf('a_ronglide') >= 0 ||
    ['mainapp.exe','taflib.dll','rdm_c.dll','rdm.dll','rquo.dll'].indexOf(m.name.toLowerCase()) >= 0
);
send('app modules: ' + appMods.map(m => m.name + '@' + m.base).join(', '));

let hookCount = 0;
const rx = /authorize|licen|permit|vip|auth_|_auth/i;
appMods.forEach(m => {
  let exps = [];
  try { exps = m.enumerateExports(); } catch (e) { return; }
  exps.forEach(e => {
    if (e.type !== 'function') return;
    if (!rx.test(e.name)) return;
    // skip if mangled name contains 'Authorize' generic svchost-ish? keep all app ones
    hookCount++;
    const addr = e.address;
    const tag = m.name + '!' + e.name;
    try {
      Interceptor.attach(addr, {
        onEnter(args) {
          this.t0 = Date.now();
          this.tag = tag;
          send('[HIT] enter ' + tag + ' a0=' + (args[0] ? args[0].toInt32() : 'n/a')
               + ' ecx=' + this.context.ecx);
        },
        onLeave(rv) { send('[HIT] leave ' + this.tag + ' ret=' + rv.toInt32()); }
      });
      send('hooked ' + tag + ' @ ' + addr);
    } catch (err) {
      send('hook-fail ' + tag + ': ' + err);
    }
  });
});
send('total hooks: ' + hookCount);
'''

logs = []
def on_message(msg, data):
    t = msg.get('payload', str(msg))
    logs.append(t)
    print(t)
    sys.stdout.flush()

session = frida.attach(PID)
script = session.create_script(JS)
script.on('message', on_message)
script.load()
print('--- hooks installed ---')

import win32gui, win32con
u32 = ctypes.windll.user32
u32.SetProcessDPIAware()

def find_main():
    res = []
    def cb(h, _):
        if win32gui.IsWindowVisible(h) and '缠中说禅' in win32gui.GetWindowText(h) and 'RLD' in win32gui.GetClassName(h):
            res.append(h)
    win32gui.EnumWindows(cb, None)
    return res[0] if res else None

def foreground(h):
    for attempt in range(10):
        if u32.GetForegroundWindow() == h:
            return True
        fg = u32.GetForegroundWindow()
        t1 = ctypes.windll.kernel32.GetCurrentThreadId()
        t2 = u32.GetWindowThreadProcessId(fg, None)
        u32.AttachThreadInput(t1, t2, True)
        try:
            win32gui.ShowWindow(h, win32con.SW_RESTORE)
            win32gui.ShowWindow(h, win32con.SW_SHOWMAXIMIZED)
            try: win32gui.SetForegroundWindow(h)
            except Exception: pass
            if u32.GetForegroundWindow() != h:
                u32.SwitchToThisWindow(h, True)
        finally:
            u32.AttachThreadInput(t1, t2, False)
        time.sleep(0.5)
    return u32.GetForegroundWindow() == h

main = find_main()
print('main', hex(main) if main else None, 'fg ok:', foreground(main))
time.sleep(0.5)

# dismiss any existing dialog first (click 取消)
def click(x, y, wait=1.2):
    u32.SetCursorPos(int(x), int(y))
    time.sleep(0.3)
    u32.mouse_event(2, 0, 0, 0, 0)
    time.sleep(0.1)
    u32.mouse_event(4, 0, 0, 0, 0)
    time.sleep(wait)

click(1196, 871)   # 取消 (if dialog open)
click(594, 33)     # 缠论
click(735, 650)    # 无脑买入线段
time.sleep(2.5)

from PIL import ImageGrab
ImageGrab.grab().save(r'D:\a_ronglide\clone-ronglide\tools\_hook_auth2.png')
print('--- screenshot saved ---')
time.sleep(0.5)
script.unload()
session.detach()
print('--- detached, %d log lines ---' % len(logs))
