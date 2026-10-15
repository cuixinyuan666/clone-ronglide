# -*- coding: utf-8 -*-
"""纯观测 frida hook: Authorize / wnwrnew 调用链 (不修改任何返回值)"""
import frida, sys, time, ctypes

PID = int(sys.argv[1]) if len(sys.argv) > 1 else 13192

JS = r'''
const mods = Process.enumerateModules();
const taflib = mods.find(m => m.name.toLowerCase() === 'taflib.dll');
const rdmc   = mods.find(m => m.name.toLowerCase() === 'rdm_c.dll');
const main   = mods.find(m => m.name.toLowerCase() === 'mainapp.exe');
send('MOD taflib=' + (taflib ? taflib.base : 'NONE')
   + ' rdm_c=' + (rdmc ? rdmc.base : 'NONE')
   + ' mainapp=' + (main ? main.base : 'NONE'));

function bt(ctx, depth) {
  try {
    return Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, depth)
      .map(a => a.toString()).join(' <- ');
  } catch (e) { return 'bt-err'; }
}

if (taflib) {
  const AUTH = taflib.base.add(0x14e60);       // ?Authorize@TAF_Calculator@@IAE_NI@Z
  Interceptor.attach(AUTH, {
    onEnter(args) {
      this.ecx = this.context.ecx;
      this.a0 = args[0].toInt32();
      this.a1 = args[1].toInt32();
      send('[AUTH] enter ecx=' + this.ecx + ' args0=' + this.a0
         + ' args1=' + this.a1 + '\n   from ' + this.returnAddress
         + '\n   ' + bt(this.context, 6));
    },
    onLeave(rv) { send('[AUTH] leave ret=' + rv.toInt32()); }
  });
  send('hooked TAF_Calculator::Authorize');

  const WNMR = taflib.base.add(0x11ee0);       // ?CalcProc_wnmrnew
  Interceptor.attach(WNMR, {
    onEnter(args) {
      this.ecx = this.context.ecx;
      send('[WNMRNEW] enter ecx=' + this.ecx + ' a0=' + args[0].toInt32()
         + ' a1=' + args[1] + ' a2=' + args[2]
         + '\n   ' + bt(this.context, 6));
    },
    onLeave(rv) { send('[WNMRNEW] leave ret=' + rv.toInt32()); }
  });
  send('hooked CalcProc_wnmrnew');

  const CHBI = taflib.base.add(0xf580);        // ?CalcProc_ChBi
  Interceptor.attach(CHBI, {
    onEnter(args) { send('[CHBI] enter ecx=' + this.context.ecx + ' a0=' + args[0].toInt32()); },
    onLeave(rv)   { send('[CHBI] leave ret=' + rv.toInt32()); }
  });
  send('hooked CalcProc_ChBi');
}

if (rdmc) {
  const AAPI = rdmc.base.add(0x6f1f0);         // ?Authorize@AuthApi@@SA_NI@Z
  Interceptor.attach(AAPI, {
    onEnter(args) { send('[AuthApi] enter a0=' + args[0].toInt32() + '\n   ' + bt(this.context, 6)); },
    onLeave(rv)   { send('[AuthApi] leave ret=' + rv.toInt32()); }
  });
  send('hooked AuthApi::Authorize');
}
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
print('--- hooks installed, triggering 缠论->无脑买入线段 ---')

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
            try:
                win32gui.SetForegroundWindow(h)
            except Exception:
                pass
            if u32.GetForegroundWindow() != h:
                u32.SwitchToThisWindow(h, True)
        finally:
            u32.AttachThreadInput(t1, t2, False)
        time.sleep(0.5)
    return u32.GetForegroundWindow() == h

main = find_main()
print('main', hex(main) if main else None, 'fg ok:', foreground(main))
time.sleep(0.5)

def click(x, y, wait=1.2):
    u32.SetCursorPos(int(x), int(y))
    time.sleep(0.3)
    u32.mouse_event(2, 0, 0, 0, 0)
    time.sleep(0.1)
    u32.mouse_event(4, 0, 0, 0, 0)
    time.sleep(wait)

click(594, 33)    # 缠论 menu
click(735, 650)   # 无脑买入线段
time.sleep(2.5)

from PIL import ImageGrab
ImageGrab.grab().save(r'D:\a_ronglide\clone-ronglide\tools\_hook_auth.png')
print('--- screenshot saved ---')
time.sleep(0.5)
script.unload()
session.detach()
print('--- detached, %d log lines ---' % len(logs))
