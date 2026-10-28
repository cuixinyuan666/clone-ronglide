# -*- coding: utf-8 -*-
"""抓权限弹窗函数 MainApp!sub_457d30 的调用栈，定位功能级权限检查点。
attach 后自动触发一次：点缠论菜单 -> 无脑买入线段，然后打印 backtrace RVA。
"""
import sys, time, ctypes
import frida
import win32gui, win32con, win32api

JS = r'''
var main = Process.getModuleByName('MainApp.exe');
var dlgFn = main.base.add(0x57d30); // RVA 0x457d30 (base 0x400000)
Interceptor.attach(dlgFn, {
  onEnter(args) {
    var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
    var lines = bt.map(function(a) {
      var s = DebugSymbol.fromAddress(a);
      var rva = a.sub(main.base);
      return a + ' RVA=' + rva + ' ' + (s.name || '');
    });
    send('[DLG] args: ' + args[0] + ', ' + args[1] + '\n' + lines.join('\n'));
  }
});
send('[READY] dialog fn hooked @ ' + dlgFn);
'''

logs = []
def on_msg(m, d):
    p = m.get('payload', str(m))
    logs.append(p)
    print(p, flush=True)

dev = frida.get_local_device()
pid = None
for p in dev.enumerate_processes():
    if p.name.lower() == 'mainapp.exe':
        pid = p.pid
        break
print('attach', pid, flush=True)
session = frida.attach(pid)
script = session.create_script(JS)
script.on('message', on_msg)
script.load()
time.sleep(0.5)


def click(x, y, wait=1.0):
    win32api.SetCursorPos((x, y)); time.sleep(0.25)
    win32api.mouse_event(2, 0, 0, 0, 0); time.sleep(0.06)
    win32api.mouse_event(4, 0, 0, 0, 0); time.sleep(wait)


def menus():
    out = []
    def cb(h, _):
        if win32gui.IsWindowVisible(h) and win32gui.GetClassName(h).startswith('#32768'):
            out.append(win32gui.GetWindowRect(h))
        return True
    win32gui.EnumWindows(cb, None)
    return out


h = win32gui.FindWindow('CLASSNAME_RLD_CZSC_MAINAPP', None)
win32gui.SetForegroundWindow(h); time.sleep(0.5)
# dismiss old dialog (click 取消 at 585,426 if present)
click(585, 426, 0.6)
click(306, 16, 0.9)
ms = menus()
print('menus:', ms, flush=True)
if ms:
    l, t, r, b = ms[0]
    n = 15
    y = t + int((b - t) * (12.5 / n))
    print('click item12 at', l + 20, y, flush=True)
    click(l + 20, y, 2.5)
time.sleep(1)
print('--- total logs:', len(logs), flush=True)
try:
    script.unload(); session.detach()
except Exception:
    pass
