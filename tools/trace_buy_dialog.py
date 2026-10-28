# -*- coding: utf-8 -*-
"""抓「购买」弹窗来源：hook 常见对话框 API + backtrace，然后自动触发缠论->无脑买入线段。"""
import time
import frida
import win32gui, win32api

JS = r'''
var main = Process.getModuleByName('MainApp.exe');
function hookMod(addr, name) {
  Interceptor.attach(addr, {
    onEnter(args) {
      var bt = Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 8);
      var lines = bt.map(function(a) { return a + ' RVA=' + a.sub(main.base); });
      send('[' + name + '] bt:\n' + lines.join('\n'));
    }
  });
}
['DialogBoxParamW','DialogBoxIndirectParamW','DialogBoxParamA','CreateDialogParamW','CreateDialogIndirectParamW','MessageBoxW','MessageBoxIndirectW'].forEach(function(n) {
  var p = Module.getExportByName('user32.dll', n);
  if (p) hookMod(p, n);
});
send('[READY]');
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
click(590, 426, 0.6)  # dismiss
click(306, 16, 0.9)
ms = menus()
print('menus:', ms, flush=True)
if ms:
    l, t, r, b = ms[0]
    y = t + int((b - t) * (12.5 / 15))
    click(l + 20, y, 3.0)
time.sleep(1)
print('--- logs:', len(logs), flush=True)
try:
    script.unload(); session.detach()
except Exception:
    pass
