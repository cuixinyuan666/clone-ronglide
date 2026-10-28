# -*- coding: utf-8 -*-
"""纯观察: 挂钩所有 app 模块 Authorize/License 类导出, 持续运行直到出现 _hook_stop.flag"""
import frida, sys, time, os

PID = int(sys.argv[1]) if len(sys.argv) > 1 else 13192
STOP = r'D:\a_ronglide\clone-ronglide\tools\_hook_stop.flag'

JS = r'''
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
    hookCount++;
    const addr = e.address;
    const tag = m.name + '!' + e.name;
    try {
      Interceptor.attach(addr, {
        onEnter(args) {
          this.t0 = Date.now();
          this.tag = tag;
          this.a0 = args[0] ? args[0].toInt32() : 'n/a';
          send('[HIT] enter ' + tag + ' a0=' + this.a0 + ' ecx=' + this.context.ecx);
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

def on_message(msg, data):
    print(time.strftime('%H:%M:%S'), msg.get('payload', str(msg)))
    sys.stdout.flush()

session = frida.attach(PID)
script = session.create_script(JS)
script.on('message', on_message)
script.load()
print('--- hooks installed, watching ---')
sys.stdout.flush()

while not os.path.exists(STOP):
    time.sleep(0.5)

print('--- stop flag found, detaching ---')
script.unload()
session.detach()
