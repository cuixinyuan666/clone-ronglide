# -*- coding: utf-8 -*-
"""常驻型 UI 权限检查绕过：hook MainApp.exe!sub_47a080 (RVA 0x7a080)
该函数检查 byte[obj+0xFC]&8，未授权返回 0 → 调用方弹「权限提示」。
此 hook 强制返回 1（放行）。

用法: python inject_perm_bypass.py [pid]   (Ctrl-C 退出后失效)
"""
import sys, time
import frida

JS = r'''
var mod = Process.enumerateModules()[0];
var main = Process.getModuleByName('MainApp.exe');
var chk = main.base.add(0x7a080);
Interceptor.attach(chk, {
  onLeave(rv) {
    send('[PERM] check -> forced 1 (orig=' + (rv.toInt32() & 0xff) + ')');
    rv.replace(ptr(1));
  }
});
send('[READY] perm check hooked @ ' + chk);
'''


def main():
    dev = frida.get_local_device()
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else None
    if not pid:
        for p in dev.enumerate_processes():
            if p.name.lower() == 'mainapp.exe':
                pid = p.pid
                break
    if not pid:
        print('MainApp not found')
        return 1
    print('attach pid', pid, flush=True)
    session = frida.attach(pid)
    script = session.create_script(JS)
    script.on('message', lambda m, d: print(m.get('payload', m), flush=True))
    script.load()
    print('--- perm bypass active ---', flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
