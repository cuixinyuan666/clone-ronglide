# -*- coding: utf-8 -*-
"""常驻型 Authorize 绕过：hook TAFLib.dll!?Authorize@TAF_Calculator@@IAE_NI@Z (RVA 0x14e60)，
强制返回 true，使 wnmr*/chduan 等 0xEA61/EA62/EA63 组付费函数可出结果。

用法: python inject_authorize_bypass.py [pid]     (Ctrl-C 退出；退出后 hook 失效)
"""
import sys, time, threading
import frida

RVA_AUTHORIZE = 0x14e60
MOD = 'TAFLib.dll'

JS = r'''
var mod = Process.getModuleByName('TAFLib.dll');
var auth = mod.base.add(%d);
var hits = {};
Interceptor.attach(auth, {
  onEnter(args) {
    this.code = args[0].toInt32();
    hits[this.code] = (hits[this.code] || 0) + 1;
    send('[AUTH] call code=0x' + (this.code >>> 0).toString(16) + ' n=' + hits[this.code]);
  },
  onLeave(rv) {
    var orig = rv.toInt32() & 0xff;
    rv.replace(ptr(1));
    send('[AUTH] code=0x' + (this.code >>> 0).toString(16) + ' orig=' + orig + ' -> forced 1');
  }
});
send('[READY] Authorize hooked @ ' + auth);
''' % RVA_AUTHORIZE


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
    print('--- bypass active, press Ctrl-C to stop ---', flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
