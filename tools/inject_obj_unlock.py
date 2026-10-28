# -*- coding: utf-8 -*-
"""常驻型功能对象权限位解锁：hook MainApp.exe!sub_5e5580（按名称查功能对象），
onLeave 把 [返回对象+0xFC] |= 8（0x47a080 判定的"已购买"位）。
所有走 0x47a080 / 对象权限位查询的功能一并放行。

用法: python inject_obj_unlock.py [pid]   (Ctrl-C 退出后失效)
"""
import sys, time
import frida

JS = r'''
var main = Process.getModuleByName('MainApp.exe');
var lookup = main.base.add(0x1e5580); // VA 0x5e5580 (RVA 0x1e5580)
Interceptor.attach(lookup, {
  onLeave(rv) {
    var obj = rv.toInt32();
    if (obj && obj !== 0) {
      try {
        var p = ptr(obj).add(0xFC);
        var b = p.readU8();
        if ((b & 8) === 0) {
          p.writeU8(b | 8);
          send('[UNLOCK] obj=' + rv + ' +0xFC ' + b + ' -> ' + (b | 8));
        }
      } catch (e) { send('[UNLOCK] err ' + e); }
    }
  }
});
send('[READY] obj unlock @ ' + lookup);
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
    print('--- obj unlock active ---', flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
