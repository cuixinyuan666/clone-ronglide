# -*- coding: utf-8 -*-
"""常驻型缠论功能权限码绕过：hook MainApp.exe!sub_406960 (RVA 0x6960)。
逻辑: [this+0xC] > 0 -> ShowPermTip(权限提示); <= 0 -> 正常执行功能。
本 hook 在 onEnter 把 [ecx+0xC] 清零，强制放行。

用法: python inject_func_perm_bypass.py [pid]   (Ctrl-C 退出后失效)
"""
import sys, time
import frida

JS = r'''
var main = Process.getModuleByName('MainApp.exe');
var fn = main.base.add(0x6960);
Interceptor.attach(fn, {
  onEnter(args) {
    var ecx = this.context.ecx;
    try {
      var old = ecx.add(0xC).readS32();
      if (old > 0) {
        ecx.add(0xC).writeS32(0);
        send('[FUNC] this=' + ecx + ' permcode ' + old + ' -> 0 (bypassed)');
      }
    } catch (e) {
      send('[FUNC] ecx=' + ecx + ' err ' + e);
    }
  }
});
send('[READY] func perm bypass @ ' + fn);
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
    print('--- func perm bypass active ---', flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
