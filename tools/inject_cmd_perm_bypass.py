# -*- coding: utf-8 -*-
"""常驻型命令权限虚调用绕过：在 MainApp.exe RVA 0x66a2 (test al,al) 处
强制 eax|=1，使 jne 走功能执行分支（绕过「购买/权限」弹窗）。

用法: python inject_cmd_perm_bypass.py [pid]   (Ctrl-C 退出后失效)
"""
import sys, time
import frida

JS = r'''
var main = Process.getModuleByName('MainApp.exe');
var site = main.base.add(0x66a2);
Interceptor.attach(site, {
  onEnter(args) {
    var old = this.context.eax.toInt32();
    if ((old & 1) === 0) {
      this.context.eax = ptr(old | 1);
      send('[CMD] perm vcall al 0 -> 1 @ esi=' + this.context.esi);
    }
  }
});
send('[READY] cmd perm bypass @ ' + site);
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
    print('--- cmd perm bypass active ---', flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
