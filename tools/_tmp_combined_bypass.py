# one-shot combined bypass for WNMR GUI test
import sys, time, frida
pid = int(sys.argv[1])
JS = r'''
var main = Process.getModuleByName('MainApp.exe');
var taf = Process.getModuleByName('TAFLib.dll');
Interceptor.attach(taf.base.add(0x14e60), {
  onEnter(args) { this.code = args[0].toInt32(); },
  onLeave(rv) {
    var orig = rv.toInt32() & 0xff;
    rv.replace(ptr(1));
    send('[AUTH] code=0x' + (this.code>>>0).toString(16) + ' orig=' + orig + ' -> 1');
  }
});
Interceptor.attach(main.base.add(0x6960), {
  onEnter(args) {
    var ecx = this.context.ecx;
    try {
      var old = ecx.add(0xC).readS32();
      if (old > 0) { ecx.add(0xC).writeS32(0); send('[FUNC] perm ' + old + ' -> 0'); }
    } catch (e) {}
  }
});
Interceptor.attach(main.base.add(0x66a2), {
  onEnter(args) {
    var old = this.context.eax.toInt32();
    if ((old & 1) === 0) { this.context.eax = ptr(old | 1); send('[CMD] eax -> 1'); }
  }
});
Interceptor.attach(main.base.add(0x7a080), {
  onLeave(rv) {
    send('[PERM] orig=' + (rv.toInt32()&0xff) + ' -> 1');
    rv.replace(ptr(1));
  }
});
send('[READY] combined bypass');
'''
print('attach', pid, flush=True)
s = frida.attach(pid)
sc = s.create_script(JS)
sc.on('message', lambda m,d: print(m.get('payload',m), flush=True))
sc.load()
print('--- active ---', flush=True)
while True:
    time.sleep(1)
