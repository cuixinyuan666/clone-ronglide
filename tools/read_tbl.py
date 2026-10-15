import frida, sys

JS = r'''
var RDM = Process.getModuleByName('RDM_C.dll');
var out = [];
var tbl = RDM.base.add(0x5aa50);
// read 40 dwords starting a bit earlier to cover 0x5a7a0..0x5aad0 area
var start = RDM.base.add(0x5aa40);
var res = [];
for (var i = 0; i < 40; i++) {
    var p = start.add(i*4).readPointer();
    if (!p.isNull()) {
        var m = null;
        try { m = Process.findModuleByAddress(p); } catch(e) {}
        if (m) {
            var off = p.sub(m.base);
            res.push('0x' + (0x5aa40 + i*4).toString(16) + ' -> ' + m.name + '+0x' + off.toString(16));
        }
    }
}
send(res.join('\n'));
'''

def main():
    dev = frida.get_local_device()
    pid = None
    for p in dev.enumerate_processes():
        if p.name == 'MainApp.exe' and p.pid != 7920:
            pid = p.pid
            break
    session = frida.attach(pid)
    script = session.create_script(JS)
    script.on('message', lambda m, d: print(m.get('payload', m)))
    script.load()
    import time
    time.sleep(2)
    try:
        session.detach()
    except Exception:
        pass

if __name__ == '__main__':
    main()
