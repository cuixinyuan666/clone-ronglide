"""probe_taflib.py - inspect the TAFLib.dll module inside the live process."""
import sys
import time
import frida

JS = r'''
'use strict';
function hexStr(p, len) {
    const b = new Uint8Array(p.readByteArray(len));
    let s = [];
    for (let i = 0; i < b.length; i++) s.push(('0' + b[i].toString(16)).slice(-2));
    return s.join(' ');
}
function tryread(p, len) {
    try { return hexStr(p, len); } catch (e) { return 'UNREADABLE (' + e.message + ')'; }
}

send({ type: 'arch', arch: Process.arch, ptr: Process.pointerSize });

let mod = null;
try {
    mod = Process.getModuleByName('TAFLib.dll');
    send({
        type: 'module', name: mod.name, base: mod.base.toString(),
        size: mod.size, path: String(mod.path)
    });
} catch (e) {
    send({ type: 'module', error: String(e) });
}

if (mod) {
    send({ type: 'bytes', at: 'base+0x2C1D0', hex: tryread(mod.base.add(0x2C1D0), 24) });
    send({ type: 'bytes', at: 'base+0x2C4B0', hex: tryread(mod.base.add(0x2C4B0), 24) });
    send({ type: 'bytes', at: 'base+0x6FC28', hex: tryread(mod.base.add(0x6FC28), 16) });
    send({ type: 'readable', at: '0x10060000', hex: tryread(ptr('0x10060000'), 16) });
    send({ type: 'readable', at: '0x10000000', hex: tryread(ptr('0x10000000'), 16) });
    send({ type: 'readable', at: '0x1002C1D0', hex: tryread(ptr('0x1002C1D0'), 16) });

    try {
        const base = mod.base;
        const e_lfanew = base.add(0x3C).readU32();
        const pe = base.add(e_lfanew);
        const sig = pe.readU32();
        const numSec = pe.add(0x6).readU16();
        const imageBase = pe.add(0x34).readU32();
        const relocRva = pe.add(0x18 + 5 * 8).readU32();
        const relocSize = pe.add(0x18 + 5 * 8 + 4).readU32();
        const secs = [];
        for (let i = 0; i < numSec; i++) {
            const s = pe.add(0x18 + 0xF8 + i * 0x28);
            const name = s.readUtf8String(8).replace(/\0+$/, '');
            secs.push({
                name: name, va: s.add(0xC).readU32(), vsize: s.add(0x8).readU32(),
                raw: s.add(0x14).readU32()
            });
        }
        send({
            type: 'pe', sig: '0x' + sig.toString(16), numSec: numSec,
            imageBase: '0x' + imageBase.toString(16),
            relocRva: '0x' + relocRva.toString(16), relocSize: relocSize,
            sections: secs
        });
    } catch (e) {
        send({ type: 'pe_error', msg: String(e) });
    }
}

const interesting = [];
Process.enumerateModules().forEach(function (m) {
    const lo = m.base.toUInt32();
    if (m.name.toLowerCase().indexOf('taf') >= 0 || m.size === 569344 ||
        (lo >= 0x10000000 && lo < 0x15000000)) {
        interesting.push(m.name + ' base=' + m.base + ' size=' + m.size + ' path=' + m.path);
    }
});
send({ type: 'modules', list: interesting });
send({ type: 'done' });
'''


def main():
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    device = frida.get_local_device()
    if not pid:
        for p in device.enumerate_processes():
            if p.name.lower() == 'mainapp.exe':
                pid = p.pid
    print("attaching to %d" % pid)
    session = device.attach(pid)

    def on_message(message, data):
        if message["type"] == "send":
            p = message["payload"]
            t = p.get("type")
            if t == "done":
                return
            if t == "modules":
                for line in p["list"]:
                    print("  MOD %s" % line)
            elif t == "pe":
                print("  PE sig=%s sections=%d imageBase=%s reloc RVA=%s size=%d" % (
                    p["sig"], p["numSec"], p["imageBase"], p["relocRva"], p["relocSize"]))
                for s in p["sections"]:
                    print("    sec %-8s va=0x%06x vsize=0x%06x raw=0x%06x" % (
                        s["name"], s["va"], s["vsize"], s["raw"]))
            else:
                print("  %r" % (p,))
        else:
            print("  [msg] %r" % (message,))

    script = session.create_script(JS)
    script.on("message", on_message)
    script.load()
    time.sleep(2)
    script.unload()
    session.detach()


if __name__ == "__main__":
    main()
