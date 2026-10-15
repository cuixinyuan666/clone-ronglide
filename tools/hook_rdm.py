import frida, time, sys, os, subprocess

LOG = r'D:\a_ronglide\clone-ronglide\tools\_rdm_hook.log'

JS = r'''
var log = function(tag, msg) { send({t: tag, m: msg}); };
var hooked = [];

function tryHook(modname, substr, label, argfmt) {
    var m = Process.findModuleByName(modname);
    if (!m) { log('ERR', modname + ' not loaded'); return; }
    var exps = m.enumerateExports();
    exps.forEach(function(e) {
        if (e.name.indexOf(substr) >= 0 && e.type === 'function') {
            try {
                Interceptor.attach(e.address, {
                    onEnter: function(args) {
                        try {
                            var info = { fn: label, addr: e.address.toString() };
                            if (argfmt === 'imphist') {
                                info.sym = hexdump(args[0], {length: 64, ansi: true});
                                info.rec = 'recset@' + args[1];
                                info.item = args[2].toInt32() & 0xffff;
                            } else if (argfmt === 'symrec') {
                                info.sym = hexdump(args[0], {length: 64, ansi: true});
                                info.a1 = args[1];
                                if (args[2] !== undefined) info.a2 = args[2].toInt32();
                            } else {
                                info.a0 = args[0]; info.a1 = args[1];
                                if (args[2] !== undefined) info.a2 = args[2];
                            }
                            send({t: 'CALL', m: JSON.stringify({fn: label, p: JSON.parse(JSON.stringify(info, function(k,v){ if (v instanceof NativePointer) return v.toString(); return v; }))})});
                        } catch (ex) { log('EX', label + ' onEnter: ' + ex); }
                    },
                    onLeave: function(ret) {
                        try { send({t: 'RET', m: label + ' -> ' + ret}); } catch(ex){}
                    }
                });
                hooked.push(label + ' @ ' + e.name);
                log('OK', 'hooked ' + label + ' (' + e.name.slice(0, 60) + ')');
            } catch (ex) { log('EX', 'attach ' + label + ': ' + ex); }
        }
    });
}

var specs = [
    ['RDM_C.dll', 'ImportHistory', 'ImportHistory', 'imphist'],
    ['RDM_C.dll', 'ImportLongAgoHistory', 'ImportLongAgoHistory', 'imphist'],
    ['RDM_C.dll', 'GetMemoryRecordsetByItemno', 'GetMemRecByItemno', 'symrec'],
    ['RDM_C.dll', 'GetTAMemoryRecordset', 'GetTAMemoryRecordset', 'symrec'],
    ['RDM_C.dll', 'NeedRequestMemoryItemno', 'NeedRequestMemoryItemno', 'symrec'],
    ['RDM_C.dll', 'RequestStaMemory', 'RequestStaMemory', 'plain'],
    ['RDM_C.dll', 'ReqeustActMemory', 'ReqeustActMemory', 'symrec'],
    ['RDM_C.dll', 'DownloadActMemory', 'DownloadActMemory', 'symrec'],
    ['RDM_C.dll', 'RequestTAMemory', 'RequestTAMemory', 'symrec'],
    ['RDM_C.dll', 'GetTAMemoryString', 'GetTAMemoryString', 'plain'],
    ['rld_lib.dll', '?open@rsfile', 'rsfile_open', 'plain'],
    ['rld_lib.dll', '?save@recordset', 'recordset_save', 'plain'],
];

specs.forEach(function(s) { tryHook(s[0], s[1], s[2], s[3]); });
log('DONE', 'all hooks processed: ' + hooked.length);
'''

def main():
    import frida
    pid = None
    for p in frida.get_local_device().enumerate_processes():
        if p.name == 'MainApp.exe':
            pid = p.pid
            break
    if pid is None:
        print('MainApp not running')
        return
    print('attaching to', pid)
    session = frida.attach(pid)
    script = session.create_script(JS)

    f = open(LOG, 'w', encoding='utf-8')
    def on_message(msg, data):
        try:
            if msg['type'] == 'send':
                p = msg['payload']
                line = f"{time.strftime('%H:%M:%S')} [{p['t']}] {p['m']}"
                f.write(line + '\n'); f.flush()
                print(line[:200])
            else:
                f.write(f"ERRMSG {msg}\n"); f.flush()
        except Exception as e:
            print('msg err', e)
    script.on('message', on_message)
    script.load()
    print('hooks loaded. logging to', LOG)
    print('now run the import UI script; this process will stay attached for 600s')
    time.sleep(600)
    try:
        session.detach()
    except Exception:
        pass
    f.close()
    print('detached')

if __name__ == '__main__':
    main()
