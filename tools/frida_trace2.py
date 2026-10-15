import frida, time, sys

LOG = r'D:\a_ronglide\clone-ronglide\tools\_trace2.log'

JS = r'''
var ts = function() {
    var d = new Date();
    return ('0' + d.getHours()).slice(-2) + ':' + ('0' + d.getMinutes()).slice(-2) + ':' + ('0' + d.getSeconds()).slice(-2) + '.' + ('00' + d.getMilliseconds()).slice(-3);
};
var out = function(s) { send(s); };
function modOf(addr) {
    try {
        var m = Process.findModuleByAddress(addr);
        if (m) return m.name + '+0x' + addr.sub(m.base).toString(16);
    } catch (e) {}
    return addr.toString();
}
function readStr(p) {
    try { return p.readUtf16String(); } catch (e) {}
    try { return p.readAnsiString(); } catch (e) {}
    return '?';
}

function hookK32(name, f) {
    var a = null;
    try { a = Process.getModuleByName('kernel32.dll').getExportByName(name); } catch (e) {}
    if (!a) { out('[MISS] ' + name); return; }
    Interceptor.attach(a, { onEnter: f });
    out('[OK] kernel32!' + name);
}

hookK32('CreateFileW', function(args) {
    var p = args[0];
    try {
        var s = p.readUtf16String() || '';
        if (s.indexOf('Sys\\') >= 0 || s.indexOf('Dat\\') >= 0 || s.indexOf('latelydays') >= 0 || s.indexOf('.rs') >= 0 || s.indexOf('testimp') >= 0 || s.indexOf('Mem') >= 0)
            out(ts() + ' [CreateFileW] ' + s + ' disp=' + args[4].toInt32() + ' acc=' + args[1].toInt32() + ' from ' + modOf(this.returnAddress));
    } catch (e) {}
});
hookK32('GetFileAttributesW', function(args) {
    try {
        var s = args[0].readUtf16String() || '';
        if (s.indexOf('Sys\\') >= 0 || s.indexOf('Dat\\') >= 0 || s.indexOf('.rs') >= 0 || s.indexOf('testimp') >= 0)
            out(ts() + ' [AttrW] ' + s + ' from ' + modOf(this.returnAddress));
    } catch (e) {}
});
hookK32('FindFirstFileW', function(args) {
    try {
        var s = args[0].readUtf16String() || '';
        if (s.indexOf('Sys') >= 0 || s.indexOf('Dat') >= 0 || s.indexOf('testimp') >= 0 || s.indexOf('.rs') >= 0)
            out(ts() + ' [FindFirst] ' + s + ' from ' + modOf(this.returnAddress));
    } catch (e) {}
});
hookK32('MoveFileExW', function(args) {
    try {
        var s = args[0].readUtf16String() || '';
        var d = args[1].readUtf16String() || '';
        out(ts() + ' [MoveFileEx] ' + s + ' -> ' + d);
    } catch (e) {}
});

function hookModule(mod, expSub, label, argFmt) {
    var m = null;
    try { m = Process.getModuleByName(mod); } catch (e) { out('[MISS MOD] ' + mod); return; }
    var found = false;
    m.enumerateExports().forEach(function(e) {
        if (e.name.indexOf(expSub) < 0 || e.type !== 'function') return;
        found = true;
        try {
            Interceptor.attach(e.address, {
                onEnter: function(args) {
                    try {
                        var info = ' from ' + modOf(this.returnAddress);
                        if (argFmt === 'path') {
                            out(ts() + ' [' + label + '] ' + readStr(args[1]) + info);
                        } else if (argFmt === 'sym') {
                            var sym = '?';
                            try { sym = args[0].readByteArray(48); sym = hexdump(sym, {length: 48}); } catch (e) {}
                            out(ts() + ' [' + label + '] sym=' + JSON.stringify(hexdump(args[0].readByteArray(40), {length: 40})) + ' item=' + args[2] + info);
                        } else if (argFmt === 'imphist') {
                            out(ts() + ' [' + label + '] sym=' + JSON.stringify(hexdump(args[0].readByteArray(40), {length: 40})) + ' recset=' + args[1] + ' item=' + (args[2].toInt32() & 0xffff) + info);
                        } else {
                            out(ts() + ' [' + label + '] a0=' + args[0] + ' a1=' + args[1] + info);
                        }
                    } catch (e) { out('[EX ' + label + '] ' + e); }
                },
                onLeave: function(ret) {
                    try { out(ts() + ' [' + label + '] ret=' + ret); } catch (e) {}
                }
            });
            out('[OK] ' + mod + '!' + e.name.slice(0, 70));
        } catch (e) { out('[EX attach ' + label + '] ' + e); }
    });
    if (!found) out('[MISS EXP] ' + mod + ' ' + expSub);
}

var M = Process.getModuleByName('MainApp.exe');
out('[base] MainApp=' + M.base + ' size=' + M.size);
try { out('[base] rld_lib=' + Process.getModuleByName('rld_lib.dll').base); } catch (e) {}
try { out('[base] RDM_C=' + Process.getModuleByName('RDM_C.dll').base); } catch (e) {}
try { out('[base] rquo=' + Process.getModuleByName('rquo.dll').base); } catch (e) {}

hookModule('rld_lib.dll', '?open@rsfile@rs@rld', 'rsfile::open', 'path');
hookModule('rld_lib.dll', '?save@recordset@rs@rld', 'recordset::save', 'path');
hookModule('RDM_C.dll', 'ImportHistory', 'ImportHistory', 'imphist');
hookModule('RDM_C.dll', 'ImportLongAgoHistory', 'ImportLongAgo', 'imphist');
hookModule('RDM_C.dll', 'GetMemoryRecordsetByItemno', 'GetMemRec', 'sym');
hookModule('RDM_C.dll', 'GetTAMemoryRecordset', 'GetTAMemRec', 'sym');
hookModule('RDM_C.dll', 'NeedRequestMemoryItemno', 'NeedReqMem', 'sym');
hookModule('RDM_C.dll', 'RequestStaMemory', 'ReqStaMem', 'plain');
hookModule('RDM_C.dll', 'ReqeustActMemory', 'ReqActMem', 'plain');
hookModule('RDM_C.dll', 'RequestTAMemory', 'ReqTAMem', 'plain');
hookModule('rquo.dll', 'get_memory_recordset', 'q::get_memory_recordset', 'plain');
hookModule('rquo.dll', 'get_min_count', 'q::get_min_count', 'plain');
hookModule('rquo.dll', 'get_history_count', 'q::get_history_count', 'plain');
out('[READY]');
'''

def main():
    dev = frida.get_local_device()
    pid = None
    if len(sys.argv) > 1:
        pid = int(sys.argv[1])
    else:
        for p in dev.enumerate_processes():
            if p.name == 'MainApp.exe':
                pid = p.pid
                break
    if pid is None:
        print('MainApp not running'); return
    print('attach', pid)
    session = frida.attach(pid)
    script = session.create_script(JS)
    f = open(LOG, 'w', encoding='utf-8')
    def on_message(msg, data):
        try:
            s = msg.get('payload') if msg.get('type') == 'send' else str(msg)
            if msg.get('type') == 'send':
                line = str(s)
            else:
                line = 'MSGERR ' + str(msg)
            f.write(line + '\n'); f.flush()
        except Exception as e:
            print('err', e)
    script.on('message', on_message)
    script.load()
    print('loaded; sleeping 900s')
    time.sleep(900)
    try: session.detach()
    except Exception: pass
    f.close()

if __name__ == '__main__':
    main()
