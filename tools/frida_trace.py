# -*- coding: utf-8 -*-
"""Frida 动态追踪: 挂钩文件访问与 rsfile::open, 观察软件运行时读写了哪些数据文件。
用法:
  python frida_trace.py            # spawn 启动 MainApp 并持续记录 (Ctrl+C 停止)
  python frida_trace.py attach     # attach 到已运行的 MainApp
日志同时写入 tools/_trace.log
"""
import sys, os, time, io, traceback
import frida

APP_DIR = r"D:\a_ronglide\缠中说禅"
EXE = os.path.join(APP_DIR, "MainApp.exe")
LOGFILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_trace.log")

SCRIPT = r"""
'use strict';
var WATCH = ['Dat', 'Sys', '.rs', 'Mem', 'Min', 'His', 'Tick', 'Tmk', 'latelydays', 'SymTable', 'xdr', '.bin', '.gd', '.dt', '.taf', 'a_ronglide', 'SelectPlan', 'Page', '.xml', 'stock'];
function ts() {
    var d = new Date();
    function p(n, w) { n = '' + n; while (n.length < w) n = '0' + n; return n; }
    return p(d.getHours(),2)+':'+p(d.getMinutes(),2)+':'+p(d.getSeconds(),2)+'.'+p(d.getMilliseconds(),3);
}
function findExport(modName, expName) {
    try { return Module.getExportByName(modName, expName); } catch (e) {}
    try { return Process.getModuleByName(modName).getExportByName(expName); } catch (e) {}
    return null;
}
function think(s) {
    var hit = false;
    for (var i = 0; i < WATCH.length; i++) if (s.indexOf(WATCH[i]) >= 0) { hit = true; break; }
    if (hit) send(ts() + ' ' + s);
}

function hookCreateFileW() {
    var pf = findExport('kernel32.dll', 'CreateFileW');
    Interceptor.attach(pf, {
        onEnter: function (args) {
            try { this.path = args[0].readUtf16String(); } catch (e) { this.path = null; }
            this.acc = args[1].toInt32();
            this.disp = args[4].toInt32();
        },
        onLeave: function (ret) {
            var r = ret.toInt32();
            if (this.path) think('[CreateFileW] disp=' + this.disp + ' acc=' + this.acc + ' ' + this.path + ' -> ' + (r === -1 ? 'FAIL' : 'ok'));
        }
    });
}
function hookCreateFileA() {
    var pf = findExport('kernel32.dll', 'CreateFileA');
    Interceptor.attach(pf, {
        onEnter: function (args) {
            try { this.path = args[0].readAnsiString(); } catch (e) { this.path = null; }
            this.disp = args[4].toInt32();
        },
        onLeave: function (ret) {
            var r = ret.toInt32();
            if (this.path) think('[CreateFileA] disp=' + this.disp + ' ' + this.path + ' -> ' + (r === -1 ? 'FAIL' : 'ok'));
        }
    });
}
function hookFileAttrs() {
    var pw = findExport('kernel32.dll', 'GetFileAttributesW');
    if (pw) Interceptor.attach(pw, {
        onEnter: function (args) { try { this.path = args[0].readUtf16String(); } catch (e) { this.path = null; } },
        onLeave: function (ret) { if (this.path) think('[GetFileAttributesW] ' + this.path + ' -> ' + ret.toInt32()); }
    });
    var pa = findExport('kernel32.dll', 'GetFileAttributesA');
    if (pa) Interceptor.attach(pa, {
        onEnter: function (args) { try { this.path = args[0].readAnsiString(); } catch (e) { this.path = null; } },
        onLeave: function (ret) { if (this.path) think('[GetFileAttributesA] ' + this.path + ' -> ' + ret.toInt32()); }
    });
    var pe = findExport('kernel32.dll', 'GetFileAttributesExW');
    if (pe) Interceptor.attach(pe, {
        onEnter: function (args) { try { this.path = args[0].readUtf16String(); } catch (e) { this.path = null; } },
        onLeave: function (ret) { if (this.path) think('[GetFileAttributesExW] ' + this.path + ' -> ' + ret.toInt32()); }
    });
}
function hookFindFirstFile() {
    var pw = findExport('kernel32.dll', 'FindFirstFileW');
    if (pw) Interceptor.attach(pw, {
        onEnter: function (args) { try { this.path = args[0].readUtf16String(); } catch (e) { this.path = null; } },
        onLeave: function (ret) { if (this.path) think('[FindFirstFileW] ' + this.path + ' -> ' + (ret.equals(ptr('-1')) ? 'FAIL' : 'ok')); }
    });
    var pa = findExport('kernel32.dll', 'FindFirstFileA');
    if (pa) Interceptor.attach(pa, {
        onEnter: function (args) { try { this.path = args[0].readAnsiString(); } catch (e) { this.path = null; } },
        onLeave: function (ret) { if (this.path) think('[FindFirstFileA] ' + this.path + ' -> ' + (ret.equals(ptr('-1')) ? 'FAIL' : 'ok')); }
    });
}
function hookMoveFile() {
    var pw = findExport('kernel32.dll', 'MoveFileExW');
    if (pw) Interceptor.attach(pw, {
        onEnter: function (args) {
            try { think('[MoveFileExW] ' + args[0].readUtf16String() + ' -> ' + args[1].readUtf16String()); } catch (e) {}
        }
    });
    var pm = findExport('kernel32.dll', 'MoveFileW');
    if (pm) Interceptor.attach(pm, {
        onEnter: function (args) {
            try { think('[MoveFileW] ' + args[0].readUtf16String() + ' -> ' + args[1].readUtf16String()); } catch (e) {}
        }
    });
}
function hookRsfileOpen() {
    var pf = findExport('rld_lib.dll', '?open@rsfile@rs@rld@@QAE_NPBD@Z');
    if (!pf) { send('[hook] rsfile::open FAIL'); return; }
    Interceptor.attach(pf, {
        onEnter: function (args) {
            try { this.p = args[0].readAnsiString(); } catch (e) { this.p = null; }
        },
        onLeave: function (ret) {
            if (this.p !== null) send(ts() + ' [rsfile::open] ' + this.p + ' -> ' + ret);
        }
    });
    send('[hook] rsfile::open @ ' + pf);
}
function hookUnlinkRename() {
    var pu = findExport('msvcr80.dll', '_unlink');
    var pr = findExport('msvcr80.dll', 'rename');
    if (pu) Interceptor.attach(pu, { onEnter: function (a) { try { think('[_unlink] ' + a[0].readAnsiString()); } catch (e) {} } });
    if (pr) Interceptor.attach(pr, { onEnter: function (a) { try { think('[rename] ' + a[0].readAnsiString() + ' -> ' + a[1].readAnsiString()); } catch (e) {} } });
    send('[hook] _unlink/rename ' + (pu ? 'ok' : 'FAIL') + '/' + (pr ? 'ok' : 'FAIL'));
}
function hookRquoExports() {
    var names = [
        '?get_min_count@q_module@@QAE?AW4dmresult_t@@AAHABVsymbol_info@@ABVxdate@rld@@@Z',
        '?get_min_by_pos@q_module@@QAE?AW4dmresult_t@@AAVrecordset@rs@rld@@ABVsymbol_info@@ABVxdate@5@HH_N@Z',
        '?get_history_count@q_module@@QAE?AW4dmresult_t@@AAHABVsymbol_info@@G@Z',
        '?get_history_by_pos@q_module@@QAE?AW4dmresult_t@@AAVrecordset@rs@rld@@ABVsymbol_info@@GHHABUDividenMode@@@Z',
        '?get_memory_recordset@q_module@@QAE?AW4dmresult_t@@AAVrecordset@rs@rld@@ABVsymbol_info@@@Z',
        '?get_total_min_count@q_module@@QAEHABVsymbol_info@@@Z',
        '?get_symbol_min_trade_date@q_module@@QAE?AW4dmresult_t@@AAVxdate@rld@@ABVsymbol_info@@@Z',
        '?recv_sta_memory_recovery@q_module@@UAE?AW4dmresult_t@@ABVsta_memory_response_pkt2@@@Z',
        '?recv_active_memory_recovery@q_module@@UAE?AW4dmresult_t@@ABVact_memory_response_pkt2@@@Z'
    ];
    names.forEach(function (n) {
        var addr = findExport('rquo.dll', n);
        if (!addr) { send('[hook] ' + n.split('@')[0] + ' FAIL'); return; }
        var short = n.split('@')[0].replace('?', '');
        Interceptor.attach(addr, {
            onEnter: function () { send(ts() + ' [rquo] ' + short); }
        });
    });
    send('[hook] rquo done');
}

hookCreateFileW();
hookCreateFileA();
hookFileAttrs();
hookFindFirstFile();
hookMoveFile();
hookRsfileOpen();
hookUnlinkRename();
function waitForModule(name, cb, tries) {
    tries = tries || 60;
    var m = null;
    try { m = Process.getModuleByName(name); } catch (e) {}
    if (m) { cb(); return; }
    if (tries <= 0) { send('[hook] waitForModule ' + name + ' timeout'); return; }
    setTimeout(function () { waitForModule(name, cb, tries - 1); }, 500);
}
waitForModule('rquo.dll', hookRquoExports);
send('[hook] all installed');
"""


def logline(line):
    try:
        print(line, flush=True)
    except Exception:
        pass
    try:
        with io.open(LOGFILE, 'a', encoding='utf-8') as f:
            f.write(line + '\n')
    except Exception:
        pass


def on_message(msg, data):
    try:
        if msg['type'] == 'send':
            logline(msg['payload'])
        elif msg['type'] == 'error':
            logline('ERROR ' + str(msg.get('stack') or msg))
    except Exception:
        logline('on_message exception: ' + traceback.format_exc())


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else 'spawn'
    io.open(LOGFILE, 'w', encoding='utf-8').close()
    device = frida.get_local_device()
    if mode == 'attach':
        pid = None
        for p in device.enumerate_processes():
            if p.name.lower() == 'mainapp.exe':
                pid = p.pid
                break
        if pid is None:
            logline('MainApp not running')
            return
        session = device.attach(pid)
        logline('attached pid %d' % pid)
    else:
        pid = device.spawn([EXE], cwd=APP_DIR)
        session = device.attach(pid)
        logline('spawned pid %d' % pid)
    script = session.create_script(SCRIPT)
    script.on('message', on_message)
    script.load()
    try:
        script.on('destroyed', lambda *a: logline('[frida] script destroyed!'))
        session.on('detached', lambda *a: logline('[frida] session detached!'))
    except Exception:
        pass
    if mode != 'attach':
        device.resume(pid)
        logline('resumed')
    logline('logging...')
    while True:
        time.sleep(1)


if __name__ == '__main__':
    main()
