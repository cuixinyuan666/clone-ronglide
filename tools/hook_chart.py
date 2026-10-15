import frida, time, ctypes, win32gui, win32con, win32api
from PIL import ImageGrab

JS = r'''
var RQ = Process.getModuleByName('rquo.dll');
var RDM = Process.getModuleByName('RDM_C.dll');

function rva(mod, off) { return mod.base.add(off); }
function symCode(symPtr) {
    try {
        var code = symPtr.add(8).readUtf8String(8);
        var mkt = symPtr.readU8();
        return mkt + ':' + code;
    } catch (e) { return '?'; }
}
function hookFn(name, addr, argMapper, retMapper) {
    Interceptor.attach(addr, {
        onEnter: function (args) {
            try { this.info = argMapper ? argMapper(args) : ''; } catch (e) { this.info = 'err'; }
        },
        onLeave: function (ret) {
            var extra = '';
            try { extra = retMapper ? retMapper(ret, this) : ''; } catch (e) { extra = 'err2'; }
            console.log('[HOOK] ' + name + ' ' + (this.info || '') + ' ret=' + ret + extra);
        }
    });
    console.log('hooked ' + name + ' @ ' + addr);
}

try {
    hookFn('q::get_symbol', rva(RQ, 0x59270),
        function (a) { return symCode(a[1]); },
        function (r) { return ' ok=' + r; });
    hookFn('q::get_history_count', rva(RQ, 0x4dcc0),
        function (a) { return 'out=' + a[1] + ' sym=' + symCode(a[2]) + ' item=' + a[3]; });
    hookFn('q::get_history_by_pos', rva(RQ, 0x4ddd0),
        function (a) { return 'sym=' + symCode(a[2]) + ' item=' + a[3] + ' pos=' + a[4] + ' want=' + a[5]; });
    hookFn('q::get_history_by_date', rva(RQ, 0x4def0),
        function (a) { return 'sym=' + symCode(a[2]) + ' item=' + a[3]; });
    hookFn('q::get_min_count', rva(RQ, 0x4cea0),
        function (a) { return 'sym=' + symCode(a[2]); });
    hookFn('q::get_min_by_pos', rva(RQ, 0x4cfb0),
        function (a) { return 'sym=' + symCode(a[2]) + ' pos=' + a[4] + ' want=' + a[5]; });
    hookFn('q::get_total_min_count', rva(RQ, 0x4c960),
        function (a) { return 'sym=' + symCode(a[1]); });
    hookFn('q::hist_is_finished', rva(RQ, 0x4e8d0),
        function (a) { return 'sym=' + symCode(a[1]) + ' item=' + a[2]; });
    hookFn('q::hist_is_recovered', rva(RQ, 0x4e7c0),
        function (a) { return 'sym=' + symCode(a[1]) + ' item=' + a[2]; });
} catch (e) { console.log('rquo hook error: ' + e); }

RDM.enumerateExports().forEach(function (e) {
    var n = e.name;
    if (n.indexOf('GetHistoryCount') >= 0 || n.indexOf('GetHistoryByPos') >= 0 ||
        n.indexOf('GetHistoryByDate') >= 0 || n.indexOf('HistoryIsFinished') >= 0 ||
        n.indexOf('HistoryIsRecovered') >= 0 || n.indexOf('GetTotalMinCount') >= 0 ||
        n.indexOf('GetMinCount') >= 0 || n.indexOf('GetMinByPos') >= 0 ||
        n.indexOf('GetSymbolMinTradeDate') >= 0 || n.indexOf('GetHistoryRecoveryRange') >= 0) {
        try {
            Interceptor.attach(e.address, {
                onEnter: function (args) { this.n = n; },
                onLeave: function (ret) { console.log('[RDM] ' + this.n.split('@@')[0].replace('?', '') + ' ret=' + ret); }
            });
            console.log('hooked RDM ' + n.split('@@')[0]);
        } catch (err) {}
    }
});
console.log('ALL READY');
'''

def find_main():
    res = []
    def cb(h, _):
        if win32gui.IsWindowVisible(h) and '缠中说禅' in win32gui.GetWindowText(h) and 'RLD' in win32gui.GetClassName(h):
            res.append(h)
    win32gui.EnumWindows(cb, None)
    return res[0] if res else None

def click(lx, ly, wait=1.0):
    win32api.SetCursorPos((lx, ly)); time.sleep(0.15)
    win32api.mouse_event(win32con.MOUSEEVENTF_LEFTDOWN, 0,0,0,0); time.sleep(0.08)
    win32api.mouse_event(win32con.MOUSEEVENTF_LEFTUP, 0,0,0,0); time.sleep(wait)

logs = []
def on_message(msg, data):
    if msg['type'] == 'log':
        line = msg['payload']
        logs.append(line)
        print(line, flush=True)

dev = frida.get_local_device()
pid = [p.pid for p in dev.enumerate_processes() if p.name.lower()=='mainapp.exe' and p.pid!=7920][0]
print('pid', pid, flush=True)
session = frida.attach(pid)
script = session.create_script(JS)
script.on('message', on_message)
script.load()
time.sleep(1.5)

main = find_main()
rect = win32gui.GetWindowRect(main)
ox, oy = rect[0], rect[1]
print('main rect', rect, flush=True)
win32gui.SetWindowPos(main, -1, 0, 0, 0, 0, win32con.SWP_NOMOVE | win32con.SWP_NOSIZE | win32con.SWP_NOACTIVATE)
time.sleep(0.3)

print('--- click 分时 nav ---', flush=True)
click(ox+38, oy+207, 2.5)
print('--- click 技术 nav ---', flush=True)
click(ox+38, oy+231, 2.5)
print('--- click 日线 ---', flush=True)
click(ox+570, oy+73, 2.5)
print('--- click 1分钟 ---', flush=True)
click(ox+99, oy+73, 3.0)

img = ImageGrab.grab()
img.save(r'D:\a_ronglide\clone-ronglide\tools\_hooked.png')
print('shot _hooked.png', flush=True)
win32gui.SetWindowPos(main, -2, 0, 0, 0, 0, win32con.SWP_NOMOVE | win32con.SWP_NOSIZE | win32con.SWP_NOACTIVATE)
time.sleep(1)
session.detach()
print('total log lines:', len(logs), flush=True)
