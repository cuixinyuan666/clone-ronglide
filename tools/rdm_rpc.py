import frida, time, sys
import struct as st

SYM = bytes.fromhex(
    '020000000000681336303030303000000000000000000000060000000f000000b601000002000000')

JS = r'''
var RDM = Process.getModuleByName('RDM_C.dll');
function exp(part) {
    var found = null;
    RDM.enumerateExports().forEach(function(e) {
        if (e.name.indexOf(part) >= 0) found = e.address;
    });
    return found;
}
function mk(symList) {
    var sym = Memory.alloc(64);
    sym.writeByteArray(symList);
    return sym;
}
rpc.exports = {
    getAllSymbols: function(market) {
        var fn = exp('GetMarketSymbolInfoVector');
        if (!fn) return {err: 'no export'};
        var vec = Memory.alloc(16);
        vec.writeByteArray([0,0,0,0,0,0,0,0,0,0,0,0]);
        var f = new NativeFunction(fn, 'void', ['pointer','int','int']);
        f(vec, market & 0xff, 0);
        var begin = vec.readPointer();
        var end = vec.add(4).readPointer();
        var n = begin.isNull() ? 0 : end.sub(begin).toInt32();
        var res = { begin: begin.toString(), bytes: n, market: market };
        if (!begin.isNull() && n > 0) res.head = hexdump(begin, {length: Math.min(n, 256)});
        return res;
    },
    getTotalMinCount: function(symList) {
        var f = new NativeFunction(exp('GetTotalMinCount'), 'int', ['pointer']);
        return { ret: f(mk(symList)) };
    },
    getMinCount: function(symList, dateBytes) {
        var xd = Memory.alloc(16); xd.writeByteArray(dateBytes);
        var out = Memory.alloc(4); out.writeU32(0);
        var f = new NativeFunction(exp('GetMinCount'), 'int', ['pointer','pointer','pointer']);
        var r = f(out, mk(symList), xd);
        return { ret: r, count: out.readS32(), dateUsed: hexdump(xd, {length: 8}) };
    },
    getHistoryCount: function(symList, item) {
        var out = Memory.alloc(4); out.writeU32(0);
        var f = new NativeFunction(exp('GetHistoryCount'), 'int', ['pointer','pointer','int']);
        var r = f(out, mk(symList), item);
        return { ret: r, count: out.readS32() };
    },
    historyIsFinished: function(symList, item) {
        var f = new NativeFunction(exp('HistoryIsFinished'), 'int', ['pointer','int']);
        return { ret: f(mk(symList), item) };
    },
    historyIsRecovered: function(symList, item) {
        var f = new NativeFunction(exp('HistoryIsRecovered'), 'int', ['pointer','int']);
        return { ret: f(mk(symList), item) };
    },
    getMinTradeDate: function(symList) {
        var out = Memory.alloc(8); out.writeByteArray([0,0,0,0,0,0,0,0]);
        var f = new NativeFunction(exp('GetSymbolMinTradeDate'), 'int', ['pointer','pointer']);
        var r = f(out, mk(symList));
        return { ret: r, date: hexdump(out, {length: 8}) };
    },
    getLatelyDays: function(symList) {
        var fn = exp('GetSymbolLatelyDays');
        if (!fn) return { err: 'no exp' };
        var vec = Memory.alloc(16); vec.writeByteArray([0,0,0,0,0,0,0,0,0,0,0,0]);
        var f = new NativeFunction(fn, 'void', ['pointer','int','pointer']);
        f(mk(symList), 0, vec);
        var begin = vec.readPointer();
        var end = vec.add(4).readPointer();
        var n = begin.isNull() ? 0 : end.sub(begin).toInt32();
        var res = { bytes: n };
        if (!begin.isNull() && n > 0) {
            var cnt = Math.min(n / 4, 8);
            var s = '';
            for (var i = 0; i < cnt; i++) s += begin.add(i*4).readU32() + ' ';
            res.first = s;
        }
        return res;
    },
    saveMinbase: function(symList) {
        var f = new NativeFunction(exp('SaveMinbaseHistoryFile'), 'int', ['pointer']);
        return { ret: f(mk(symList)) };
    },
    symbolIsRegistered: function(symList) {
        var f = new NativeFunction(exp('SymbolIsRegistered'), 'int', ['pointer']);
        return { ret: f(mk(symList)) };
    },
    connectCount: function() {
        var f = new NativeFunction(exp('GetQSClientAutoConnectCount'), 'int', []);
        return { ret: f() };
    }
};
'''

def main():
    dev = frida.get_local_device()
    pid = None
    for p in dev.enumerate_processes():
        if p.name == 'MainApp.exe' and p.pid != 7920:
            pid = p.pid
            break
    print('attach pid', pid)
    session = frida.attach(pid)
    script = session.create_script(JS)
    script.on('message', lambda m, d: print('MSG', m))
    script.load()
    api = script.exports_sync
    S = list(SYM)

    def t(name, fn, *args):
        try:
            r = fn(*args)
            print(f'{name}: {r}')
            return r
        except Exception as e:
            print(f'{name}: EXC {e}')
            return None

    t('connectCount', api.connect_count)
    t('symbolIsRegistered', api.symbol_is_registered, S)
    t('getTotalMinCount', api.get_total_min_count, S)
    t('historyIsFinished(item=96)', api.history_is_finished, S, 96)
    t('historyIsRecovered(item=96)', api.history_is_recovered, S, 96)
    t('getMinTradeDate', api.get_min_trade_date, S)
    t('getLatelyDays', api.get_lately_days, S)
    t('getHistoryCount(item=96)', api.get_history_count, S, 96)
    v1 = list(st.pack('<I', 20171229) + bytes(12))
    v2 = list(st.pack('<HBB', 2017, 12, 29) + bytes(11))
    t('getMinCount u32-20171229', api.get_min_count, S, v1)
    t('getMinCount u16y-u8m-u8d', api.get_min_count, S, v2)
    t('getAllSymbols(m2)', api.get_all_symbols, 2)
    try:
        session.detach()
    except Exception:
        pass

if __name__ == '__main__':
    main()
