import frida, sys
import struct as st

SYM = bytes.fromhex(
    '020000000000681336303030303000000000000000000000060000000f000000b601000002000000')

JS = r'''
var RDM = Process.getModuleByName('RDM_C.dll');
var RQ = Process.getModuleByName('rquo.dll');

function mkSym(list) {
    var sym = Memory.alloc(64);
    sym.writeByteArray(list);
    return sym;
}

var get_instance = null, add_market = null, get_market = null, load_symtab = null,
    get_symbol = null, get_all_markets = null, get_market_symbol_vec = null;

rpc.exports = {
    init: function() {
        get_instance = new NativeFunction(RDM.base.add(0x22580), 'pointer', []);
        add_market = new NativeFunction(RQ.base.add(0x47430), 'bool', ['pointer', 'uint8'], 'thiscall');
        get_all_markets = new NativeFunction(RQ.base.add(0x477d0), 'void', ['pointer', 'pointer'], 'thiscall');
        get_market = new NativeFunction(RQ.base.add(0x58f60), 'bool', ['pointer', 'uint8', 'pointer'], 'thiscall');
        load_symtab = new NativeFunction(RQ.base.add(0x280b0), 'int', ['pointer'], 'thiscall');
        get_symbol = new NativeFunction(RQ.base.add(0x59270), 'bool', ['pointer', 'pointer', 'pointer'], 'thiscall');
        get_market_symbol_vec = new NativeFunction(RQ.base.add(0x49720), 'void', ['pointer', 'pointer', 'uint8', 'uint8'], 'thiscall');
        return 'ok';
    },
    inst: function() {
        return get_instance().toString();
    },
    markets: function() {
        var inst = get_instance();
        var vec = Memory.alloc(16);
        vec.writeByteArray([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
        get_all_markets(inst, vec);
        var begin = vec.readPointer();
        var end = vec.add(4).readPointer();
        var n = begin.isNull() ? 0 : end.sub(begin).toInt32();
        var arr = [];
        for (var i = 0; i < n; i++) arr.push(begin.add(i).readU8());
        return { n: n, markets: arr };
    },
    addMarket: function(m) {
        var inst = get_instance();
        return { ret: add_market(inst, m) };
    },
    getMarket: function(m) {
        var inst = get_instance();
        var sp = Memory.alloc(8);
        sp.writeByteArray([0,0,0,0,0,0,0,0]);
        var ok = get_market(inst, m, sp);
        var raw = sp.readPointer();
        var ctrl = sp.add(4).readPointer();
        return { ok: ok, raw: raw.toString(), ctrl: ctrl.toString() };
    },
    loadSymtab: function(mktPtr) {
        var p = ptr(mktPtr);
        var ret = load_symtab(p);
        return { ret: ret };
    },
    symbolCount: function(market) {
        var inst = get_instance();
        var vec = Memory.alloc(16);
        vec.writeByteArray([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
        get_market_symbol_vec(inst, vec, market, 0);
        var begin = vec.readPointer();
        var end = vec.add(4).readPointer();
        var n = begin.isNull() ? 0 : end.sub(begin).toInt32();
        return { bytes: n, count: n > 0 ? Math.floor(n / 40) : 0 };
    },
    getSymbol: function(symList) {
        var inst = get_instance();
        var sp = Memory.alloc(8);
        sp.writeByteArray([0,0,0,0,0,0,0,0]);
        var ok = get_symbol(inst, mkSym(symList), sp);
        var raw = sp.readPointer();
        var res = { ok: ok, raw: raw.toString() };
        if (!raw.isNull()) {
            res.fields = hexdump(raw, { length: 64 });
        }
        return res;
    },
    rdmcSymbolCount: function(market) {
        var fn = null;
        RDM.enumerateExports().forEach(function(e) {
            if (e.name.indexOf('GetMarketSymbolInfoVector') >= 0) fn = e.address;
        });
        if (!fn) return { err: 'no export' };
        var vec = Memory.alloc(16);
        vec.writeByteArray([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
        var f = new NativeFunction(fn, 'void', ['pointer', 'int', 'int']);
        f(vec, market & 0xff, 0);
        var begin = vec.readPointer();
        var end = vec.add(4).readPointer();
        var n = begin.isNull() ? 0 : end.sub(begin).toInt32();
        return { bytes: n, count: n > 0 ? Math.floor(n / 40) : 0 };
    }
};
'''

def main():
    dev = frida.get_local_device()
    pid = None
    for p in dev.enumerate_processes():
        if p.name.lower() == 'mainapp.exe' and p.pid != 7920:
            pid = p.pid
            break
    if not pid:
        print('MainApp not found')
        return
    print('attach pid', pid)
    session = frida.attach(pid)
    script = session.create_script(JS)
    script.on('message', lambda m, d: print('MSG', m))
    script.load()
    api = script.exports_sync

    def t(name, fn, *args):
        try:
            r = fn(*args)
            print(f'{name}: {r}')
            return r
        except Exception as e:
            print(f'{name}: EXC {e}')
            return None

    t('init', api.init)
    t('instance', api.inst)
    t('marketsBefore', api.markets)
    mkt = None
    r = t('getMarket(2)', api.get_market, 2)
    if r and r.get('raw') and r['raw'] != '0x0':
        mkt = r['raw']
    else:
        t('addMarket(2)', api.add_market, 2)
        r = t('getMarket(2) again', api.get_market, 2)
        if r:
            mkt = r.get('raw')
    if mkt and mkt != '0x0':
        t('loadSymtab', api.load_symtab, mkt)
        S = list(SYM)
        t('getSymbol(600000)', api.get_symbol, S)
    else:
        print('no market object, abort injection')
    try:
        session.detach()
    except Exception:
        pass

if __name__ == '__main__':
    main()
