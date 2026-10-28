"""e2e_inject.py - symbol table injection that targets the MainApp instance owning
the real main window (avoids the zombie leftover process).
Reuses SYM/JS from tools/inject_symtab.py. Usage: python e2e_inject.py
"""
import ctypes
import os
import sys

import frida
import win32gui

TOOLS = r"D:\a_ronglide\clone-ronglide\tools"
sys.path.insert(0, TOOLS)
import inject_symtab as inj  # noqa: E402


def find_pid():
    res = []

    def cb(h, _):
        try:
            if win32gui.IsWindowVisible(h) and \
                    win32gui.GetClassName(h) == 'CLASSNAME_RLD_CZSC_MAINAPP':
                res.append(h)
        except Exception:
            pass
    win32gui.EnumWindows(cb, None)
    if not res:
        return None
    hwnd = res[0]
    pid = ctypes.c_ulong(0)
    ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    print('main window %s pid %d' % (hex(hwnd), pid.value), flush=True)
    return pid.value


def main():
    pid = find_pid()
    if not pid:
        print('no MainApp main window found')
        return 1
    session = frida.attach(pid)
    script = session.create_script(inj.JS)
    script.on('message', lambda m, d: print('MSG', m, flush=True))
    script.load()
    api = script.exports_sync

    def t(name, fn, *args):
        try:
            r = fn(*args)
            print('%s: %s' % (name, r), flush=True)
            return r
        except Exception as e:
            print('%s: EXC %s' % (name, e), flush=True)
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
        t('getSymbol(600000)', api.get_symbol, list(inj.SYM))
    else:
        print('no market object, abort injection', flush=True)
    try:
        session.detach()
    except Exception:
        pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
