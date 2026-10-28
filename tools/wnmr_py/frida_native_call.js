'use strict';
// Run the real TAFLib.dll CHBI entries natively inside the instrumented process.
//   c1d0: cdecl  args (W**, count, out, series, iface)   -> NativeFunction
//   c4b0: cdecl + EAX=series                            -> trampoline stub
// iface vtbl[1] is replaced by a stub: mov eax,1; ret 4  (thiscall auth gate)

const MODULE_NAME = 'TAFLib.dll';
const DLL_PATH = 'D:\\a_ronglide\\缠中说禅\\TAFLib.dll';
const OFF_C1D0 = 0x2C1D0;
const OFF_C4B0 = 0x2C4B0;
const QUIET = true; // skip all Interceptor instrumentation (bisection test)

const TRACE_OFFS = [
    [0x3D780, 'iter2a'], [0x3D8A0, 'iter2b'], [0x3DB40, 'sb40'],
    [0x3E200, 'se200'], [0x3EBA0, 'seba0'], [0x3EF00, 'sef00'],
    [0x3F0D0, 'iter_at'], [0x3F150, 'sf150'], [0x3F170, 'sf170'],
    [0x4B1E0, 's4b1e0'], [0x4F430, 's4f430'], [0x6A040, 's6a040'],
    [0x6A4E0, 'iter_begin'], [0x6A5E0, 's6a5e0'], [0x6A720, 's6a720'],
    [0x6B050, 's6b050'], [0x6B1C0, 'copyA0'], [0x6B1F0, 'copy28'],
    [0x6B320, 'free2'], [0x6B344, 'free1'], [0x6B34A, 'malloc'],
    [0x6BC70, 'ftol'],
];

function exportAddr(modName, name) {
    return Process.getModuleByName(modName).getExportByName(name);
}

function u32(p) { return p.toUInt32(); }

const RtlZeroMemory = new NativeFunction(exportAddr('ntdll.dll', 'RtlZeroMemory'),
    'void', ['pointer', 'uint32']);

// Frida Memory.alloc blocks are freed once their JS wrapper is garbage-collected.
// The engine thread keeps using these buffers long after buildAndRun() returns,
// so every allocation must stay referenced for the whole script lifetime.
const KEEPALIVE = [];

function zalloc(size) {
    const p = Memory.alloc(size);
    KEEPALIVE.push(p);
    RtlZeroMemory(p, size);
    return p;
}

const REPORT_PATH = 'C:\\Users\\Administrator\\AppData\\Local\\Temp\\opencode\\crash_report.txt';

let taflib = null;
let trace = [];
let stubAddr = null;
let wPtr = null;

function tpush(tag) {
    trace.push(tag);
    if (trace.length > 64) trace.shift();
}

Process.setExceptionHandler(function (details) {
    try {
        const ctx = details.context || {};
        const lines = [];
        lines.push('type=' + details.type);
        lines.push('address=0x' + (details.address ? details.address.toString(16) : '?'));
        const pc = ctx.pc || ctx.eip;
        const sp = ctx.sp || ctx.esp;
        function r(n, v) { if (v !== undefined && v !== null) lines.push(n + '=0x' + v.toString(16)); }
        r('eip', pc); r('esp', sp);
        r('eax', ctx.eax); r('ebx', ctx.ebx); r('ecx', ctx.ecx); r('edx', ctx.edx);
        r('esi', ctx.esi); r('edi', ctx.edi); r('ebp', ctx.ebp);
        lines.push('trace=' + trace.join(' -> '));
        try {
            const b = new Uint8Array(ptr(sp).readByteArray(256));
            const dump = [];
            for (let i = 0; i + 4 <= b.length; i += 4) {
                const v = (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)) >>> 0;
                dump.push(('00000000' + v.toString(16)).slice(-8));
            }
            lines.push('stack=' + dump.join(' '));
        } catch (e) { lines.push('stack dump failed: ' + e); }
        const f = new File(REPORT_PATH, 'w');
        f.write(lines.join('\n') + '\n');
        f.flush();
        f.close();
    } catch (e) { }
    return false;
});

setInterval(function () {
    if (trace.length) {
        send({ type: 'trace_tail', trace: trace.slice() });
    }
}, 500);

function ensureTaflib() {
    if (taflib) return taflib;
    try {
        taflib = Process.getModuleByName(MODULE_NAME);
        console.log('[native] TAFLib already loaded base=' + taflib.base);
        return taflib;
    } catch (e) { }
    const LoadLibraryW = new NativeFunction(exportAddr('kernel32.dll', 'LoadLibraryW'),
        'pointer', ['pointer']);
    const path = Memory.allocUtf16String(DLL_PATH);
    const h = LoadLibraryW(path);
    if (h.isNull()) throw new Error('LoadLibraryW failed: ' + DLL_PATH);
    taflib = Process.getModuleByName(MODULE_NAME);
    console.log('[native] TAFLib loaded base=' + taflib.base + ' size=' + taflib.size);
    return taflib;
}

function installTrace(base) {
    TRACE_OFFS.forEach(function (item) {
        const p = base.add(item[0]);
        try {
            Interceptor.attach(p, {
                onEnter: function () { tpush(item[1]); },
            });
        } catch (e) {
            console.log('[trace] attach fail ' + item[1] + ': ' + e);
        }
    });
}

function safeU32(p) {
    try { return p.readU32(); } catch (e) { return 0xFFFFFFFF; }
}

function installProbes(base) {
    function dumpW(tag, wPtr) {
        const w = ptr(wPtr);
        send({
            type: 'probe',
            line: tag + ' W=0x' + w.toString(16) +
                ' begin=0x' + safeU32(w.add(4)).toString(16) +
                ' end=0x' + safeU32(w.add(8)).toString(16) +
                ' allocEnd=0x' + safeU32(w.add(0xC)).toString(16) +
                ' nrec=' + ((safeU32(w.add(8)) - safeU32(w.add(4))) / 0xA0 | 0),
        });
    }
    const probes = [
        [0x2C281, function (ctx) {
            const sp = ctx.esp;
            send({
                type: 'probe',
                line: 'sb40-call-stack [esp]=0x' + sp.readU32().toString(16) +
                    ' [esp+4]=0x' + sp.add(4).readU32().toString(16) +
                    ' [esp+8]=0x' + sp.add(8).readU32().toString(16) +
                    ' [esp+0xC]=0x' + sp.add(0xC).readU32().toString(16) +
                    ' [esp+0x10]=0x' + sp.add(0x10).readU32().toString(16),
            });
        }],
        [0x2C288, function (ctx) { dumpW('se200-call', ctx.eax); }],
        [0x3E200, function (ctx) { dumpW('se200-entry', ctx.eax); }],
        [0x3E243, function (ctx) {
            send({
                type: 'probe',
                line: 'iter_at-call ebx=0x' + ctx.ebx.toString(16) +
                    ' esi=0x' + ctx.esi.toString(16) +
                    ' k=' + ctx.esp.readU32() +
                    ' begin=0x' + safeU32(ptr(ctx.ebx).add(4)).toString(16) +
                    ' end=0x' + safeU32(ptr(ctx.ebx).add(8)).toString(16),
            });
        }],
    ];
    probes.forEach(function (item) {
        let hits = 0;
        try {
            Interceptor.attach(base.add(item[0]), {
                onEnter: function () {
                    if (hits++ >= 5) return;
                    try { item[1](this.context); } catch (e) {
                        send({ type: 'probe', line: 'probe@0x' + item[0].toString(16) + ' error: ' + e });
                    }
                },
            });
        } catch (e) {
            console.log('[probe] attach fail 0x' + item[0].toString(16) + ': ' + e);
        }
    });
}

function installChecks(base) {
    function sendLine(line) { send({ type: 'probe', line: line }); }
    function wline(tag) {
        if (!wPtr) return tag + ' W=?';
        const w = ptr(wPtr);
        return tag + ' W=0x' + w.toString(16) +
            ' begin=0x' + safeU32(w.add(4)).toString(16) +
            ' end=0x' + safeU32(w.add(8)).toString(16) +
            ' allocEnd=0x' + safeU32(w.add(0xC)).toString(16) +
            ' nrec=' + (((safeU32(w.add(8)) - safeU32(w.add(4))) / 0xA0) | 0);
    }
    function ff(rec, offs) {
        const out = [];
        for (let i = 0; i < offs.length; i++) {
            out.push(offs[i] + ':0x' + safeU32(ptr(rec).add(offs[i])).toString(16));
        }
        return out.join(' ');
    }
    Interceptor.attach(base.add(0x2C1D0), {
        onEnter: function () {
            try {
                const sp = this.context.esp;
                const cell = sp.add(4).readU32();
                const n = sp.add(8).readU32();
                const out = sp.add(0xC).readU32();
                const ser = sp.add(0x10).readU32();
                wPtr = ptr(cell).readU32();
                sendLine('c1d0-entry cell=0x' + cell.toString(16) + ' W=0x' + wPtr.toString(16) +
                    ' n=' + n + ' out=0x' + out.toString(16) + ' series=0x' + ser.toString(16));
                sendLine(wline('c1d0-in'));
            } catch (e) { sendLine('c1d0-entry err ' + e); }
        },
    });
    Interceptor.attach(base.add(0x3DB40), {
        onEnter: function () {
            try {
                const sp = this.context.esp;
                const n = sp.add(8).readU32();
                const b1 = ptr(sp.add(0xC).readU32());
                const b2 = ptr(sp.add(0x10).readU32());
                sendLine(wline('sb40-entry'));
                sendLine('sb40-in n=' + n +
                    ' buf1[' + ff(b1, [0, 4, 8, 12, 16, 20, 24, 28]) + ']' +
                    ' buf2[' + ff(b2, [0, 4, 8, 12, 16, 20, 24, 28]) + ']');
            } catch (e) { sendLine('sb40-entry err ' + e); }
        },
    });
    function pushProbe(off, tag, stride, cap) {
        let hits = 0;
        Interceptor.attach(base.add(off), {
            onEnter: function () {
                if (hits >= cap) return;
                hits++;
                try {
                    const cont = ptr(this.context.esi);
                    const rec = this.context.eax;
                    const b = safeU32(cont.add(4)), e = safeU32(cont.add(8));
                    sendLine(tag + '#' + hits + ' cont=0x' + cont.toString(16) +
                        ' nrec=' + (((e - b) / stride) | 0) + ' rec=0x' + rec.toString(16) +
                        ' ' + ff(rec, [0, 0xC, 0x20, 0x98]));
                } catch (err) { sendLine(tag + ' err ' + err); }
            },
        });
    }
    pushProbe(0x6A5E0, 'push-m0', 0xA0, 60);
    pushProbe(0x6A720, 'push-m5', 0x28, 40);
    let cpyHits = 0;
    Interceptor.attach(base.add(0x6B1C0), {
        onEnter: function () {
            if (cpyHits >= 60) return;
            cpyHits++;
            try {
                const c = this.context;
                sendLine('copyA0#' + cpyHits + ' dst=0x' + ptr(c.eax).toString(16) +
                    ' src=0x' + ptr(c.ebx).toString(16) + ' n=' + (c.edx.toUInt32() | 0) +
                    ' ' + ff(c.ebx, [0, 0xC, 0x20, 0x98]));
            } catch (err) { sendLine('copyA0 err ' + err); }
        },
    });
    Interceptor.attach(base.add(0x3E200), {
        onEnter: function () {
            try {
                sendLine(wline('se200-entry'));
                const w = ptr(wPtr);
                sendLine('se200-rec0 ' + ff(safeU32(w.add(4)), [0, 0xC, 0x20, 0x98]));
            } catch (e) { sendLine('se200 err ' + e); }
        },
    });
}

function rwxAlloc(size) {
    const VirtualAlloc = new NativeFunction(exportAddr('kernel32.dll', 'VirtualAlloc'),
        'pointer', ['pointer', 'uint32', 'uint32', 'uint32']);
    const p = VirtualAlloc(ptr(0), size, 0x3000, 0x40);
    if (p.isNull()) throw new Error('VirtualAlloc failed');
    KEEPALIVE.push(p);
    return p;
}

function initContainer(w, off, stride, cap) {
    const buf = zalloc(stride * cap);
    w.add(off).writeU32(0);
    w.add(off + 4).writeU32(u32(buf));
    w.add(off + 8).writeU32(u32(buf));
    w.add(off + 0xC).writeU32(u32(buf.add(stride * cap)));
}

function scanCodeRange(base, size) {
    const lo = 0x1001000, hi = 0x106E20B;
    let hits = 0;
    const samples = [];
    for (let rva = 0x1000; rva + 4 <= size; rva += 4) {
        let v;
        try { v = base.add(rva).readU32(); } catch (e) { break; }
        if (v >= lo && v <= hi) {
            hits++;
            if (samples.length < 8) {
                samples.push('rva=0x' + rva.toString(16) + '->0x' + v.toString(16));
            }
        }
    }
    send({ type: 'scan', base: base.toString(), hits: hits, samples: samples });
}

function buildAndRun(n, hBuf, lBuf) {
    const mod = ensureTaflib();
    const base = mod.base;
    const entryC1D0 = base.add(OFF_C1D0);
    const entryC4B0 = base.add(OFF_C4B0);

    const w = zalloc(0x60);
    initContainer(w, 0x00, 0xA0, n + 64);
    initContainer(w, 0x20, 0x28, 2 * n + 64);
    initContainer(w, 0x30, 0x28, 2 * n + 64);
    initContainer(w, 0x40, 0x28, 2 * n + 64);
    initContainer(w, 0x50, 0x28, 2 * n + 64);

    const pH = zalloc(8 * n);
    const pL = zalloc(8 * n);
    pH.writeByteArray(hBuf);
    pL.writeByteArray(lBuf);

    const pP = zalloc(8);
    pP.writeDouble(51.0);

    const series = zalloc(12);
    series.add(0).writeU32(u32(pH));
    series.add(4).writeU32(u32(pL));
    series.add(8).writeU32(u32(pP));

    const cell = zalloc(4);
    cell.writeU32(u32(w));

    const out = zalloc(8 * n);
    const out2 = zalloc(8 * n);
    const flag0 = zalloc(4);
    const flag1 = zalloc(4);
    const flag2 = zalloc(4);
    flag0.writeU32(0xAAAAAAAA);
    flag1.writeU32(0xEEEEEEEE);
    flag2.writeU32(0xEEEEEEEE);

    const stubMem = rwxAlloc(256);
    stubMem.writeByteArray([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC2, 0x04, 0x00]);
    stubAddr = stubMem;
    const vtbl = zalloc(12);
    vtbl.add(0).writeU32(0);
    vtbl.add(4).writeU32(u32(stubMem));
    vtbl.add(8).writeU32(0);
    const iface = zalloc(4);
    iface.writeU32(u32(vtbl));

    console.log('[native] n=' + n + ' W=' + w + ' pH=' + pH + ' pL=' + pL +
        ' out=' + out + ' stub=' + stubMem + ' c1d0=' + entryC1D0 + ' c4b0=' + entryC4B0);

    scanCodeRange(base, mod.size);
    if (!QUIET) {
        installTrace(base);
        installProbes(base);
        installChecks(base);
    }

    // trampoline executed on a fresh thread (faults land in our exception handler):
    //   [flag0]=0x11111111
    //   push iface; push series; push out; push n; push cell; call c1d0; add esp,20; mov [flag1],eax
    //   [flag0]=0x22222222
    //   mov eax,series; push iface; push out2; push n; push cell; call c4b0; add esp,16; mov [flag2],eax
    //   [flag0]=0x33333333
    //   ret
    const tramp = stubMem.add(16);
    function imm5(op, v) { return [op, v & 0xFF, (v >>> 8) & 0xFF, (v >>> 16) & 0xFF, (v >>> 24) & 0xFF]; }
    function mark(v) {
        const a = u32(flag0);
        return [0xC7, 0x05, a & 0xFF, (a >>> 8) & 0xFF, (a >>> 16) & 0xFF, (a >>> 24) & 0xFF,
                v & 0xFF, (v >>> 8) & 0xFF, (v >>> 16) & 0xFF, (v >>> 24) & 0xFF];
    }
    const code = [];
    code.push.apply(code, mark(0x11111111));
    code.push.apply(code, imm5(0x68, u32(iface)));
    code.push.apply(code, imm5(0x68, u32(series)));
    code.push.apply(code, imm5(0x68, u32(out)));
    code.push.apply(code, imm5(0x68, n));
    code.push.apply(code, imm5(0x68, u32(cell)));
    let rel = (u32(entryC1D0) - (u32(tramp) + 40)) >>> 0;
    code.push.apply(code, imm5(0xE8, rel));
    code.push(0x83); code.push(0xC4); code.push(0x14);
    code.push.apply(code, imm5(0xA3, u32(flag1)));
    code.push.apply(code, mark(0x22222222));
    code.push.apply(code, imm5(0xB8, u32(series)));
    code.push.apply(code, imm5(0x68, u32(iface)));
    code.push.apply(code, imm5(0x68, u32(out2)));
    code.push.apply(code, imm5(0x68, n));
    code.push.apply(code, imm5(0x68, u32(cell)));
    rel = (u32(entryC4B0) - (u32(tramp) + 88)) >>> 0;
    code.push.apply(code, imm5(0xE8, rel));
    code.push(0x83); code.push(0xC4); code.push(0x10);
    code.push.apply(code, imm5(0xA3, u32(flag2)));
    code.push.apply(code, mark(0x33333333));
    const exitSlot = stubMem.add(8);
    exitSlot.writePointer(exportAddr('kernel32.dll', 'ExitThread'));
    code.push(0x6A, 0x00);
    code.push(0xFF, 0x15);
    const es = u32(exitSlot);
    code.push(es & 0xFF, (es >>> 8) & 0xFF, (es >>> 16) & 0xFF, (es >>> 24) & 0xFF);
    code.push(0xCC);
    tramp.writeByteArray(code);

    const CreateThread = new NativeFunction(exportAddr('kernel32.dll', 'CreateThread'),
        'pointer', ['pointer', 'uint32', 'pointer', 'pointer', 'uint32', 'pointer']);
    const th = CreateThread(ptr(0), 0x400000, tramp, ptr(0), 0, ptr(0));
    console.log('[native] thread=' + th);
    send({ type: 'thread_started', thread: th.toString() });

    trace = [];
    let waited = 0;
    const timer = setInterval(function () {
        waited += 0.2;
        const f0 = flag0.readU32();
        const f1 = flag1.readU32();
        const f2 = flag2.readU32();
        if (f1 !== 0xEEEEEEEE && f2 !== 0xEEEEEEEE) {
            clearInterval(timer);
            console.log('[native] c1d0 rc=0x' + f1.toString(16) + ' c4b0 rc=0x' + f2.toString(16));
            send({ type: 'entry_result', entry: 'c1d0', rc: f1, n: n },
                out.readByteArray(8 * n));
            send({ type: 'entry_result', entry: 'c4b0', rc: f2, n: n },
                out2.readByteArray(8 * n));
            send({ type: 'done' });
        } else if (waited > 45) {
            clearInterval(timer);
            send({
                type: 'thread_timeout', flag0: f0, flag1: f1, flag2: f2,
                trace: trace.slice()
            });
        }
    }, 200);
}

recv('run', function (message, data) {
    try {
        const n = message.n;
        const all = new Uint8Array(data);
        const hBuf = all.slice(0, 8 * n).buffer;
        const lBuf = all.slice(8 * n, 16 * n).buffer;
        buildAndRun(n, hBuf, lBuf);
    } catch (e) {
        send({ type: 'script_error', stack: e.stack || String(e), trace: trace.slice() });
    }
});

send({ type: 'script_ready' });
