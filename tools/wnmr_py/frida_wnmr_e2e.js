'use strict';
// WNMR_线段 (无脑买入线段) end-to-end native verification inside a 32-bit host.
//
// Real TAFLib.dll chain, all natively executed:
//   CHBI(c1d0)  -> fills W (笔 objects, stride 0xA0)
//   CHDUAN      -> prepare(W) + outDuan[i] = (double)obj[+0x24]
//   [snapshot W->m[0] records: sent to Python for wnmr.py replay]
//   WNMRNEW     -> outWnmr[index-1] = obj[+0x90]
//   WNMRPRINEW  -> outPri [index-1] = obj[+0x94]
//
// Entry conventions (verified from disassembly 2026-10-19):
//   c1d0 (0x2C1D0) cdecl : cell, count, out, series, iface
//   CHDUAN (0x2C710)     : ecx=count, eax=cell, [out, ctx], ret 8
//   WNMRNEW (0x3A7C0)    : ecx=count, eax=cell, [out, holder(double** in), ctx], ret 0xC
//   WNMRPRINEW (0x3A960) : ecx=count, eax=cell, edx=ctx, [out], ret 4
//   ctx vtable slot 1 = Authorize stub: mov eax,1; ret 4

const MODULE_NAME = 'TAFLib.dll';
const DLL_PATH = 'D:\\a_ronglide\\缠中说禅\\TAFLib.dll';
const OFF_C1D0 = 0x2C1D0;
const OFF_CHDUAN = 0x2C710;
const OFF_WNMRNEW = 0x3A7C0;
const OFF_WNMRPRI = 0x3A960;

function exportAddr(modName, name) {
    return Process.getModuleByName(modName).getExportByName(name);
}

function u32(p) { return p.toUInt32(); }

const RtlZeroMemory = new NativeFunction(exportAddr('ntdll.dll', 'RtlZeroMemory'),
    'void', ['pointer', 'uint32']);

const KEEPALIVE = [];

function zalloc(size) {
    const p = Memory.alloc(size);
    KEEPALIVE.push(p);
    RtlZeroMemory(p, size);
    return p;
}

function rwxAlloc(size) {
    const VirtualAlloc = new NativeFunction(exportAddr('kernel32.dll', 'VirtualAlloc'),
        'pointer', ['pointer', 'uint32', 'uint32', 'uint32']);
    const p = VirtualAlloc(ptr(0), size, 0x3000, 0x40);
    if (p.isNull()) throw new Error('VirtualAlloc failed');
    KEEPALIVE.push(p);
    return p;
}

const REPORT_PATH = 'C:\\Users\\Administrator\\AppData\\Local\\Temp\\opencode\\wnmr_e2e_crash.txt';

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
        try {
            const b = new Uint8Array(ptr(sp).readByteArray(192));
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

let taflib = null;

function ensureTaflib() {
    if (taflib) return taflib;
    try {
        taflib = Process.getModuleByName(MODULE_NAME);
        return taflib;
    } catch (e) { }
    const LoadLibraryW = new NativeFunction(exportAddr('kernel32.dll', 'LoadLibraryW'),
        'pointer', ['pointer']);
    const path = Memory.allocUtf16String(DLL_PATH);
    const h = LoadLibraryW(path);
    if (h.isNull()) throw new Error('LoadLibraryW failed: ' + DLL_PATH);
    taflib = Process.getModuleByName(MODULE_NAME);
    return taflib;
}

function initContainer(w, off, stride, cap) {
    const buf = zalloc(stride * cap);
    w.add(off).writeU32(0);
    w.add(off + 4).writeU32(u32(buf));
    w.add(off + 8).writeU32(u32(buf));
    w.add(off + 0xC).writeU32(u32(buf.add(stride * cap)));
}

function imm32(op, v) {
    v = v >>> 0;
    return [op, v & 0xFF, (v >>> 8) & 0xFF, (v >>> 16) & 0xFF, (v >>> 24) & 0xFF];
}

function buildAndRun(n, hBuf, lBuf, probe) {
    const mod = ensureTaflib();
    const base = mod.base;

    // ---- W container (same layout as the verified CHBI harness) ----
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

    const outChbi = zalloc(8 * n);
    const outDuan = zalloc(8 * n);
    const outWnmr = zalloc(8 * n);
    const outPri = zalloc(8 * n);
    const holder = zalloc(4);
    holder.writeU32(u32(outDuan));

    const flag0 = zalloc(4);
    const flag1 = zalloc(4);
    const flag2 = zalloc(4);
    const flag3 = zalloc(4);
    const flag4 = zalloc(4);
    flag0.writeU32(0xAAAAAAAA);
    flag1.writeU32(0xEEEEEEEE);
    flag2.writeU32(0xEEEEEEEE);
    flag3.writeU32(0xEEEEEEEE);
    flag4.writeU32(0xEEEEEEEE);

    // auth stub + ctx object
    const stubMem = rwxAlloc(256);
    stubMem.writeByteArray([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC2, 0x04, 0x00]);
    const vtbl = zalloc(12);
    vtbl.add(0).writeU32(0);
    vtbl.add(4).writeU32(u32(stubMem));
    vtbl.add(8).writeU32(0);
    const ctx = zalloc(4);
    ctx.writeU32(u32(vtbl));

    send({
        type: 'e2e_meta', n: n,
        addrs: {
            c1d0: base.add(OFF_C1D0).toString(),
            chduan: base.add(OFF_CHDUAN).toString(),
            wnmrnew: base.add(OFF_WNMRNEW).toString(),
            wnmrpri: base.add(OFF_WNMRPRI).toString(),
        }
    });

    // ================= phase 1: CHBI + CHDUAN =================
    const tramp1 = stubMem.add(16);
    const code1 = [];
    function mark1(v) {
        const a = u32(flag0);
        code1.push(0xC7, 0x05, a & 0xFF, (a >>> 8) & 0xFF, (a >>> 16) & 0xFF, (a >>> 24) & 0xFF,
            v & 0xFF, (v >>> 8) & 0xFF, (v >>> 16) & 0xFF, (v >>> 24) & 0xFF);
    }
    function call1(target) {
        const next = u32(tramp1) + code1.length + 5;
        const rel = (u32(target) - next) >>> 0;
        code1.push(0xE8);
        code1.push(rel & 0xFF, (rel >>> 8) & 0xFF, (rel >>> 16) & 0xFF, (rel >>> 24) & 0xFF);
    }

    mark1(0x11111111);
    code1.push.apply(code1, imm32(0x68, u32(ctx)));
    code1.push.apply(code1, imm32(0x68, u32(series)));
    code1.push.apply(code1, imm32(0x68, u32(outChbi)));
    code1.push.apply(code1, imm32(0x68, n));
    code1.push.apply(code1, imm32(0x68, u32(cell)));
    call1(base.add(OFF_C1D0));
    code1.push(0x83, 0xC4, 0x14);
    code1.push.apply(code1, imm32(0xA3, u32(flag1)));

    mark1(0x22222222);
    code1.push.apply(code1, imm32(0x68, u32(ctx)));
    code1.push.apply(code1, imm32(0x68, u32(outDuan)));
    code1.push.apply(code1, imm32(0xB8, u32(cell)));
    code1.push.apply(code1, imm32(0xB9, n));
    call1(base.add(OFF_CHDUAN));
    code1.push(0x83, 0xC4, 0x08);
    code1.push.apply(code1, imm32(0xA3, u32(flag2)));

    mark1(0x33333333);
    const exitSlot1 = zalloc(4);
    exitSlot1.writePointer(exportAddr('kernel32.dll', 'ExitThread'));
    code1.push(0x6A, 0x00);
    code1.push(0xFF, 0x15);
    const es1 = u32(exitSlot1);
    code1.push(es1 & 0xFF, (es1 >>> 8) & 0xFF, (es1 >>> 16) & 0xFF, (es1 >>> 24) & 0xFF);
    code1.push(0xCC);
    tramp1.writeByteArray(code1);

    const CreateThread = new NativeFunction(exportAddr('kernel32.dll', 'CreateThread'),
        'pointer', ['pointer', 'uint32', 'pointer', 'pointer', 'uint32', 'pointer']);
    const th1 = CreateThread(ptr(0), 0x400000, tramp1, ptr(0), 0, ptr(0));
    send({ type: 'phase1_started', thread: th1.toString() });

    let waited = 0;
    const timer1 = setInterval(function () {
        waited += 0.2;
        if (flag1.readU32() !== 0xEEEEEEEE && flag2.readU32() !== 0xEEEEEEEE) {
            clearInterval(timer1);
            if (flag1.readU32() !== 0 || flag2.readU32() !== 0) {
                send({ type: 'phase1_error', rc_chbi: flag1.readU32(), rc_chduan: flag2.readU32(), flag0: flag0.readU32() });
                return;
            }
            const begin = safeU32(w.add(4));
            const end = safeU32(w.add(8));
            const nrec = ((end - begin) / 0xA0) | 0;
            send({
                type: 'phase1_done', nrec: nrec,
                w_begin: begin, w_end: end, w_alloc: safeU32(w.add(0xC)),
            });
            try {
                if (nrec > 0 && nrec < 2000000) {
                    send({ type: 'w_snapshot', nrec: nrec },
                        ptr(begin).readByteArray(nrec * 0xA0));
                } else {
                    send({ type: 'w_snapshot', nrec: nrec, skipped: true });
                }
                send({ type: 'out', name: 'chbi', n: n }, outChbi.readByteArray(8 * n));
                send({ type: 'out', name: 'chduan', n: n }, outDuan.readByteArray(8 * n));
            } catch (e) {
                send({ type: 'snapshot_error', msg: String(e) });
            }
            startPhase2();
        } else if (waited > 300) {
            clearInterval(timer1);
            send({ type: 'phase1_timeout', flag0: flag0.readU32(), flag1: flag1.readU32(), flag2: flag2.readU32() });
        }
    }, 200);

    // ================= phase 2: WNMRNEW + WNMRPRINEW =================
    let phase2Started = false;
    function startPhase2() {
        if (phase2Started) return;
        phase2Started = true;
        const tramp2 = rwxAlloc(256);
        const code2 = [];
        function mark2(v) {
            const a = u32(flag0);
            code2.push(0xC7, 0x05, a & 0xFF, (a >>> 8) & 0xFF, (a >>> 16) & 0xFF, (a >>> 24) & 0xFF,
                v & 0xFF, (v >>> 8) & 0xFF, (v >>> 16) & 0xFF, (v >>> 24) & 0xFF);
        }
        function call2(target) {
            const next = u32(tramp2) + code2.length + 5;
            const rel = (u32(target) - next) >>> 0;
            code2.push(0xE8);
            code2.push(rel & 0xFF, (rel >>> 8) & 0xFF, (rel >>> 16) & 0xFF, (rel >>> 24) & 0xFF);
        }

        // ---- optional diagnostic: tag the four buy-instance status-1 writes ----
        // The immediate operand of `mov dword [esi+0x90],1` is rewritten to
        // 0x11..0x14 per instance. Pure data patch, no code-flow change.
        let probeCounts = null;
        if (probe) {
            const VirtualProtect = new NativeFunction(exportAddr('kernel32.dll', 'VirtualProtect'),
                'int', ['pointer', 'uint32', 'uint32', 'pointer']);
            const oldProt = zalloc(4);
            [0x5a1fa, 0x5a85c, 0x5bcd4, 0x5cae3].forEach(function (off, k) {
                const p = base.add(off + 7);   // C7 86 90 00 00 00 <imm32>

                VirtualProtect(p, 1, 0x40, oldProt);
                p.writeU8(0x11 + k);
            });
            send({ type: 'instances_tagged' });
        }

        mark2(0x44444444);
        code2.push.apply(code2, imm32(0x68, u32(ctx)));
        code2.push.apply(code2, imm32(0x68, u32(holder)));
        code2.push.apply(code2, imm32(0x68, u32(outWnmr)));
        code2.push.apply(code2, imm32(0xB8, u32(cell)));
        code2.push.apply(code2, imm32(0xB9, n));
        call2(base.add(OFF_WNMRNEW));
        code2.push(0x83, 0xC4, 0x0C);
        code2.push.apply(code2, imm32(0xA3, u32(flag3)));

        mark2(0x55555555);
        code2.push.apply(code2, imm32(0x68, u32(outPri)));
        code2.push.apply(code2, imm32(0xB8, u32(cell)));
        code2.push.apply(code2, imm32(0xB9, n));
        code2.push.apply(code2, imm32(0xBA, u32(ctx)));
        call2(base.add(OFF_WNMRPRI));
        code2.push(0x83, 0xC4, 0x04);
        code2.push.apply(code2, imm32(0xA3, u32(flag4)));

        mark2(0x66666666);
        const exitSlot2 = zalloc(4);
        exitSlot2.writePointer(exportAddr('kernel32.dll', 'ExitThread'));
        code2.push(0x6A, 0x00);
        code2.push(0xFF, 0x15);
        const es2 = u32(exitSlot2);
        code2.push(es2 & 0xFF, (es2 >>> 8) & 0xFF, (es2 >>> 16) & 0xFF, (es2 >>> 24) & 0xFF);
        code2.push(0xCC);
        tramp2.writeByteArray(code2);

        const th2 = CreateThread(ptr(0), 0x400000, tramp2, ptr(0), 0, ptr(0));
        send({ type: 'phase2_started', thread: th2.toString() });

        let waited2 = 0;
        const timer2 = setInterval(function () {
            waited2 += 0.2;
            if (flag3.readU32() !== 0xEEEEEEEE && flag4.readU32() !== 0xEEEEEEEE) {
                clearInterval(timer2);
                const end2 = safeU32(w.add(8));
                const begin2 = safeU32(w.add(4));
                const nrec2 = ((end2 - begin2) / 0xA0) | 0;
                send({
                    type: 'phase2_done',
                    rc_wnmrnew: flag3.readU32(),
                    rc_wnmrpri: flag4.readU32(),
                    nrec_after: nrec2,
                });
                // post-WNMR container census + m[0] snapshot (debug: where status landed)
                const census = {};
                const specs = [[0x00, 0xA0], [0x20, 0x28], [0x30, 0x28], [0x40, 0x28], [0x50, 0x28]];
                specs.forEach(function (sp) {
                    const b = safeU32(w.add(sp[0] + 4));
                    const e = safeU32(w.add(sp[0] + 8));
                    census['m' + (sp[0] / 0x10 | 0)] = ((e - b) / sp[1]) | 0;
                });
                send({ type: 'post_census', census: census });
                try {
                    if (nrec2 > 0 && nrec2 < 2000000) {
                        send({ type: 'w_post', nrec: nrec2 },
                            ptr(begin2).readByteArray(nrec2 * 0xA0));
                    }
                    specs.forEach(function (sp) {
                        if (sp[0] === 0) return;
                        const b = safeU32(w.add(sp[0] + 4));
                        const e = safeU32(w.add(sp[0] + 8));
                        const cnt = ((e - b) / sp[1]) | 0;
                        if (cnt > 0 && cnt < 2000000) {
                            send({ type: 'container', off: sp[0], stride: sp[1], cnt: cnt },
                                ptr(b).readByteArray(cnt * sp[1]));
                        }
                    });
                } catch (e) { send({ type: 'post_snapshot_error', msg: String(e) }); }
                send({ type: 'out', name: 'wnmr', n: n }, outWnmr.readByteArray(8 * n));
                send({ type: 'out', name: 'wnmrpri', n: n }, outPri.readByteArray(8 * n));
                send({ type: 'done' });
            } else if (waited2 > 300) {
                clearInterval(timer2);
                send({ type: 'phase2_timeout', flag0: flag0.readU32(), flag3: flag3.readU32(), flag4: flag4.readU32() });
            }
        }, 200);
    }
}

function safeU32(p) {
    try { return p.readU32(); } catch (e) { return 0xFFFFFFFF; }
}

recv('run', function (message, data) {
    try {
        const n = message.n;
        const all = new Uint8Array(data);
        const hBuf = all.slice(0, 8 * n).buffer;
        const lBuf = all.slice(8 * n, 16 * n).buffer;
        buildAndRun(n, hBuf, lBuf, !!message.probe);
    } catch (e) {
        send({ type: 'script_error', stack: e.stack || String(e) });
    }
});

send({ type: 'script_ready' });
