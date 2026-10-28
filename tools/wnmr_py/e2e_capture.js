'use strict';
// e2e_capture.js - capture CHBI P=51 input (H,L,P) + output (out[]) from the live client.
// Hooks TAFLib.dll entries:
//   0x1002C4B0  (EAX = series; stack args: W**, count, out, iface)
//   0x1002C1D0  (stack args: W**, count, out, series, iface)
// Only P == 51 calls are captured (binary send: H || L || out, each count*8 bytes).
// Other P values are logged (rate-limited) for identification of app behavior.

const MODULE = 'TAFLib.dll';
const RVA_C4B0 = 0x2C4B0;
const RVA_C1D0 = 0x2C1D0;

let mod;
try {
    mod = Process.getModuleByName(MODULE);
} catch (e) {
    console.log('[e2e] module not found: ' + MODULE);
    throw e;
}
const base = mod.base;
console.log('[e2e] TAFLib base=' + base + ' size=' + mod.size);

let seq = 0;
const seen = {};

function note(tag) {
    seen[tag] = (seen[tag] || 0) + 1;
    if (seen[tag] <= 5) {
        console.log('[e2e] ' + tag +
            (seen[tag] === 5 ? ' (further identical logs suppressed)' : ''));
    }
}

function readSeries(sp) {
    const pH = sp.readPointer();
    const pL = sp.add(4).readPointer();
    const pP = sp.add(8).readPointer();
    return { pH: pH, pL: pL, pP: pP, pv: pP.readDouble() };
}

function install(entry, rva, nArgs, seriesGetter) {
    Interceptor.attach(base.add(rva), {
        onEnter: function (args) {
            try {
                var sp;
                try {
                    sp = seriesGetter(this, args);
                } catch (e) {
                    sp = null;
                }
                if (sp === null || sp.isNull()) return;
                var s = readSeries(sp);
                this.id = ++seq;
                this.entry = entry;
                this.count = args[1].toInt32();
                this.outPtr = args[2];
                this.pv = s.pv;
                this.pH = s.pH;
                this.pL = s.pL;
                this.want = (s.pv === 51);
                note(entry + ' p=' + s.pv + ' n=' + this.count);
                var tag = entry + '_args';
                seen[tag] = (seen[tag] || 0) + 1;
                if (seen[tag] <= 3) {
                    var parts = [];
                    for (var i = 0; i < nArgs; i++) parts.push(args[i].toString());
                    console.log('[e2e] ' + entry + ' first-call args=' + parts.join(','));
                }
                if (this.want) {
                    console.log('[e2e] ' + entry + '#' + this.id + ' ENTER count=' + this.count +
                        ' P=' + s.pv + ' out=' + this.outPtr);
                }
            } catch (e) {
                this.want = false;
            }
        },
        onLeave: function (ret) {
            try {
                if (!this.want) return;
                var rc = ret.toInt32();
                console.log('[e2e] ' + this.entry + '#' + this.id + ' LEAVE rc=' + rc);
                if (rc !== 0) return;
                var n = this.count;
                if (n <= 1 || n > 300000) {
                    console.log('[e2e] ' + this.entry + '#' + this.id +
                        ' count out of range for capture: ' + n);
                    return;
                }
                var h = this.pH.readByteArray(8 * n);
                var l = this.pL.readByteArray(8 * n);
                var o = this.outPtr.readByteArray(8 * n);
                if (h === null || l === null || o === null) {
                    console.log('[e2e] ' + this.entry + '#' + this.id +
                        ' readByteArray returned null');
                    return;
                }
                var buf = new ArrayBuffer(24 * n);
                var dst = new Uint8Array(buf);
                dst.set(new Uint8Array(h), 0);
                dst.set(new Uint8Array(l), 8 * n);
                dst.set(new Uint8Array(o), 16 * n);
                send({
                    name: 'e2e_capture',
                    payload: {
                        entry: this.entry,
                        id: this.id,
                        count: n,
                        p: this.pv,
                        layout: 'h|l|out each count*8 bytes float64 LE'
                    }
                }, buf);
                console.log('[e2e] ' + this.entry + '#' + this.id + ' captured ' + n + ' bars');
            } catch (e) {
                console.log('[e2e] capture error: ' + e);
            }
        }
    });
    console.log('[e2e] hook installed: ' + entry + ' @ ' + base.add(rva));
}

install('c4b0', RVA_C4B0, 4, function (self, args) { return self.context.eax; });
install('c1d0', RVA_C1D0, 5, function (self, args) { return args[3]; });
console.log('[e2e] ready');
