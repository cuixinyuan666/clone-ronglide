'use strict';
// CHBI P=51 live dump for the 58560-bar comparison.
// Hooks both real entry points inside TAFLib.dll:
//   0x1002c4b0  hardcoded P=51 entry   (series in EAX, args: W**,count,out,iface)
//   0x1002c1d0  generic entry          (args: W**,count,out,series,iface)
// On successful return the out[] double array is sent to the Python side.

const MODULE_NAME = 'TAFLib.dll';
const OFF_C4B0 = 0x2c4b0;
const OFF_C1D0 = 0x2c1d0;

function dumpOut(tag, count, outPtr) {
    const arr = [];
    for (let i = 0; i < count; i++) {
        arr.push(outPtr.add(i * 8).readDouble());
    }
    send({
        name: 'chbi_p51_out',
        payload: {
            entry: tag,
            count: count,
            out: arr,
        },
    });
}

function hookEntry(moduleBase, offset, tag, getSeries) {
    const target = moduleBase.add(offset);
    Interceptor.attach(target, {
        onEnter: function (args) {
            this.count = args[1].toInt32();
            this.outPtr = args[2];
            try {
                this.series = getSeries.call(this, args);
                const pP = this.series.add(8).readPointer();
                this.pVal = pP.readDouble();
            } catch (e) {
                this.pVal = null;
            }
            if (this.pVal !== null && Math.abs(this.pVal - 51.0) > 1e-9) {
                console.log('[chbi] ' + tag + ' enter count=' + this.count +
                    ' P=' + this.pVal + ' (skip, not P=51)');
                this.skip = true;
                return;
            }
            console.log('[chbi] ' + tag + ' enter count=' + this.count +
                ' P=' + this.pVal + ' out=' + this.outPtr);
            this.armed = this.count > 0;
        },
        onLeave: function (retval) {
            if (!this.armed || this.skip) {
                return;
            }
            const rc = retval.toInt32();
            if (rc === 0) {
                console.log('[chbi] ' + tag + ' done, dumping ' + this.count + ' doubles');
                dumpOut(tag, this.count, this.outPtr);
            } else {
                console.log('[chbi] ' + tag + ' failed, ret=' + rc);
            }
        },
    });
    console.log('[chbi] hooked ' + tag + ' @ ' + target);
}

const mod = Process.getModuleByName(MODULE_NAME);
const base = mod.base;
console.log('[chbi] ' + MODULE_NAME + ' base=' + base);

hookEntry(base, OFF_C4B0, 'c4b0', function () {
    return this.context.eax;
});
hookEntry(base, OFF_C1D0, 'c1d0', function (args) {
    return args[3];
});
