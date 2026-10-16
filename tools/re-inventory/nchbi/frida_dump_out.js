// frida_dump_out.js — NChBi 族 out[] / Item21 出口 dump（第三批 T4 预备包）
// 目标模块: chlib.dll（TAFLib.dll 通过 IAT 0x1006f328 动态加载）
// 本脚本【未在本批运行】；等交易软件启动、用户在场时执行。
//
// 用法（任选其一）:
//   frida -f "MainApp.exe" -l frida_dump_out.js --no-pause
//   frida -p <pid>        -l frida_dump_out.js
// 先找 pid:
//   任务管理器 / `tasklist | findstr /i "MainApp"`
//   frida-ps | findstr /i "MainApp"
//
// 输出: 每个命中函数的 out[count](double) 全量 + 入口快照(Item21/Rec20)
//       （count 上限 PRINT_MAX；超出只打头部/尾部并注明）

'use strict';

const MODULE   = 'chlib.dll';
const PRINT_MAX = 4096;   // out[] 最多打印多少个 double
const SNAP_MAX  = 128;    // Item21 / Rec20 最多打印多少条

// fn RVA -> 元数据。__thiscall + ret 0x10：
//   arg1 = [esp+4] (count)   arg2 = [esp+8] (out: double[count])
//   this  = ecx
const TARGETS = {
  '0x10002340': { name: 'NChBi',        countArg: 1, outArg: 2 },
  '0x10002770': { name: 'NChBiSta',     countArg: 1, outArg: 2 },
  '0x10002ea0': { name: 'NChBiZj',      countArg: 1, outArg: 2 },
  '0x10003180': { name: 'NChBiZjOrder', countArg: 1, outArg: 2 },
  '0x100038b0': { name: 'NChBiZjNum',   countArg: 1, outArg: 2 },
};

// Item21: stride 0x21（33B）  value@+0x00(i32) flags@+0x04(u8) ord@+0x05(i32)
//                            recIdx@+0x09(i32) d1@+0x0d(f64) d2@+0x15(f64) barIdx@+0x1d(i32)
// Rec20 : stride 0x20（32B）  startBar@+0x00(i32) ...（对象链见 docs/27）
const ITEM21_STRIDE = 0x21;
const REC20_STRIDE  = 0x20;

function readItem21(base, n) {
  const out = [];
  const lim = n < SNAP_MAX ? n : SNAP_MAX;
  for (let i = 0; i < lim; i++) {
    const p = base.add(i * ITEM21_STRIDE);
    try {
      out.push({
        i: i,
        value:  p.add(0x00).readS32(),
        flags:  p.add(0x04).readU8(),
        ord:    p.add(0x05).readS32(),
        recIdx: p.add(0x09).readS32(),
        d1:     p.add(0x0d).readDouble(),
        d2:     p.add(0x15).readDouble(),
        barIdx: p.add(0x1d).readS32(),
      });
    } catch (e) { out.push({ i: i, err: String(e) }); }
  }
  if (n > lim) out.push({ truncated: true, total: n });
  return out;
}

function readRec20(base, n) {
  const out = [];
  const lim = n < SNAP_MAX ? n : SNAP_MAX;
  for (let i = 0; i < lim; i++) {
    const p = base.add(i * REC20_STRIDE);
    try {
      out.push({ i: i, startBar: p.add(0x00).readS32(), endBar: p.add(0x04).readS32() });
    } catch (e) { out.push({ i: i, err: String(e) }); }
  }
  if (n > lim) out.push({ truncated: true, total: n });
  return out;
}

function snapContainers(thisPtr) {
  // this -> ch_api；obj8=this[+8]；obj10=this[+0x10]
  const snap = {};
  try {
    const obj8  = thisPtr.add(0x08).readPointer();
    const obj10 = thisPtr.add(0x10).readPointer();
    snap.obj8 = ptr(obj8);
    snap.obj10 = ptr(obj10);
    if (!obj8.isNull()) {
      const recBase = obj8.add(0x1c).readPointer();
      const recCnt  = obj8.add(0x28).readS32();
      snap.rec20 = { base: recBase, count: recCnt,
                     items: recBase.isNull() ? [] : readRec20(recBase, recCnt) };
    }
    if (!obj10.isNull()) {
      const typeCode = obj10.add(0x1c).readS32();
      const itBase   = obj10.add(0x30).readPointer();
      const itCnt    = obj10.add(0x3c).readS32();
      snap.obj10_typeCode = typeCode;
      snap.item21 = { base: itBase, count: itCnt,
                      items: itBase.isNull() ? [] : readItem21(itBase, itCnt) };
    }
  } catch (e) { snap.err = String(e); }
  return snap;
}

function dumpOut(outPtr, count) {
  const res = { count: count, values: [] };
  if (outPtr.isNull() || count <= 0) return res;
  const lim = count < PRINT_MAX ? count : PRINT_MAX;
  try {
    // 全量按数组读一次（快），再切片
    const arr = outPtr.readDoubleArray(lim);
    res.values = Array.prototype.slice.call(arr);
  } catch (e) {
    for (let i = 0; i < lim; i++) {
      try { res.values.push(outPtr.add(i * 8).readDouble()); }
      catch (e2) { res.values.push(null); break; }
    }
    res.readErr = String(e);
  }
  if (count > lim) res.truncated = true;
  return res;
}

function main() {
  const m = Process.findModuleByName(MODULE);
  if (!m) {
    console.log('[!] ' + MODULE + ' 未加载。请在交易软件打开(触发 chlib 载入)后再 attach，或用 -f 启动。');
    return;
  }
  console.log('[*] ' + MODULE + ' base = ' + m.base + '  size = ' + m.size);

  Object.keys(TARGETS).forEach(function (rvaStr) {
    const rva = ptr(rvaStr);
    const addr = m.base.add(rva);
    const meta = TARGETS[rvaStr];
    let ctx = null;

    Interceptor.attach(addr, {
      onEnter: function (args) {
        try {
          const esp = this.context.esp;
          const count = esp.add(4).readS32();          // arg1
          const outPtr = esp.add(8).readPointer();      // arg2
          const thisPtr = this.context.ecx;             // ch_api*
          ctx = { count: count, out: outPtr };
          console.log('\n===== ENTER ' + meta.name + ' @' + addr +
                      '  count=' + count + ' out=' + outPtr + ' this=' + thisPtr + ' =====');
          this.snap = snapContainers(thisPtr);
          this.outPtr = outPtr;
          this.count = count;
          this.retval = null;
        } catch (e) { ctx = null; console.log('[!] ' + meta.name + ' onEnter: ' + e); }
      },
      onLeave: function (retval) {
        if (!ctx) return;
        try {
          console.log('--- retval = ' + retval + '  (0=ok, -1=fail)');
          console.log('--- container snapshot:');
          console.log(JSON.stringify(this.snap, null, 1));
          console.log('--- out[' + this.count + '] dump:');
          console.log(JSON.stringify(dumpOut(this.outPtr, this.count)));
          console.log('===== LEAVE ' + meta.name + ' =====\n');
        } catch (e) { console.log('[!] ' + meta.name + ' onLeave: ' + e); }
      },
    });
    console.log('[*] hooked ' + meta.name + ' @ ' + addr);
  });
}

setImmediate(main);
