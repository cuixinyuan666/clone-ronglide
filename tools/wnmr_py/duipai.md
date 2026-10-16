# 58560 点对拍方案（CHBI 第五批）

> 数据集: `D:/a_ronglide/缠中说禅/Dat/His/02/1/600000.1`（浦发银行 2017 全年 1 分钟线）
> 规模: 2,108,228 字节 = 68 字节头 + 58,560 条 × 36 字节
> 字段表: 9 字段（ID 102/101/104/105/107/108/211/214/225），已 100% 解码（docs/2026-10-15 报告）
> 字段顺序: **[日期, 时间, 开, 收, 高, 低, 量, 额, 保留]**
> 置信度: [A] 字节级实证 ｜ [B] 多路交叉 ｜ [C] 待仲裁

---

## §0 字段定位 [A]

```
+0x00 (4B) u32  date  (YYYYMMDD 整数，如 20170103)
+0x04 (4B) u32  time  (HHMMSS 整数，如 093100)
+0x08 (4B) f32  open
+0x0C (4B) f32  close
+0x10 (4B) f32  high  ← H
+0x14 (4B) f32  low   ← L
+0x18 (4B) u32  volume
+0x1C (4B) u32  amount
+0x20 (4B) u32  reserved
+0x24 (4B)   9 字段共 36 字节
```

注：2017 全年 244 交易日 × 240 分钟 = 58,560 条，时间范围 2017-01-03 ~ 2017-12-29。

---

## §1 Python 重放端（`tools/wnmr_py/dupai_load.py`）[A]

### §1.1 加载 .1 文件

```python
import struct

def load_tdx(path, skip_header=68, record_size=36):
    """加载通达信 .1 数据文件，返回 dict 列表（每条 36 字节）。"""
    with open(path, 'rb') as f:
        f.seek(skip_header)
        raw = f.read()
    n = len(raw) // record_size
    out = []
    for i in range(n):
        b = raw[i*record_size:(i+1)*record_size]
        d = struct.unpack('<IIffffIII', b)
        out.append({
            'date': d[0], 'time': d[1],
            'open': d[2], 'close': d[3],
            'high': d[4], 'low':  d[5],   # ← chbi 输入的 H, L
            'volume': d[6], 'amount': d[7],
        })
    return out


def to_chbi_input(records):
    """转换为 chbi.py 的 H, L 列表。"""
    H = [r['high'] for r in records]
    L = [r['low']  for r in records]
    return H, L
```

### §1.2 调用 chbi.py

```python
from tools.wnmr_py.chbi import chbi_p51_replay  # 引入 P=51 全链

records = load_tdx(r'D:/a_ronglide/缠中说禅/Dat/His/02/1/600000.1')
H, L = to_chbi_input(records)
outD = chbi_p51_replay(H, L, count=len(records), iface_authorize_ok=True)

# 写出 outD 用于 frida 对拍
import json
with open('chbi_p51_600000.json', 'w') as f:
    json.dump({
        'count': len(records),
        'out_nonzero': [(i+1, v) for i, v in enumerate(outD or []) if v != 0.0],
    }, f, indent=2)
```

预期产出 58,560 长度的 outD 数组；非零位 = 笔端点 ±1 / ±2。

---

## §2 frida 侧 dump 方案 [B]

### §2.1 挂载点

目标函数: `ChBi` @ `0x1000f580`（TAFLib.dll，ImageBase 0x10000000）。
**双入口**：
- `sub_1002c1d0(series, ctx, count, outD, iface)`：通用 P 入口（P=11/12/21/22/31/32/51）
- `sub_1002c4b0(series, ctx, count, outD, iface)`：硬编码 P=51 入口

挂 `0x1002c4b0` 即可覆盖 P=51 全链（与 chbi.py 对应）。

### §2.2 frida 脚本骨架（`tools/wnmr_py/frida_chbi_600000.js`）

```javascript
'use strict';
const MOD = 'TAFLib.dll';
const BASE = ptr('0x10000000');

const target = BASE.add(0x1002c4b0 - 0x10000000);
const iface_vtbl_query = BASE.add(0x1002c334 - 0x10000000);  // EA62 门
const output_loop = BASE.add(0x1002c33a - 0x10000000);        // 输出环入口

Interceptor.attach(target, {
    onEnter: function(args) {
        this.series = args[0];
        this.ctx = args[1];
        this.count = args[2].toInt32();
        this.outD = args[3];
        this.iface = args[4];
        console.log('[chbi:p51] enter, count=' + this.count +
                    ' outD=' + this.outD +
                    ' iface=' + this.iface);
        this.outD_pre = this.outD.readByteArray(this.count * 8);
    },
    onLeave: function(retval) {
        if (retval.toInt32() === 0) {
            // 成功：dump outD
            const arr = [];
            for (let i = 0; i < this.count; i++) {
                arr.push(this.outD.add(i * 8).readDouble());
            }
            send({ name: 'chbi_p51_out', payload: { count: this.count, out: arr } });
        } else {
            console.log('[chbi:p51] failed, ret=' + retval.toInt32());
        }
    },
});

// 第二道 EA62 门：可选择性拦截
Interceptor.attach(iface_vtbl_query, {
    onEnter: function(args) {
        const code = args[1].toInt32();
        if (code === 0xEA62) {
            console.log('[chbi:p51] EA62 query: ' + code);
        }
    },
});
```

### §2.3 Python 端接收（`tools/wnmr_py/frida_runner.py`）

```python
import frida
import json

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        if payload.get('name') == 'chbi_p51_out':
            with open('chbi_p51_frida_600000.json', 'w') as f:
                json.dump(payload['payload'], f)
            print('dumped', len(payload['payload']['out']), 'doubles')

session = frida.attach('缠中说禅.exe')
script = session.create_script(open('frida_chbi_600000.js', encoding='utf-8').read())
script.on('message', on_message)
script.load()
# 用户在软件里: 600000 + 1 分钟 K 线 + 启用缠论笔 (P=51)
# 触发后输出 dumps/chbi_p51_frida_600000.json
session.detach()
```

---

## §3 对拍脚本（`tools/wnmr_py/dupai.py`）[B]

```python
import json
import struct

def compare(chbi_path, frida_path, tol=1e-6):
    """对拍 chbi.py 与 frida dump 的 outD 数组"""
    with open(chbi_path) as f: chbi = json.load(f)
    with open(frida_path) as f: frida = json.load(f)
    a = chbi['out']
    b = frida['out']
    assert len(a) == len(b), f'len mismatch: {len(a)} vs {len(b)}'
    diff = [(i, a[i], b[i]) for i in range(len(a)) if abs(a[i] - b[i]) > tol]
    n_diff = len(diff)
    n_nz_chbi = sum(1 for v in a if v != 0)
    n_nz_frida = sum(1 for v in b if v != 0)
    print(f'chbi 非零 {n_nz_chbi}, frida 非零 {n_nz_frida}, diff {n_diff}')
    if n_diff:
        print('前 10 个差异:')
        for i, va, vb in diff[:10]:
            print(f'  [{i}] chbi={va} frida={vb}')
    return n_diff == 0

if __name__ == '__main__':
    compare('chbi_p51_600000.json', 'chbi_p51_frida_600000.json')
```

**预期**：
- 早期 chbi.py 是简化骨架（不含完整的 a040 借用语义细节），可能与软件输出有 ±1-2 处差异。
- 通过差异定位 → 修正 chbi.py → 重跑对拍 → 直至 0 差异（n_diff=0）。
- 全文 58,560 长度对拍 = 完整 2017 年 1 分钟线。

---

## §4 实际执行步骤

1. **步骤 A** (本批已完成)：chbi.py 骨架 + duipai.md 方案文档 + 数据集字段定位。
2. **步骤 B** (用户配合)：启动缠中说禅软件 + 加载 600000 + 1 分钟 K 线 + 启用缠论笔。
3. **步骤 C** (用户配合)：运行 `python tools/wnmr_py/frida_runner.py` → 生成 `chbi_p51_frida_600000.json`。
4. **步骤 D** (用户配合)：运行 `python tools/wnmr_py/dupai.py` → 输出差异报告。
5. **步骤 E** (迭代)：根据差异迭代修正 chbi.py 的 a040/eba0/ef00 借用语义细节。

**环境依赖**：
- `frida` Python 包（pip install frida）——本机未装，需用户安装
- 通达信客户端在 D:/a_ronglide/缠中说禅/ 下
- 需 600000 的服务器索引已下发给软件（K 线能正常显示）

---

## §5 遗留

- **本批未执行实际对拍**（依赖 frida 安装 + 客户端启动）。
- chbi.py 当前是简化骨架，**预期与真实软件有差异**（特别是 a040 的"借用栈槽"语义与 eba0/ef00 的端点戳时序）。
- frida dump 数据集未生成。
- 对拍脚本与差异分析未跑。

环境就绪后即可执行步骤 B-E，无需修改 chbi.py 接口。
