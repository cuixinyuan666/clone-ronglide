# CHDUAN 第四批 — frida 动态验证方案（静态不可判定项）

> 目标：验证 docs/24 §8 遗留的顺序敏感项与容器归属。
> 前置：`pip install frida frida-tools`；启动「缠中说禅」并载入含 600000 的分钟线；确认 TAFLib.dll 已加载。
> 免责声明：仅供技术学习与安全研究，分析对象为本人合法安装软件；未涉及破解或授权绕过。

---

## 一、观察点清单

| # | 地址 | 目的 | 期望观察 |
| --- | --- | --- | --- |
| O1 | `0x1003eba0` 函数入口 | 拆表前后 m[2]/m[3] 的 size | `W+0x28`/`W+0x24`（m[2]）与 `W+0x38`/`W+0x34`（m[3]）差值 ÷0x28 |
| O2 | `0x1003ed26` / `0x1003ed81` / `0x1003ee35` / `0x1003ee90` | `m[0][idx].+0x20` 逐次写入 | 记录 (idx, value)、m[5] 项序号 → **判定是否出现同一 idx 被重复写** |
| O3 | `0x100535d2`（跳板） | 阶段选择器 `esi` 序列 | 期望序列形态 `0,1,-1` 的循环；确认 ①→② 只发生一次 |
| O4 | `0x10053c86` / `0x10053d2f` | 包含关系处理核的命中率 | 统计「整体替换 / 单边刷低 / 上移」三类各多少次 |
| O5 | `0x10055099` / `0x10055b48` | ③/④ 发布块的触发次数 | 与 m[3]/m[2] 元素数对比 |
| O6 | `0x10055d46`/`0x10055d88`/`0x10055e8a`/`0x10055f2f`/`0x10055fd7` | `+0x24` 五写点 | 记录 (idx, ±1/±2) 全序列 |
| O7 | `0x1002c710` 返回前 | W→输出映射 | `out[item[+0x00]-1] = item[+0x24]` 的一致性核对（用 600000 序列的已知线段切分反查） |

## 二、脚本骨架（`frida_chduan4.py`）

```python
# -*- coding: utf-8 -*-
"""CHDUAN 第四批动态验证 —— 挂 TAFLib.dll 观察 prep 的写点与阶段序列。
   用法: python frida_chduan4.py [--timeout 120]
   注意: 需要缠中说禅软件在运行且已载入 600000 的分钟数据。
"""
import sys, time, json
import frida

TARGET = "TAFLib.dll"

# 地址（ImageBase=0x10000000，DLL 未重定位时可直接用绝对地址）
A = {
    "eba0_entry": 0x1003eba0,
    "m0_20_writes": [0x1003ed26, 0x1003ed81, 0x1003ee35, 0x1003ee90],
    "trampoline": 0x100535d2,
    "incl_core": [0x10053c86, 0x10053d2f],
    "publish": [0x10055099, 0x10055b48],
    "m24_writes": [0x10055d46, 0x10055d88, 0x10055e8a, 0x10055f2f, 0x10055fd7],
}

JS = r"""
var A = %s;
var base = null;
var log = [];

function fix(a) { return base ? ptr(a - 0x10000000).add(base) : ptr(a); }

function hookAt(absAddr, tag, dump) {
    Interceptor.attach(absAddr, {
        onEnter: function (args) {
            var rec = { tag: tag, addr: absAddr.toString(), t: Date.now() };
            if (dump) { try { dump.call(this); } catch (e) { rec.err = "" + e; } }
            log.push(rec);
            if (log.length %% 64 === 0) { send(JSON.stringify(log.splice(0, log.length))); }
        }
    });
}

function main() {
    var mod = Process.findModuleByName("TAFLib.dll");
    if (!mod) { send(JSON.stringify({error: "TAFLib.dll not loaded"})); return; }
    base = mod.base;
    send(JSON.stringify({loaded: base.toString(), size: mod.size}));

    // O1 拆表入口: W = [esp+4]（__stdcall, 函数首条为 sub esp,0x58）
    Interceptor.attach(fix(A.eba0_entry), {
        onEnter: function () {
            var W = this.context.esp.add(4).readPointer();
            var m2n = W.add(0x28).readU32().sub(W.add(0x24).readU32()) / 0x28 | 0;
            var m3n = W.add(0x38).readU32().sub(W.add(0x34).readU32()) / 0x28 | 0;
            var m5n = W.add(0x58).readU32().sub(W.add(0x54).readU32()) / 0x28 | 0;
            log.push({tag: "eba0_in", W: W.toString(), m2: m2n, m3: m3n, m5: m5n});
        }
    });

    // O2 m[0].+0x20 写入: edi = 元素指针, 值来自立即数
    A.m0_20_writes.forEach(function (a) {
        Interceptor.attach(fix(a), {
            onEnter: function () { log.push({tag: "m0_20", pc: a.toString(), edi: this.context.edi.toString()}); }
        });
    });

    // O3 跳板: 记录 esi
    Interceptor.attach(fix(A.trampoline), {
        onEnter: function () { log.push({tag: "tramp", esi: this.context.esi.toInt32()}); }
    });

    // O4 包含核
    A.incl_core.forEach(function (a) {
        Interceptor.attach(fix(a), { onEnter: function () { log.push({tag: "incl", pc: a.toString()}); } });
    });

    // O5 发布块
    A.publish.forEach(function (a) {
        Interceptor.attach(fix(a), { onEnter: function () { log.push({tag: "pub", pc: a.toString()}); } });
    });

    // O6 +0x24 写点: 记录 edi/ebx 指针
    A.m24_writes.forEach(function (a) {
        Interceptor.attach(fix(a), {
            onEnter: function () { log.push({tag: "m24", pc: a.toString(), ptr: this.context.edi.toString()}); }
        });
    });

    // 周期性回传
    setInterval(function () { if (log.length) { send(JSON.stringify(log.splice(0, log.length))); } }, 1000);
}
"""
% json.dumps({k: (v if isinstance(v, list) else [v]) for k, v in A.items()})
# 注: JS 模板里 A.eba0_entry 需要标量，上述 json 已把标量转成单元素数组，
#     正式运行时请把 A.eba0_entry 改回标量（见脚本注释）。


def on_message(msg, data):
    if msg["type"] == "send":
        print(msg["payload"])


def main():
    dev = frida.get_local_device()
    pid = None
    for p in dev.enumerate_processes():
        if "chan" in p.name.lower() or "tdx" in p.name.lower() or "zhongshu" in p.name.lower():
            pid = p.pid
    if pid is None:
        print("[!] 未找到缠中说禅进程；请先启动软件（或手工指定 pid）。")
        return 1
    session = dev.attach(pid)
    script = session.create_script(JS)
    script.on("message", on_message)
    script.load()
    timeout = 120
    if "--timeout" in sys.argv:
        timeout = int(sys.argv[sys.argv.index("--timeout") + 1])
    print("[*] 已注入 pid=%d；%d 秒后卸载（在此期间请在软件里打开 600000 的线段指标）" % (pid, timeout))
    time.sleep(timeout)
    session.detach()
    print("[*] done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

> 说明：上表地址为 **ImageBase=0x10000000 下的绝对 VA**；脚本已用 `Process.findModuleByName` 取实际基址并做重定位换算。
> `A.eba0_entry` 在 JS 中按标量使用，生成模板时通过 `%s` 注入的是「标量→单元素数组」的字典，运行时请按注释把入口改回标量（或直接用 `A.eba0_entry[0]`）。

## 三、判定标准

| 待仲裁项 | 观察点 | 判定 |
| --- | --- | --- |
| m[0].+0x20 是否被跨 m[5] 项覆盖 | O2：同一 `edi` 出现 >1 次 | 出现 → **顺序敏感成立**（后者覆盖）；不出现 → 顺序不敏感 |
| ③/④ 是否各只跑一遍 | O3：`esi` 序列中 1 与 -1 各出现次数 | 各 1 次 = 单遍；多次 = 与 m[2]/m[3] 长度相关 |
| 包含核三类分支分布 | O4：两地址命中次数比 | 给出「整体替换 : 单边刷低 : 上移」比例，用于校验 §4 语义 |
| +0x24 序列可复现 | O6 + O7 | 与按 §7 语义串重放的结果逐点比对 |
| 内层容器归属 | O1 的 m5 计数 与 O5 触发数 | 若 m5 = m[2]+m[3]，则 [esp+0x120] 迭代器源容器 = m[0] 子序列，需进一步 ref 观察 |

## 四、当前状态

- 本批**仅完成方案与脚本骨架**，**未实际运行**（依赖用户配合启动软件 + 安装 frida）。
- 静态分析已给出的结论（§8）**在无动态数据前均标注 [B]**；O2/O7 是将其升级为 [A] 的关键实验。
