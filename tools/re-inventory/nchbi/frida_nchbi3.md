# NChBi 第三批 T4 — frida 动态验证预备包（本轮**未运行**）

目的：等用户在场启动交易软件后，**一条命令**即可把 NChBi 族 out[] 判定表从静态 [A] 升到「运行时实证」，
并顺带 dump 出 Item21 / Rec20 容器快照与 ZjNum 的间隔计数，用于和静态结论逐条对拍。

- 本机 frida 版本：**17.23.3**（CLI 与 frida-python 均实测存在，2026-10-17）
- 前置：交易软件（缠中说禅 / MainApp.exe）**已启动**，且已打开/操作触发 NChBi 族计算的界面
- 脚本：`tools/re-inventory/nchbi/frida_dump_out.js`（可直接用）

---

## 1. 挂哪些点

| RVA | 符号 | 语义 | 关注 |
|---|---|---|---|
| `0x10002340` | NChBi | 主 out：bit0→`out[barIdx]=value`；bit3→×2；再 argmax/argmin | out[] 全量 |
| `0x10002770` | NChBiSta | ×10 段A / ×1,×2 段B / ×3 段C / 尾广播 | out[] 全量 |
| `0x10002ea0` | NChBiZj | bit2→`out[barIdx]=value` | out[] 全量 |
| `0x10003180` | NChBiZjOrder | 阈值过滤 + 按 Rec20[recIdx+1].startBar 重排 | out[] + Rec20 |
| `0x100038b0` | NChBiZjNum | bit0→`out[barIdx]=cnt`（间隔计数） | out[]（含 cnt） |

调用约定均为 `__thiscall` + `ret 0x10`：`this=ecx`，`arg1=[esp+4]=count`，`arg2=[esp+8]=out(double[count])`。
脚本在 `onEnter` 抓 count/out/this + 容器快照，在 `onLeave` dump 全量 out[]。

## 2. 一次性准备

```bash
# (a) 确认 chlib.dll 已在目标进程加载（可先跑一次）
frida-ps | findstr /i "MainApp"
# 若进程名不同（如 chan/MainApp64 等），frida-ps 里找那个加载 chlib 的进程
```

## 3. 运行（两种方式，任选）

**方式 A：attach 到已运行进程（推荐，不重启软件）**
```bash
# 1) 取 pid
tasklist | findstr /i "MainApp"      # 或 frida-ps | findstr /i "MainApp"
# 2) 挂
frida -p <PID> -l "D:/a_ronglide/clone-ronglide/tools/re-inventory/nchbi/frida_dump_out.js"
# 3) 在弹出的 frida REPL 里回到软件界面，触发一次该指标计算（如切周期/改参数/刷新）
#    控制台会打印 ===== ENTER/LEAVE ===== 与 out[] JSON
# 4) 复制控制台输出存盘，例如 > tools/re-inventory/nchbi/frida_run_YYYYMMDD.log
```

**方式 B：由 frida 启动软件（需软件支持从命令行起）**
```bash
frida -f "C:/path/to/MainApp.exe" -l "D:/a_ronglide/clone-ronglide/tools/re-inventory/nchbi/frida_dump_out.js" --no-pause
```

可选：把输出重定向到文件
```bash
frida -p <PID> -l ".../frida_dump_out.js" -q -o ".../frida_run_YYYYMMDD.log"
```

## 4. 判读与对拍清单（拿到日志后逐条核对）

1. **NChBi(0x10002340)**：`flags&1` 的项是否恰为 `out[barIdx]=value`；`flags&8` 的项是否 = 2×该项；末尾是否恰有
   一个位置 = `-2×firstValue`，且该位置 = out[] 的 argmax（firstValue≥0）或 argmin（firstValue<0）。
2. **NChBiSta(0x10002770)**：是否出现 `10×|value| / |value| / 2×|value| / 3×|value|` 四档，且位置符合 段A/段B/段C。
3. **NChBiZj(0x10002ea0)**：输出非零位置是否**恰等于** Item21 中 `flags&4` 的项的 barIdx；值是否 = 该项 value。
4. **NChBiZjNum(0x100038b0)**：输出值是否为**整数计数**（间隔数），且仅落在 `flags&1` 项的 barIdx 上。
5. **NChBiZjOrder(0x10003180)**：输出位置是否为 `Rec20[recIdx+1].startBar`；是否只保留 `|ZjNum[barIdx]| >= THR`。
6. **容器快照**：`obj10_typeCode ∈ {0..6}`；`item21.count` 与 `rec20.count`；`Item21.value ∈ {0,+1,-1}`（关键对拍点）。

## 5. 可能的坑

- **ASLR**：脚本用 `Process.findModuleByName('chlib.dll')` + RVA，自动适配基址；无需手改。
- **未收到 ENTER**：说明该指标尚未被计算 → 在软件里真正触发一次（或换周期让引擎重算）。也可先只挂
  `0x10002340`（最先跑的那个）确认链路。
- **`-f` 方式被反调试拦**：优先用 attach（方式 A）。
- **32 位进程**：frida 默认按目标位数选择；如提示架构不符，用对应位数的 frida（本机 17.23.3 已含 32/64）。
- 脚本已对每次 read 做 try/catch，遇到非法指针只会记 `err`，不会崩目标进程。

## 6. 运行后要补的记录

把控制台日志落到 `tools/re-inventory/nchbi/frida_run_YYYYMMDD.log`，并在下一批：
- 用日志逐条勾掉上面 §4 的 6 个对拍项；
- 把 docs/27 §判定表 中仍标 [B]/[C] 的行升为 [A]；
- 记录本次运行的软件版本、指标参数（周期/P 值）、样本日期，便于复现。
