# summary.md — CHBI 逆向工程：错误与经验教训日志

> 跨会话知识库。**任何新错误、新教训、新事实，立即追加到本文件**（见文末更新规约）。
> 任务前必读入口：AGENTS.md。

---

## 0. 目标

- CHBI 公式（P=51）的忠实实现：Python x86 模拟器逐条执行 TAFLib.dll 真实代码（已完成、自测通过）。
- 与真实 DLL 对拍：**已完成** —— frida 在进程内原生执行真实 TAFLib.dll 入口，全量 58560 根 c1d0/c4b0 双入口与模拟器**逐位全等**（2026-10-18，见 §2.7）。
- 实机侧路线：GUI 驱动（死路）→ frida 进程内原生执行真实 TAFLib.dll 入口（**已成功**）。

---

## 1. 环境与关键路径

| 项 | 值 |
|---|---|
| Python | `C:\Users\Administrator\Documents\a_conda\python.exe`（3.13.12，长跑必须加 `-u`） |
| frida | 17.23.3（32 位客户端，需 32 位 agent） |
| 客户端 | `D:\a_ronglide\缠中说禅`（32 位、GBK、**离线环境**） |
| 工具目录 | `D:\a_ronglide\clone-ronglide\tools\wnmr_py` |
| 证据反汇编 | `D:\a_ronglide\clone-ronglide\tools\re-inventory\chbi` |
| 数据集 | `D:\a_ronglide\缠中说禅\Dat\His\02\1\600000.1`（58560 根；同位 000001/600004/600006） |
| 临时产物 | `C:\Users\Administrator\AppData\Local\Temp\opencode\`（JSON、crash_report.txt、截图、spawn 脚本） |
| 原生宿主 | `C:\Windows\SysWOW64\notepad.exe`（spawn 时 cwd=客户端目录） |

**勿动进程**：1304/16724（mul-agent orchestrator，用户自用）、9112/11388/12408/16792（freellmapi 系统服务）。

---

## 2. 技术事实（已验证）

### 2.1 入口与数据

- 入口 `0x1002C4B0`（EAX=series；参数 W**, count, out, iface）；`0x1002C1D0`（W**, count, out, series, iface）。两者全量输出实测逐位全等。
- 运行时字节与证据完全一致：c1d0 = `83 EC 28 53 55 8B 6C 24 38 85 ED 56 8B 74 24 44 57 0F 8E BB 02 00 00 83`；c4b0 含 `8B F8`（mov edi,eax）。
- 参数（栈帧内已确认）：arg1=W**（CELL 存引擎指针）、arg2=count、arg3=out、arg4=series、arg5=iface。
- series = {pH(double*), pL(double*), pP(double 51.0)} —— **注意 [0]/[1] 的 H/L 顺序目前按 [0]=pH、[1]=pL 构建，需最终证据复核**。

### 2.2 c1d0 前段流程（0x1002C1F2–0x1002C269，最新梳理）

- 两次 `malloc(4*count)`（带 `seto/or` 溢出检查模式）→ buf1(ebx)、buf2([esp+0x14])。
- 转换循环（0x1002C238–0x1002C269）：buf1[k]=float(series[0][k])、buf2[k]=float(series[1][k])，另向 out 写一份 double；FP 栈有 `fldz`/`fst` 保留值花活。
- `call 0x1003DB40(W, count, buf1, buf2)` ← **核心算法**（用两个 float 缓冲）；随后 `call 0x1003E200`。
- series[2]（pP）double → `call 0x1006BC70`(ftol) → P 整数 → `cmp 0xB(11)/0xC(12)/0x15(21)/0x16(22)/...` 分支（P=51=0x33 在后续分支；c4b0 入口为 P=51 硬编码版）。

### 2.3 容器/内存布局

- W 容器：W+0x00 stride 0xA0 cap n+64；W+0x20/0x30/0x40/0x50 stride 0x28 cap 2n+64。
- 容器头：+0=0，+4=begin，+8=live-end，+0xC=alloc-end。
- auth 门：`mov ecx,[esp+0x4c]`(iface) → `call [vtbl+4]`，push 0xEA62、thiscall、callee `ret 4`、AL 返回。原生 stub = `B8 01 00 00 00 C2 04 00`。

### 2.4 模拟器钩子语义

- h_malloc = bump 分配器：单调、**零初始化、永不复用**；h_free = NOP。
- h_iter_begin（ecx=container，esi=slot，`ret 4`）；h_iter_at（ebx=container，esi=slot，[esp+4]=k；begin=[c+4]、end=[c+8]、cur=begin+k*0xA0 clamp）。
- h_copy_a0 / h_copy_28 = mem.copy 0xA0 / 0x28 字节；h_ftol；h_auth。
- ✅ 钩子与真实函数语义核对（disasm_func.py 新 dump，`f_1006a4e0/b1c0/b1f0/b34a/bc70.txt`）：iter_at ≡ 真实 0x1003F0D0；copy_a0/copy_28 真实体=按 edx 条数复制（快路径调用点恒 edx=1 → 等价；慢路径 grow 函数 0x1006A930/0x1006A9E0 不在证据集、从未命中）；iter_begin 真实=容器克隆构造（ecx=源、[esp+4]=目标、经 0x1003F150 在 se200 之后调用，内容等价）；ftol 真实另写 edx（调用方只读 eax，可接受）；malloc 目标=`jmp [0x1006F058]` 导入 thunk。
- 钩子常量：MALLOC=0x1006B34A、FREE=0x1006B344/0x1006B320、FTOL=0x1006BC70、ITER_BEGIN=0x1006A4E0、CPY_A0=0x1006B1C0、CPY_28=0x1006B1F0、ITER_AT=0x1003F0D0、ASSERT 桩=0x1006F194。

### 2.5 PE / 模块事实

- TAFLib.dll：PE32，ImageBase=0x10000000，无 dynamic_base，**有 .reloc**（rva=0x86000 size=15640）。
- 节表：.text va=0x1000 vsize=0x6D20B（RVA 0x60000 在 .text 内）、.rdata 0x6F000、.data 0x7C000、.rsrc 0x85000、.reloc 0x86000。
- 导入：rld_lib.dll、chlib.dll、RDM_C.dll、RCommon.dll、RData.dll、MFC80U.DLL、MSVCR80.dll、KERNEL32.dll、MSVCP80.dll（**非自包含**）。
- libcurl.dll 同样首选 0x10000000 → 在 app 内 TAFLib 被重定位（实例 11724 中 base=0x12F0000）。

### 2.6 模拟器结果基线

- 全量：14,406,536 步 / 44.34s / 8518 非零（14.5%），直方图 {+1×4259, −1×4258, −2×1}。
- c4b0 vs c1d0：差异 0/58560。
- JSON：`Temp\opencode\chbi51_600000.json`（c4b0）、`chbi51_600000_c1d0.json`、`chbi51_600000_10k.json`、`emu_200_c1d0.json`、`emu_2000_c1d0.json`。
- 200 根基准（dbg_em.py）：47588 步 / 24 非零；m0 推入 47、m5 推入 69、iter_at=142、iter_begin=1、malloc=2、free=3；容器 nrec：W+0x20=12、W+0x30=11、W+0x40=23、W+0x50=23。

### 2.7 原生执行验证（2026-10-18 全通）

- **全量 58560 根双入口与模拟器逐位全等**：`RESULT: ALL MATCH`；直方图 {(−2.0)×1, (−1.0)×4258, (+1.0)×4259}，非零 8518；引擎原生执行仅 3.0s（Python 模拟器 44s）。
- 规模抽查：200 / 2000 / 58560 三档全部 0 diff；原生 dump 在 `tools\wnmr_py\dumps\chbi_native_{c1d0,c4b0}_{200,2000,58560}.json`。
- **验证运行必须零插桩**：`frida_native_call.js` 顶部 `const QUIET = true`（跳过 installTrace/installProbes/installChecks）。任何 Interceptor.attach 的 JS 回调都会污染引擎线程栈（详见 §3.5）。
- trampoline 线程结尾改为 `push 0; call dword ptr [ExitThread]`（地址预写 stubMem+8）——不再出现退出时 eip=0 违规报告；引擎 rc 仍写 flag1/flag2。
- 原生侧关键中间量核对（与模拟器一致）：c1d0-in W 头 begin/end/allocEnd、sb40-in buf1/buf2 浮点逐位、push-m0#1 记录内容（f00=0x3、f0C=0x4181eb85）。
- sb40 推入容器来源已钉死：`0x1003DE4F mov esi,[esp+0x188]`（=arg1 W，实参槽）→ 之后 4 个 push 调用点（0x1003DFFA/0x1003E01F/0x1003E05C/0x1003E088）不再改 esi；esp 无漂移（0x1003D8A0 为普通 `ret`，调用方 `add esp,4` 平衡）；iter2a(0x1003D780)=返回 m0 记录数（只用 eax/ecx/edx），不碰 esi。

### 2.8 WNMR_线段 全链 e2e（2026-10-19）

- 新工具：`tools/wnmr_py/frida_wnmr_e2e.js` + `tools/wnmr_py/wnmr_e2e.py`。
  链路：`c1d0(CHBI)` → `0x1002c710(CHDUAN)` → `[快照 W->m[0]]` → `0x1003a7c0(WNMRNEW)` → `0x1003a960(WNMRPRINEW)`，全部在 notepad 宿主内原生执行；全量 58560 根 2.5s。
- 入口约定（反汇编复核）：
  - `CHDUAN 0x1002c710`：ecx=count，eax=cell，栈 `[out, ctx]`，`ret 8`。
  - `WNMRNEW 0x1003a7c0`：ecx=count，eax=cell，栈 `[out, double** inputHolder, ctx]`，`ret 0xC`；`out` 清零后从 `**[inputHolder]` 拷 float 到 temp。
  - `WNMRPRINEW 0x1003a960`：ecx=count，eax=cell，edx=ctx，栈 `[out]`，`ret 4`。
- W 容器实测（58560 根后）：m0(0xA0)=13110、m2=4259、m3=4258、m4(0x28)=829（WNMR 合并 bar）、m5=8517。CHBI 阶段与已验证基线 `dumps/chbi_native_c1d0_58560.json` **逐点 0 diff**。
- 真实结果：CHDUAN 非零 831；WNMR 状态 `1@index 35281 / 3@index 35401 / 2@index 35406`，价格 `12.72 / 12.70 / 12.72`；WNMRPRI 非零 3。
- `wnmr.py` 用同一 m0 快照 + CHDUAN 序列重放 → **全 0**，status/price 各 3 点 diff。结论：`merge_by_flag`/`main_engine` 未复刻真实窗口扫描，非符号/精度问题。
- 关键字段纠正：level object `+0x04`/`+0x08` 是 **float 价格**（与 `+0x0C`/`+0x10` 同值），不是索引；m4 bar(0x28) 才是 `+0x00 serial / +0x04 当前 m0 索引 / +0x08 前一 m0 索引 / +0x0C low / +0x10 high`。
- 实际买入触发在**实例②**（入口 `0x1005a7be`，写点 `0x1005a85c`），条件见 `0x1005a7d6`：`fld o2[+0x0C] / fld bar[+0x10] / fcompp / test ah,5 / jnp → 触发`，即 `bar.high != o2.low`。本次实测 `bar.pos=8297`（bar 517）、`nextbar.pos=8334`（bar 519）、`o2=8335=nextbar.pos+1`；写入 `o1=objs[bar.pos]=1`、`o2=2`、`o3=objs[nextbar.pos]=3`，价格分别 `bar.high / bar.high / nextbar.high`。实例①（0x1005a1b5）本次 0 命中。

### 2.9 买入块精确字段映射 + 剩余阻塞点（2026-10-19 续）

- **输出下标映射已确认**：`m0[k].index` 是 1 基 K 线序号，引擎写 `out[serial-1]=status`、`out[serial-1]=price`。实测目标：`k=8297→serial 35281→out 35280`、`k=8334→35401→35400`、`k=8335→35406→35405`，与真实引擎一致。
- **Bar28 字段纠正**：`+0x04 = 起始 m0 记录下标 k`（买入组查表基），`+0x08 = 结束 m0 记录下标 k`。买入三写目标（实例②）精确为：
  `o1 = objs[B.f04]`（B 起始记录）、`o3 = objs[N.f04]`（N 起始记录）、`o2 = objs[N.f04+1]`（N 起始记录+1）；价格 `o1=o2=B.high`、`o3=N.high`。
- **阻塞点（已升级认知）**：仅用 `B.high != o2.low` 朴素条件，全量合并 bar（829）产生 **820** 个命中；再加 `o2.direction==0` 仍 **513** 个。真实引擎只命中 **1** 个。
- **为什么必须整函数转录**：实例②的路由入口 `0x1005a697` 由外层多组比较决定（`0x1005a53c cmp ebx,1 / jne`、`0x1005a582`/`0x1005a5b6` high 比较、`0x1005a5ea` low 比较、`0x1005a710`/`0x1005a743` 入口处极值 gate）。而这些比较依赖的极值槽 `[esp+0x64]/[esp+0x80]/[esp+0x8c]/[esp+0x98]` 在 **整个 `sub_10056190`（~64KB）里约 15 处**被写入（含 4 个实例与共享前导 `0x1005a400+`、helper `0x1005a989`/`0x1005be05` 等），属于**全局 leg 跟踪状态**。即把 820→1 收窄的是整函数的 legs/极值决策树，不是实例②局部能复刻的。`wnmr.py` 要想 0 diff，需要**逐实例（① 0x5a1b5 / ② 0x5a697 / ③ 0x5bcd4 / ④ 0x5cae3）+ 共享前导**完整转录 + e2e 回归。这是多步、需动态验证的大 RE，单轮 session 内无法保证收敛，且半成品改动只会**增大** e2e diff，故未提交伪修复。
- **e2e 宿主现状**：`wnmr_e2e.py` 调 `wnmr.wnwr_new(objs, n, arr=chduan)`，内部 `merge_by_flag` 用 chduan 信号重新归并出 bar；当前 `main_engine` 用 `bar.pos=None` → 全 0 输出。字段映射修正见上，但 0 diff 仍卡在上面的过滤树。

### 2.10 x86emu 全链贯通：CHBI→CHDUAN→WNMRNEW→WNMRPRINEW（2026-10-24，✅ 逐位全等）

- **新工具** `tools/wnmr_py/wnmr_full.py`：在 x86emu 中**离线顺序执行全链四入口**（无 frida、无 DLL 注入）：
  - c1d0（cdecl: cell,count,out,series,iface）→ `0x1002C710`（eax=cell, ecx=count, 栈 [out,ctx], ret 8）→ `0x1003A7C0`（eax=cell, ecx=count, 栈 [out,holder,ctx], ret 0xC；holder=指向 outDuan 的 double**）→ `0x1003A960`（eax=cell, ecx=count, edx=ctx, 栈 [out], ret 4）。
  - 同一 emu 实例四阶段共用 W（0x40000000），每阶段前 `esp=STACK_TOP` 重置、SENTINEL 停机；auth vtbl+4 钩子对 0xEA62/0xEA63 通用。
- **全量对拍结果（vs 原生 e2e dumps/wnmr_e2e_full_N.json）**：
  - 2000 根：4 组输出 0 diff（该段无信号）。
  - 10000 根：4 组 0 diff（无信号；chduan 非零 138 与原生一致）。
  - **58560 全量：4 组 0 diff（ALL MATCH）**。chduan 非零 831；WNMR 状态直方图 {1×1, 2×1, 3×1}（index 35281/35401/35406 同 §2.8）；pri 非零 3。模拟器总耗时 ~5.5 min（CHBI 50s + CHDUAN 256s + WNMR 13s + PRI 2s）。
  - **检查点**：`--ckpt dumps/ckpt_pre_wnmr_58560.pkl` 在 CHDUAN 后保存模拟器内存页（6.3 MB），复用后从 WNMRNEW 起跑 15s 内复现 ALL MATCH。
- **新增反汇编证据** `tools/re-inventory/wnmr/`（disasm_func.py 生成）：f_1003a7c0（136）、f_1003a960（98）、f_10053540（3067，CHDUAN prepare）、f_10056010/100560d0（argmax/argmin）、受检迭代器/扩容族 f_1006a680/1006a6a0/1006a830/1006a860/1006a8e0/1006aa90/1006ad60/1006a930/1006a9e0、f_1003d720（迭代器后置自增）。
- **x86emu.py 新增指令**：`fucompp`（比较 ST0/ST1 双弹栈）、`fld1`（MarkSignalFlag 内）、`setne`（0x1006a8e0 内）。
- **工作流固化**：遇到 UnknownCall 先静态扫描全部 `call` 目标（脚本见对话/§3.8），批量补 dump；P=11/12/21/22/31/32 分支（0x1003f170/0x1004b1e0/0x1004f430）在 P=51 路径不执行，无需加载。

---

## 3. 错误与经验教训（持续追加）

### 3.1 数据链路

- ❌ 曾以为 GUI 操作可驱动真实数据 → 用 frida 文件钩子证实 **app 从不读任何 Dat\ 历史文件**。教训：GUI 自动化投入前先验证数据链路是否真实可达。
- ❌ 键盘精灵只认 HotKey 命令（0 项可用），键盘切股路线死。
- ✅ 服务器 47.94.134.160:11101 / 47.100.119.34:11101 TCP 拒连（ping 通但无外网），离线客户端永不产生实机数据。
- ❌ 入口点 0x1002C4B0/0x1002C1D0 **不是 stdcall 导出**（地址不在导出表），frida NativeFunction 导出查找失败 → 用 base.add(rva)。
- ⚠️ 需要为非启动进程注入：先用 frida 在一个启动的 notepad 里注入验证，再对真实进程操作。

### 3.2 GUI 自动化（备用知识）

- 菜单必须在**同一条命令内**完成"打开菜单 + 点击子项"（PowerShell 调用间菜单自动关闭）。
- DPI 200%：先 `SetProcessDPIAware()`；`keybd_event` 前需 `SetForegroundWindow`。
- 坐标（屏幕像素）：功能(777,302)、公式管理器(875,523)、用户tab(917,320)、TESTCHBI1(785,451)、预览(1410,583)；**避开 删除(1410,469)**。

### 3.3 frida

- frida 17：`Process.getModuleByName(x).getExportByName(y)` 用法；**不能定义全局名 `hexdump`**（与内置冲突，改名 hexStr）。
- ⚠️ **NativeFunction 会把目标代码的异常转成 JS 错误并抢走 `Process.setExceptionHandler`** → 改用 `CreateThread` + RWX trampoline 让异常落回处理器。
- ⚠️ 异常处理器里打印的 `address` 可能是**故障指令地址**，非法访问地址在 `details.memory`（此前未抓，教训：抓 memory 字段）。
- ❌ MainApp 单实例：已有实例运行时 `frida.spawn` 卡死（300s 无输出）→ spawn 前先确认无实例，或直接 attach。
- ⚠️ `frida_runner.py` 的 CANDIDATES 不含 MainApp.exe，需显式传名字。
- ⚠️ 进程存活查询偶发假阴性（"11724 gone" 误报过一次）。
- ⚠️ `recv` 过早 done 的竞态要处理；spawn_monitor.py 异常终止会留孤儿进程（记得清理）。

### 3.4 模拟器（x86emu / chbi51）

- ✅ **零全局假设已验证**：gdata_probe.py 用真实 .data/.rdata 覆盖后跑 200 根，输出逐位不变（0 diff）。引擎全程只读 3 个全局：0x1006F194（assert 指针，117 次）、0x1006FC50（-1.0，23 次）、0x1006FC28（0.001，1 次）。
- ⚠️ h_malloc（bump、零初始化、永不复用）vs 真实 malloc（可复用）语义不同——但 200 根下未暴露差异。
- ⚠️ 被钩掉的函数（malloc/free/iter/copy/ftol）**真实函数体从未执行** → 原生直跑时它们成为主要嫌疑。
- ⚠️ 模拟器只加载 .txt 反汇编（代码），.data/.rdata 全零 + 3 处常量覆写。
- ✅ GBK 文档先转 UTF-8 再读；证据 txt 用行号窗口分批读（40-50 行一批够用）。

### 3.5 原生执行

- ❌ **根因已定位（2026-10 修复）**：`frida_native_call.js` trampoline 给 c1d0 只推了 4 个参数（**漏传 series**；c1d0 实为 5 参数 W**,count,out,series,iface）。结果：arg4(series)=iface 指针、arg5(iface)=栈垃圾 → 转换循环从 iface 对象头开始按 stride8 读，落在 frida 内存池内无异常地跑了 28,355 次后走出映射区才崩（EIP=0x1002C24D `fld qword [edx+eax]`）。
- ✅ **寄存器取证技巧**（值得复用）：崩溃时 ebx=0x75FD/ecx=0x77FDC3C/esi=0xFFFC6CF8/ebp=0xE4C0 全部与干净模型吻合——esi=-(0x39308) 恰为两次 malloc 相邻堆块差（4*count+8 堆头）；buf2=0x077E2130 正好留在崩溃栈 `[esp+0x14]`（c1d0 的 buf2 局部）→ 反推 eax/edx 的函数关系得 series[0]=0xF169E8、series[1]=0xBD0040 = **iface 对象前 8 字节** → 帧错位（漏参数）实锤。教训：手写 cdecl trampoline 必须逐个入口核对参数个数（c1d0=5 栈参；c4b0=4 栈参+EAX=series）。
- ❌ 早期误判遗留：app attach 崩 0x10060000（=首选基址+0x60000，疑似 **同一漏参 bug 的后果**：垃圾指针进入引擎后被调用/使用）；notepad 直调全量崩 0x83B0000（直调路径参数正确，待修复 trampoline 后复核）。此前"寄存器全垃圾 → 上游已发散"结论**已被推翻**：那是漏参的直接后果。
- ✅ 重定位理论排除：notepad host 中 TAFLib 落 0x10000000，指针扫描仅 51 个巧合值（无未重定位残留）。
- ✅ notepad 宿主可达首选基址（app 内不行，libcurl 抢先）。
- ⚠️ 直调（NativeFunction）故障 = 进程直接死（frida 转 JS 错误但 32 位挂钩下仍死）；线程版能拿到 crash_report.txt。
- ❌ **Memory.alloc GC 根因（重大教训）**：`Memory.alloc` 返回的 JS 包装一旦被 GC，frida 就释放该内存；引擎线程仍在用时即被复用（W 头曾出现 console.log 字符串字节 "ead="）。症状：非确定性崩溃、容器"损坏"、nrec=22696 假象。修复：全局 `KEEPALIVE=[]`，zalloc/rwxAlloc 内 push 全部指针。
- ❌ **frida Interceptor.attach 回调污染引擎线程（重大教训）**：引擎线程上任何 JS 回调（trace/probe/check）都会破坏其栈槽——实测 push 时 esi 读到 0x4A9340F（应为 W），栈上出现 0x4A92xxx 家族（frida 内部地址残渣）→ 容器垃圾指针 → 崩 0x1006B1D3。**同一份代码在 QUIET（零 attach）下 100% 干净、逐位全等**。教训：逐位验证必须零插桩；出现"目标程序损坏"先去掉全部 attach 复测再下结论。
- ⚠️ 线程 trampoline 结尾不要用 `ret`（返回地址被扰动后可弹出 0 → eip=0 违规报告）；用 `push 0; call dword ptr [ExitThread]`。
- ⚠️ `frida_native_host.py` 全量跑偶发收尾挂起（一次被 420s 超时杀，dump 已落盘）；重跑正常（3.0s）。**dump 落盘即视为结果有效**。

### 3.6 工作流

- PowerShell：路径带空格用 `& "..."`；`&&` 不可用，用 `;` 或 `cmd1; if ($?) { cmd2 }`。
- 长输出/大命令易超时；python 长跑一律 `-u`；分批读大文件。
- 写汉字到 PowerShell 命令易乱码，改用文件写入工具。

### 3.7 WNMR e2e（2026-10-19）

- ❌ **反汇编文本的 `[reg + 0x90]` 不等于 7 字节指令**：真实编码 `C7 86 90 00 00 00 01 00 00 00`（disp32，10 字节），立即数在 `+6`。按 disp8 假设改 `+3` 会把 0x90 位移改成 0x11，状态直接不写。教训：改机器码前必须读原始字节确认 ModRM/长度。
- ❌ 用 `call`/`jmp` + 原生桩做探针时，若把 10 字节指令的前 5 字节覆盖、桩内只重放 7 字节，会跳进位移中间崩溃（本次 crash eip=0x86b0016）。优先用**纯数据标记**（只改 imm32 低字节为 0x11..0x14）做实例归因，零控制流风险。
- ✅ 实例归因结果：4 个买入写点 `0x5a1fa(①) / 0x5a85c(②) / 0x5bcd4(③) / 0x5cae3(④)`；本次 3 个信号来自**实例②**（把 ② 的立即数改成 0x12 → 输出 0x1201，因只改了低字节旁的 +7 位；正确立即数位是 +6）。
- ⚠️ `sub_10056190` 的 4 个实例是 4 套独立窗口扫描，不能把 ① 的伪码当成全部；Python 简化版一次性 `bar.high < o1.low` 假设会产生 787 个假触发（真实 1 个）。
- ✅ 快速判据：`grep -n "mov      dword ptr \[esi + 0x90\], 1"` 可列全 4 个写点；`f_10056190.txt` 中 `0x1005a7be` 是实例②的判定入口。

### 3.8 x86emu 全链扩展（2026-10-24）

- ❌ **capstone 线性扫描在「嵌入数据/非常规指令」处错位，错位解码会静默毒化模拟器执行**。本次共修正 5 处（均先用原始字节手工对齐核实再改 listing）：
  - `f_10053540.txt` 0x1005553f–0x1005554c：真实为 `lea esi,[esp+0x24]` + `call 0x1006a860` + `mov edi,[esp+0x1cc]`；listing 曾错解出 `je/and al,0xe8/sbb [ebx+1]`。
  - `f_10056190.txt` 0x1005b196：真实为 `mov [esp+0x14],edx`（89 54 24 14），listing 错解成 `push esp`+`and al,0x14`——**多压栈 4 字节使整个栈帧偏移**，后续读槽全错、在 0x10056638 误触发 assert。教训：模拟器报出的 assert/缺指令先怀疑 listing 错位，不要急着逆向"为什么断言失败"。
  - `f_10056190.txt` 0x1005718f–0x10057195：真实为 `jb +2`/`call ebp`/`mov edx,[esp+0x4c]`（listing 的 `aad 0x8b`）。
  - `f_10056190.txt` 0x1005918e–0x10059195：真实为 `call 0x100560d0`（argmin）+ `lea eax,[eax+eax-2]`（listing 的 `cmp eax,0x8dffffcf`/`inc esp`）。
  - `f_10056190.txt` 0x1005a18e–0x1005a197：真实为 `cmp dword ptr [esi+0x20],1` + `je 0x10056610`（direction==1 跳回循环头；listing 的 `jle/add/test` 全是错位）。
  - 高发模式：MSVC 受检块 `f3 a5 72 06 ff 15 94 f1 06 10`（rep movsd; jb+6; call [0x1006f194]）——`72 06` 极易被吞。修正方法：从 PE 原始字节以锚点指令（如 fnstsw/test/jne 序列）对齐后用 capstone 重解，再按"保持行序=fall-through 链"替换 listing 行。
- ✅ **UnknownCall 批量排查**：加载全部代码后静态扫 `call 0x...` 目标，缺失 9 个 → 补 6 个（0x1006a6a0/1006a860/1006a8e0/1006aa90/1006ad60/1003d720），CHBI P 分支 3 个（0x1003f170/0x1004b1e0/0x1004f430）确认不在 P=51 路径、跳过。
- ⚠️ `x86emu.py` 是已验证基础设施，本次仅做**增量指令支持**（fucompp/fld1/setne），未动既有语义；新代码文件一律经 `wnmr_full.py` 的 EXTRA_CODE 加载，不改 `make_emu` 的 CODE_FILES。

### 2.11 ChZhongShu 族核心 worker 第二批（2026-10-28）

- **G/D 双胞胎语义**：`0x1002cd00` / `0x1002cee0` 经归一化后控制流同构；唯一字段差异为 float 读取偏移 `+0x50` / `+0x54`。两者遍历 `W->m[0]` 的 `0xA0` 步长快照，序号 `record[+0] - 1` 定位输出；类别 `record[+0x28]` 在 1..4 且对应价格严格大于 0 时更新持有价，否则沿用旧值，空档按旧值延展，输出形成阶梯序列。
- x87 方向已按字节复核：`fldz; fld current; fcom st(1); fnstsw ax; fstp st(1); test ah,0x41; jne` 的跳转覆盖小于、相等与 unordered；只有 `current > 0` 执行更新。这更正了 `docs/37` 中“`jne` 表示大于”的旧表述。
- 主序列 `0x1002ca30` 清零 `count*8` 输出，读取输入首个 double 并 `_ftol` 后连同 `state[0]` 传入 `0x10061920`，之后快照遍历记录，将 `record[+0x28]` 写成 double；中间缺口保持 0。`0x10061920` 的内部副作用仍待拆解，以上均为静态反汇编结论，尚未原生对拍。
- REA `info` 复核目标仍为 x86 PE，SHA-256 `d277f1b647e4a5c1c570b0bd69eb0f3955737b65e35332a62d0da4f80ef9b588`；依既有勘误，不把 `rea xrefs/decompile` 当地址级证据。本批没有 `MainApp.exe` 在运行，因此 `inject_*_bypass` 尚无目标进程，未获得动态命中记录。

### 2.12 ChFxbi 族第一批（2026-10-28）
- **入口与鉴权**：导出 `ChFxbi @ 0x1000f740`（formula FXBI，分型笔，auth code `0xEA62`）。Dump：`tools/re-inventory/fxbi/wrapper_ChFxbi_1000f740.txt`；文档：`docs/40-ChFxbi-第一批-入口链与骨架.md` [A]。
- **包装链**：lazy-init `[edi+0xB0]==0`→`malloc(4)+call 0x1002c160`；`push 0xEA62; mov ecx,edi; call 0x10014e60`（包装层授权门，失败置零返回 0）。通过后构造轻量 iface 对象（`new(4)`, `[eax]=0x1006f708`）、`call dword ptr [0x1006f190]`、再以 `__usercall` 调用 `0x1002c4b0`（`push esi, [ebp+0xC], [ebp+8], [edi+0xB0]`；`ret 0x14`），收尾释放对象并返回 `al=1` [A]。
- **对比 ChBi**：`ChBi` 走 `shared_ptr(obj)+0x1001c110+0x1002c1d0` 且在 P==51 时双重 EA62 门并做 P 分派；`ChFxbi` **无 P 读取，直接走 P=51 硬编码函数 `sub_1002c4b0`**，仅包装层做 EA62 门（`0x1002c4b0` 内部亦有 EA62 门，共用同一 iface 对象）[A]。
- **复用**：主体链路与 CHBI 相同（`db40→e200→a040→eba0→ef00→EA62(iface)→输出环`），大量 worker 已在 `tools/re-inventory/chbi/` 复用。`0x1006f190` 暂判定为间接指针槽位（[B]）；双重授权门、参数语义及输出差异待小样本对拍验证（[C]）。
### 2.12 ZouShiBi 族 第一批（2026-10-28）

- **导出确认**：`TAFLib.dll` `?CalcProc_ZouShiBi@TAF_Calculator@@IAE_NIPANQAPAN@Z` @ `0x10010010`（auth `0xEA62`）、`?CalcProc_ZouShiZsAll@TAF_Calculator@@IAE_NIPANQAPAN@Z` @ `0x10010110`、`?CalcProc_ZouShimmd@TAF_Calculator@@IAE_NIPANQAPAN@Z` @ `0x10010210` [A]。
- **Wrapper 骨架（同构）**：序言/SEH、canary、容器懒初始化 `[edi+0xb0]==0` → `malloc(4)` + `call 0x1002c160` 初始化并写回、**授权门** `push 0xEA62` → `call 0x10014e60`（`thiscall ecx=edi`, `ret 4`）、授权失败清零输出并返回 `AL=0`、授权通过构造临时对象（vtable `0x1006f708`）并调用 worker、析构临时对象、返回 `AL=1`、`ret 0xc` [A]。
- **授权函数 `sub_10014e60`**：共享 `shared_ptr` 控制块模式（`0x1001d9f0/0x1001e780`、`lock xadd` 原子计数）、构造对象成员（vtable `0x1006f700`）、从 `this+0xc` 取字符串传入、写 `[this+0xb4]=0`，最终返回 `AL`。传入 code `0xEA62` 存储/校验路径待追踪 [A][C]。
- **首层 worker**：`ZouShiBi` → `sub_1002fbf0`（wrapper `0x100100e5`），`ZouShiZsAll` → `sub_10030b50`（`0x100101e5`），`ZouShimmd` → `sub_10033760`（`0x100102e5`）。`ZouShimmd` 的栈参数压入顺序与前两者略有差异 [A][C]。
- **产出**：`tools/re-inventory/zoushi/wrapper_ZouShiBi_10010010.txt`、`wrapper_ZouShiZsAll_10010110.txt`、`wrapper_ZouShimmd_10010210.txt`、`auth_10014e60.txt`；文档 `docs/39-ZouShiBi-第一批-入口链与骨架.md`。

---

## 4. 当前状态

| 项 | 状态 |
|---|---|
| 模拟器（x86emu + chbi51 + dupai） | ✅ 完成（全量跑通、自测 9/9、c4b0≡c1d0） |
| 零全局假设验证 | ✅ 完成（0 diff，只读 3 全局） |
| GUI 驱动实机数据 | ❌ 死路（app 不读 Dat、无网、键盘精灵无效） |
| 原生直跑 TAFLib（notepad 宿主 + 线程 trampoline） | ✅ **全量 58560 逐位全等（QUIET 模式，双入口 0 diff）** |
| WNMR_线段 全链原生 e2e（CHBI→CHDUAN→WNMRNEW→WNMRPRINEW） | ✅ 工具跑通；真实结果 3 个信号点（index 35281/35401/35406） |
| **x86emu 全链（wnmr_full.py，离线无注入）** | ✅ **58560 全量 4 组输出逐位 ALL MATCH**（2026-10-24，§2.10；2000/10000/58560 三档全过） |
| ChZhongShu 族（`0x1000f910/fb10/fc10`） | 🟡 第二批静态闭合 G/D 阶梯输出；`0x10061920` 与原生数组对拍待完成 |
| ChFxbi 族（`0x1000f740`） | 🟡 第一批静态：包装链+直调 `0x1002c4b0`，复用 CHBI 引擎；`0x1006f190` 等 [C] 待验证 |
| `wnmr.py` 对拍 | ❌ 3 status + 3 price diff（main_engine 窗口扫描未复刻；现已不阻塞——全链以 x86emu 为准） |
| 直调路径（NativeFunction 0x83B0000）/ app 内 attach | ⏸ 未复测（干扰源已知后可再验，低优先） |

---

## 5. 下一步计划

1. ~~重跑 host 确认 c1d0/c4b0 与模拟器对拍~~ → ✅ 已完成（全量 ALL MATCH，见 §2.7）。
2. 可选：把 `QUIET` 改为 host 命令行开关（当前硬编码在 JS 顶部）。
3. 可选：直调路径 0x83B0000 与 app 内 attach 复测（在已知"零插桩"前提下）。
4. 可选：`frida_native_host.py` 偶发收尾挂起的低优先排查（dump 落盘即有效，不影响结果）。
5. 交付封装：线程 trampoline（5 参 c1d0 / EAX=series 的 c4b0 + ExitThread 结尾）+ KEEPALIVE 方案已可作模板复用。
6. ~~WNMR 下一步：复刻实例②窗口扫描~~ → ✅ 已用更可靠路线完成：**x86emu 全链 wnmr_full.py 逐位 ALL MATCH**（§2.10）；`wnmr.py` 的纯 Python main_engine 转录降为可选优化（做完后可与 emu 输出对拍，仍以 emu/原生为基准）。
7. 交付封装候选：`wnmr_full.py` + `--ckpt` 检查点（CHDUAN 后 6.3 MB）即可作为「无脑买入线段」的离线计算引擎对外提供（15s/全量，无需 frida/DLL/客户端）。
8. 继续付费函数批次：ChZhongShu 族第二批见 `docs/38-ChZhongShu-第二批-核心算法与步进输出.md`；下一步展开 `0x10061920` 并对 G/D 小样本逐点原生对拍。REA 地址级解析有已知缺陷；动态观察需目标进程启动后再按需附加授权/权限 hook。

---

## 6. 关键文件

- 工具：`tools\wnmr_py\`（x86emu.py、chbi51.py、chbi.py、dupai.py、dbg_em.py、frida_native_call.js、frida_native_run.py、frida_native_host.py、frida_chbi_600000.js、frida_runner.py、probe_taflib.py、pe_info.py、gdata_probe.py）
- 反汇编工具：`tools\re-inventory\disasm_func.py`；函数 dump（chbi/）：core_1002c1d0.txt（443 行；崩溃循环在 35–55 行）、f_1003db40.txt（sb40）、f_1003d780/d8a0.txt（iter2a/iter2b）、f_1003e200.txt（se200）、f_1003f0d0.txt（iter_at）、f_1003f150.txt、f_1006a5e0/a720/b050.txt、f_1006a4e0/b1c0/b1f0/b34a/bc70.txt
- 原生对拍产物：`tools\wnmr_py\dumps\chbi_native_{c1d0,c4b0}_{200,2000,58560}.json`
- WNMR e2e：`tools\wnmr_py\frida_wnmr_e2e.js`、`wnmr_e2e.py`；产物 `dumps\wnmr_e2e_{raw,report,full}_58560.json`、`wnmr_e2e_w_58560.bin`、`wnmr_e2e_w_post_58560.bin`、`wnmr_e2e_c{20,30,40,50}_58560.bin`
- **x86emu 全链**：`tools\wnmr_py\wnmr_full.py`（+ `dbg_wnmr_full.py` 调试）；新证据 `tools\re-inventory\wnmr\`（f_1003a7c0/1003a960/10053540/10056010/100560d0/1006a830 等 11 个 dump）；检查点 `dumps\ckpt_pre_wnmr_58560.pkl`；模拟器输出 `dumps\wnmr_emu_full_58560.json`
- 产物：`Temp\opencode\chbi51_600000*.json`、`emu_200*_c1d0.json`、`emu_2000_c1d0.json`、`crash_report.txt`（无崩溃时应无此文件）
- 逆向文档：`D:\a_ronglide\缠中说禅\re-MainApp.md`（GBK、32745 行）、`re-TAFLib.md`
- ChZhongShu：`docs/37-ChZhongShu-第一批-入口链与三支骨架.md`、`docs/38-ChZhongShu-第二批-核心算法与步进输出.md`、`tools/re-inventory/chzhongshu/`

---

## 7. 更新规约

1. 任何新错误/教训 → 立即追加 §3（分类编号）。
2. 任何新验证事实 → 追加 §2。
3. 任务进展/状态变化 → 更新 §4、§5。
4. 保持条目具体：写清路径、地址、字节、命令。
