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

### 3.9 反汇编 dump 校验（2026-10-28，docs/44 F4 批）

- ❌ **`push` 之后、`add esp,4` 之前的 `mov [esp+X],eax` 真实落点比字面小 4**（`push` 已让 esp 减 4）。本批 `ChBmmd` worker 有 5 处这样的写法，首轮按字面读槽位 → 误判「`0x1C`/`0x2C` 两个 `float[n]` 缓冲只读不写、`0x38` 一槽两用」，进而得出「只分配 5 个缓冲、7 次 free 不自洽」的假象。**规则：遇到 `push xxx; call yyy; mov [esp+N],reg` 序列，先数清这条指令之前、同一 `add esp,4` 之前的所有 `push`，把 N 逐个减 4。**
- ✅ **dump 完整性必须先核验再下结论**：把 `f_1002d0c0.txt`（1264 条）/ `f_1002e040.txt`（1269 条）与「按 DLL 原始字节线性反汇编」逐条比对，`first mismatch = None`（差异只在尾部 `int3` 截断）。**这一步花的时间远少于被错位/丢条的 dump 带偏后返工的时间**，应作为每个新批次的第一步。

> ### 🔴 §3.9 的 `esp` 槽位坑：已二次确认，升级为**硬性检查步骤**
>
> 2026-10-28 **F10 批次（docs/48，走势/递归族）由另一位分析者、在完全不同的函数上独立重踩了同一个坑**（详见 §2.17）：`0x10030b50` 的 12 条 float 缓冲与 `0x10033760` 的 8 条，若不减 4 会误判「缓冲互相别名」，进而**误读全部输出写点**。
>
> 两个不同批次、不同函数、不同分析者踩同一个坑 ⇒ 这不是偶发疏忽，是**该编译器代码模式的系统性陷阱**。
>
> **强制规则（每个新批次开工第一步，与 dump 完整性核验并列）**：
> 1. 搜索 dump 中所有 `push ...; call <malloc/new>; mov [esp+X], eax` 序列。
> 2. 对每条 `mov [esp+X], eax`，**数清它之前、且在配对的 `add esp,4` 之前有几条 `push`**，真实槽位 = `X − 4×(push 条数)`。
> 3. 把修正后的槽位表写进批次文档与伪码注释，**否则后来人必然重踩**。
>
> 判别口诀：**看 `add esp,4` 在哪 —— 它之前的 `[esp+X]` 要减 4，它之后的不用。**

> ### 🔴 第三次出现（2026-10-28，F5+F6 补写时发现）
>
> `pseudocode/chdzhongshu.c` 里 **`dnum` 的 5 个实参全部偏大 4**（真实 `sub esp,0x70`，伪码写成 `0x78`）；而**同一文件、同一批**的 `dmmd` 同一组字面值却恰好正确。
>
> 这说明该坑的触发条件不是"函数复杂"，而是**写伪码时有没有逐条数 `push`**。同一作者在同一文件里都会一个错一个对 ⇒ 必须靠**机械检查**而非经验。
>
> **累计三次（F4 ChBmmd / F10 ZouShiZsAll+ZouShimmd / F5+F6 dnum），跨三个批次、三个不同函数族。**
> 结论不变且更强：`disasm_func.py --fix-esp` 自动化（§5.14）应从"可选"提升为**下一批开工前必做**。

### 3.11 文档"已交付"必须验证落盘，看板必须覆盖全部批次（2026-10-28）

- ❌ **docs/45 从未存在，但主控连续记录了 4 次"已交付"**：`summary.md` §4、`orchestrator/workqueue.md` 第 2 波表、状态台账、以及看板口径，全都写着"F5+F6 docs/45 + pseudocode/chdzhongshu.c 已交付"。实际 `docs/` 目录编号从 44 直接跳到 46，`git log --all -- "docs/45*"` 也为空。
- ✅ **worker 其实交付了伪码与证据**（`pseudocode/chdzhongshu.c` 39 KB + 14 份 dump），只是 markdown 文档没落盘。所以 9 支函数的算法是逆向完成的，缺的是归档。
- ❌ **看板给出了"虚假完整"**：`verify_status.py` 生成的 `docs/19` 里**根本没有 F5+F6 这一批的任何条目**（grep `CHDZHONGSHU|docs/45|chdzhongshu` 零命中），于是它显示"21/21 全 ✅"——因为它连这一批都没登记，而不是因为它通过了检查。
- **规则**：
  1. 每批验收时，**必须实际 `Test-Path` 文档与伪码两个文件**，不能凭"worker 回报完成"记账。
  2. 看板生成脚本必须**先枚举作战清单里的全部批次**（workqueue 的 F1–F16），再逐批查产物；**缺产物应显示 ❌ 而非不显示**。"全部 ✅"必须伴随"登记批次数 == 作战清单批次数"的断言。
  3. `git log --all -- <path>` 是判断"文件是否曾经存在"的**唯一可靠手段**，怀疑漏落盘时先查它。

### 3.10 派工单转述常量会出错（2026-10-28，F10 批次）

- ❌ **主控写派工单时，凭旧笔记转述常量/参数，会把 A 函数的参数安到 B 函数头上**。本例：派工单把 `(20,84,20)/窗口0x10` 或 `(80,336,80)/窗口0x40` 写成 **ZouShimmd** 的参数，实际这组「三参数 + 窗口」是 **ZouShiZsAll** 的（`0x10030e51/0x10030e7b`）；ZouShimmd 实际是 mode1→`5.0/21.0`、mode2→`80.0/336.0`，且**没有窗口槽位**。两处的 `80.0/336.0` 是**巧合同名、不同常量地址、语义无关**。
- ✅ **worker 做对了**：发现派工单与 dump 证据冲突时，**以证据为准**，按真实值写进产物，同时在回报里单列出来提醒主控，并没擅自改派工口径。这个行为应固化为规则。
- **规则**：
  1. 主控派工单里凡是**具体常量、参数、窗口值**，必须注明「**以 dump 为准，与派工单冲突请回报**」。
  2. worker 回报中任何「派工单说 X，实际是 Y」的条目，主控必须**当批次修回 `summary.md`**，不能拖（本条已修，见 §2.17）。
  3. `summary.md` 里记的常量，**优先记常量地址而非只记值** —— 数值会同名巧合，地址不会。

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

### 2.13 Index/RLD 族 + NChBi 消费族 第一批（2026-10-28，F2/F3 补完）

- **F3（docs/43，7 支）**：`IndexDuo 0x10008580` / `IndexKong 0x10008870` / `HyDuo 0x10008b50` / `IndexMA 0x10008e10` / `IndexCount 0x100090f0` / `IndexCountInner 0x10009470` / `Macdnum 0x100105a0`。
  - **序列号→内部码表**（`0x10016350`，表在 `0x1001653c`，24 项 PE 直读）：1..10→`0x1b58..0x1b61`；11..14→`0x1b64..0x1b67`（跳过 `0x1b62/0x1b63`）；**15 非法**（跳 `0x100164a3` 失败块）；16..24→`0x1b68..0x1b70`。
  - **DUO** = `(s4+s5)*100/(s3+s4+s5+s6)`，分母≤0 置 0，随后 **零值前值延展**（`fucomp`+`test ah,0x44; jp`）；**KONG** = `(s3+s5)*100/T`，同延展；**HYDUO** 与 DUO 同式但负参数走行业句柄 `0x10029f90` 且**无延展**。
  - **INDEXMA(N)**，N∈{1..4}：`out[k]=series(20+N)[k]*100/series20[k]`（内部码分子 `0x1b6d..0x1b70`、分母 `0x1b6c`）；N 越界返 false 且**不清零**；除零只挡 unordered。
  - **INDEXCOUNT**：N∈{7,8,9,10} 直取序列 N；N=15 求 `s3+s4+s5+s6`（4 路展开 + 尾步）；N<7 或 ∉{7..10,15} 返 false（不清零）。
  - **INDEXCOUNTINNER**：N<1000 直取序列 N；N=1001 读 `%s\BiPlan.bin`（43 B 定长记录，`rec+0x0E`→`-1.0`、`rec+0x1A`→`(double)rec[0x22]`）。
  - **MACDNUM**：N=1→**10.0**、N=2→**22.0**、N=3→**7.5**（常量 `0x1006fba0/fb98/fb90`），其余 N 全 0；lazy-init `this[+0xB0]`。
  - 公式语料 `taf_formulas.json` 交叉印证：`RLD市场风向标` = `DF:=RLD_INDEXDUO; KF:=RLD_INDEXKONG; 分水线:50`；`均线多空` = `RLD_INDEXMA(1..4)`；`指标底部` = `INDEXCOUNT(15/8/10)`。
- **F2（docs/42，8 支）**：包装层 8/8 逐字节同构（44 条指令），槽位/授权码逐文件直证（Bhh `+0x18`、Bhl `+0x1c`、Sta `+0x38`、Zj `+0x44`、ZjOrder `+0x4c`（**唯一 EA62**）、FjZsNum `+0xa0`、MacdArea `+0xb8`、SecArea `+0xbc`）。
  - **Bhh/Bhl 双胞胎**：95 行仅 1 行差异（`fld [ecx+0x10]` ↔ `[ecx+0x18]`）；引擎记录 stride `0x20`：`+0x00` 起始 bar、`+0x04` 结束 bar、`+0x10` 高、`+0x18` 低。
  - **NChMacdArea** = 整段搬运（`0x10014952` 从 `engine[+0x30]` 拷出），非逐记录散射；**NChSecArea** = `0x10006240` 薄壳 → `0x10013e60`（逐 bar `p1+|p0|` + 按 `p1` 整数码切段）。
  - **NChFjZsNum** = 加权位掩码统计（外层 stride `0x1D`、掩码 `i+1`、内层 `0x5D` 元素位与+值相等，命中累加 `i+1`，散射到 `rec[+9]`）。
  - **NChSecArea 累加语义 [C]**：静态读法下每根只写增量，与「段面积=累计」命名不符，需动态对拍。



### 2.14 笔中枢买卖点族（F4，docs/44，4 支，2026-10-28 交付）

- **导出与授权**：`ChBmmd 0x1000FD10`（BIMMD）、`ChBmmd_t 0x1000FE10`（BIMMD_T）、`ChBsmmd 0x1000FF10`（BISMMD）、`ChLeimmd 0x1000FA10`（LEIMMD）。4 支授权码统一 `0xEA61`，与 CHBI/Fxbi 的 `0xEA62` 不同 [A]。
- **包装层同构**：`this[+0xB0]==0` → `operator new(4)` + `call 0x1002C160`（`malloc(0xC8)`+`0x1003D910` → cell 存 `W*`）→ `push 0xEA61; call 0x10014E60`（失败 `memset(out,0,count*8)` + `al=0`）→ 构造临时对象（vtable `0x1006F708`）→ 调 worker → `vt[0](1)` 析构 → `al=1`；`ret 0xC` [A]。
- **双道授权门**：临时对象 `vt[1] = 0x10001DB0` 是 thunk（`push code; call [0x1006F1F0]`），`0x1006F1F0` = `RDM_C.dll!?Authorize@AuthApi@@SA_NI@Z`，与包装层 `0x10014E60` 内部导入槽**是同一个** → worker 内第二道门与包装层第一道门最终同源 [A]。
- **worker 形状差异**：`ChBmmd`/`ChBmmd_t` = 5 栈参 `ret 0x14`（1264/1269 条）；`ChBsmmd` = `ecx=n` + 3 栈参 `ret 0xC`；`ChLeimmd` = `ecx=n`/`edx=iface` + 2 栈参 `ret 8`（无 SEH/无 GS cookie）。同类源码因签名不同被编译器选了不同调用形状 [A]。
- **算法**：`ChBmmd`/`_t` 先分配 7 个 `float[n]` 并做 **MACD(12,26,9)** 预处理（常数 `2.0/13.0/27.0/10.0` = `2/(N+1)`），再遍历 `W->m[0]`（stride `0xA0`）快照做区间/强弱比较，输出 `out[serial-1] ∈ {-2,-1,0,+1,+2}`，并有 `float E[]` 收集后整段覆盖回 `out` 的 ±2 标记通道。`-1`-支要求区间内 MACD 双负、`+1`-支要求双正 [A 机制 / B 归属]。
- **`ChBmmd` vs `ChBmmd_t` 只有 2 处差异**：①面积累加常数 `K = -1.0` vs `0.0`（`acc += (g>acc) ? g : g*K`）；②找 `end` 记录的扫描是否排除 `+0x98 == 1` [A]。
- **`ChBsmmd`** = `out[serial-1] = (rec[+0x98]==1) ? 0 : (double)_ftol(rec[+0x6C])`；**`ChLeimmd`** = `(rec[+0x9C]∈{5,6} && rec[+0x98]!=1) ? (double)rec[+0x9C] : 0`。两者无预处理、无面积比较 [A]。
- **4 支共同约定**：先把 `W->m[0]` 深拷贝成快照（`0x1003F150` 拷贝构造 + `0x1003D580` 拷贝赋值）再遍历；输出下标一律 `rec->+0x00 - 1`；空洞用「游标 + 前向 `memset`」补 0 [A]。
- **新增证据**：`tools/re-inventory/chbmmd/`（4 份包装层 + 4 份 worker + 新增 `f_10001d90.txt` 标量删除析构、`f_10001db0.txt` 授权 thunk）。
- **⚠️ 新教训（重要，见 §3.9）**：dump 完整性必须先与「按 DLL 字节线性反汇编」逐条比对再下结论；本批首轮因读错 5 处「`push` 之后、`add esp,4` 之前」的 `mov [esp+X],eax` 而误判两个缓冲只读不写。
- **剩余 [C]**：`+0x28`/`+0x30`/`+0x50..+0x5C`/`+0x6C`/`+0x9C` 的业务语义（写者不在现有 361 份 dump 里）；买卖方向归属；面积常数 `K` 的业务定名；快照副本的必要性。共 10 条遗留，见 `docs/44` §四。

### 2.15 MACD 面积族（F7，docs/46，4 支，2026-10-28 交付）

- **导出与授权**：`Chbimacds 0x10010b60` / `Chbimacds_t 0x10010c60` / `Chduanmacds 0x10010d60` / `Chduanmacds_t 0x10010e60`，授权码统一 `0xEA61`（与 F4 笔中枢族同码）[A]。
- **包装层 4/4 逐字节同构**（各 87 条指令），唯一差异 = worker 调用地址 [A]。
- **worker 签名**：`int __usercall worker(double **p /*ecx*/, void *cell, int count, double *out, void *tmp)`，`ret 0x10`；`cell = this[+0xB0]`，`*(void**)cell` = 引擎对象（**0xC8 字节**，由 `0x1003d910` 构造，含 8 个 0x10 B 容器槽）[A]。
- **第二道授权门**：worker 内部 `tmp->vt[1](0xEA61)`，与 F2 的 `this[+0x04]->vt[1](0xEA61)` 同源 [A]。
- **MACD 柱 = 教科书 MACD**：`ema1=ema2=x[0]`、`dea=0`；`ema1 += (x-ema1)*2/(N1+1)`、`ema2 += (x-ema2)*2/(N2+1)`；`dif=ema1-ema2`；`dea += (dif-dea)*2/(N3+1)`；`bufBAR[k] = 2*(dif-dea)`，`bufBAR[0]=0` [A]。
- **周期码三档**（`code = (int)(float)p[1][idx]`，常量 `.rdata` PE 直读）：1→(12,26,9)、2→(24,52,18)、3→(48,78,27)，其余走默认 (12,26,9) [A]。
- **输入只用 `p[0]`**（逐 bar 转 float）与 `p[1][idx]`（周期码）[A]。
- **笔/段双胞胎差异仅 2 处**：周期码索引 `p[1][1]`（笔）↔ `p[1][0]`（段）；端点戳字段 `elem+0x20`（笔）↔ `elem+0x24`（段）。指令数 506↔506 完全同构 [A]。
- **主变体 vs `_t` 变体 = 面积项口径**：主变体累加 `|柱|`（全柱绝对值），`_t` 变体只累加**与笔/段同向**的那一侧柱 [A 指令 / B 语义]。
- **输出是逐 bar 阶梯**：在每个笔/段区间 `[cur.bar, next.bar-1]` 内逐根写运行和 `out[bar-1] = acc`，区间起点 `acc` 从 0 重开；尾部再补一段「未闭合笔/段」到 `count-1`；未被覆盖的 bar 保持 0 [A]。
- 证据：`tools/re-inventory/macdarea/`（4 份包装层 + 4 份 worker + 新增 `f_1003d580.txt` 容器 assign、`f_1003d910.txt` 引擎构造、`f_10001db0.txt` 授权 thunk、`f_10001d90.txt` 临时对象析构）。
- **剩余 [C]**：`elem+0x24` 的段端点戳语义、尾部两处 `je 收尾`、未做原生对拍。共 7 条，见 `docs/46` §8。

### 2.16 NChFx 分型族（F9，docs/47，6 支，2026-10-28 交付）

- **包装层 6/6 逐指令同构**（各 44 条指令 / 1351 B），脚本归一化后差异 **0 条**；全族授权码一律 **`0xEA62`** [A]。
- **虚表直读闭环**（`chlib!0x10015214`，RVA `0x15214`，42 行）：`+0x24=0x10001a10`(Fx) / `+0x28=0x10001bd0`(FxSta) / `+0x2c=0x10001d90`(FxUpDn) / `+0x30=0x10002190`(FxOrder) / `+0x58=0x10003680`(FxNum) / `+0x60=0x10003a90`(Speed)，与包装层槽位逐条吻合 [A]。
- **共用容器准备器 `0x10006670(self, count)`**：构建 `obj8`（笔/段表）与 `obj_c`（分型表），并把 `obj8[+0x1c]/[+0x28]` 镜像进 `obj_c[+0x20]/[+0x24]`；失败返 -1 [A]。
- **行情输入只用 `ctx6[0]` 与 `ctx6[2]`**（经 setter `0x1000e0b0` 写入 `obj[+0x08]/[+0x0c]`，长度 `obj[+0x14] = count`）⇒ raw 分型记录 `+0x09` 是**下标域 = bar 序号**，其 `[0,count)` 上界检查即 bar 上界检查 [A]。
- **NCHFX** = 逐分型单点散射：`out[raw.bar(+0x09)] = value(±1)`，`flags bit1`（尾根合成分型）则 ×2 ⇒ ±2 [A]。
- **NCHFXSTA** = 与 `NChBiSta(0x10002770)` 完全同构的「四段阶梯」模板（段前 ±10 / 段内 ±1·(×2) / 段后 ±3 / 尾部 ±10），数据源换成 raw 分型记录（**stride 0x1D**）+ `Rec20[segIdx]` [A 结构 / B 业务命名]。
- **NCHFXUPDN** = x87 双槽轮转 + 双计数器：每个分型与「上一**反向**分型的极值」比较（顶：`上一底.low > 本顶.high`；底：`上一顶.high < 本底.low`），命中则 `out[bar] = ±k`（k 累加），否则 k 清零；`bit1` 记录整条跳过 [A 机制 / B 业务语义]。
- **NCHFXORDER** = 先内部调 `vt[+0x2c]`（= FxUpDn）把结果算进临时 `vector<double>(count)`，再按 `_ftol(fabs(tmp[raw.bar])) == P0` 过滤，把分型值写到**下一段的 `startBar`** [A]。
- **⚠️ 两套容器不可混用**：本批 4 支配 raw 分型记录（**stride 0x1D**，下标域 `+0x09`）；`NCHBIFXNUM`/`NCHBISPEED` 读 `obj10` 的 Item21（**stride 0x21**）。二者是不同容器 [A]。
- **只有 FxOrder 写 `out[]` 时未做上界检查**（`out[Rec20[bi+1].startBar]`，依赖 `startBar < count` 不变式）；其余 3 支均有 `0 <= idx < count` 检查 [A]。
- 证据：`tools/re-inventory/nchfx/`（6 份包装层 + 4 份 chlib 新解 + 新增 `chlib_10006670.txt`/`chlib_1000e0b0.txt`/`chlib_10011900.txt`/`ch_api_vtable_10015214.txt` + 生成脚本 `dump_vtable.py`）。
- **剩余 [C]**：7 条（均有静态可绕行说明），见 `docs/47`。

### 2.17 走势/递归族（F10，docs/48，5 支，2026-10-28 交付）

- **导出与授权**：`ZouShiZsAll 0x10010110` / `ZouShimmd 0x10010210` / `zsdg 0x10011a20` / `nzsqj 0x10011920` / `nzs 0x10011820`。包装层 5/5 逐指令同构 [A]。
- **授权码**：包装层 ZouShiZsAll/ZouShimmd/nzs/nzsqj = `0xEA62`，**`zsdg = 0xEA63`**（全批唯一，与 RLD 族同码）；worker 内部有二次校验（`0x10030b50@0x10030e24=EA62`、`0x10033760@0x10033959=EA62`、`0x10039990@0x100399ef=EA62`、`0x10039b10@0x10039b30=EA62`、**`0x10039c70@0x10039cdc=EA63`**）[A]。
- **参数读取**全部走 `in[0][1]` → `_ftol` 得模式号；**只有 ZouShimmd 例外**（`ecx=in`，直接 `fld qword [[in]+8]` + ftol）[A]。
- **三支小支同源**（`nzs`/`nzsqj`/`zsdg`）：前置分派 →（按模式调 `0x1003ef00`/`0x1003e6c0`/`0x1003e930` 或 `0x10060aa0`+`0x100616b0`）→ `call 0x10056190`（买卖点族）→ `call 0x1003f150`（迭代器构造）→ 遍历 **`W->m0`（0xA0 步长）快照**，把记录字段写成 double 到 `out`，**索引 = 记录 `[+0]-1`，中间缺口填 0** [A]。
- **三支小支唯一实质差异 = 取的字段与过滤**：`nzs` 取 `[+0x88]`（无过滤）；`nzsqj` 取 `[+0x28]` 且**仅当 ∈{1,2,3,4,5,6}** 才写，否则写 **0.0**（`0x10039c14` `fldz`）；`zsdg` 取 `[+0x88]`（无过滤）[A]。
- **ZouShiZsAll `0x10030b50`**：**代码体积 0x2C01 = 11265 字节 / 3617 条指令**（126 KB 是 dump **文本**体积，不是代码体积 —— 别被文件名骗了）。4 输入序列 → **12 条 `count` 长 float 缓冲**（4 装序列、8 零初始化）→ 参数分派 → **4 组嵌套扫描**产出索引/方向数组 → `call 0x1003e0c0`（清空 `W->m0` 并 push_back 重建）→ **输出段 12 对写点**写 `out[]` 并**回写记录字段 `[+0x50]/[+0x54]/[+0x28]=3/4`** → 释放 12 条缓冲 [A 骨架/写点；B 每段扫描的业务命名]。
- **ZouShiZsAll `0x10030b50` 的参数分派**：`0x10030e51`/`0x10030e7b` 直读，参数 1/2 选 `(20.0, 84.0, 20.0)` **/ 窗口 `0x10`** 或 `(80.0, 336.0, 80.0)` **/ 窗口 `0x40`**，窗口槽 `[esp+0x20]` [A]。
- **ZouShimmd `0x10033760`**：两个输入序列 → 3 条 float 缓冲（含 1 条全零）→ 参数分派：
  - **mode1 → `5.0` / `21.0`**（常量 `0x1006fcc0` / `0x1006fcb8`）
  - **mode2 → `80.0` / `336.0`**（常量 `0x1006fce8` / `0x1006fce0`）
  - ⚠️ **ZouShimmd 没有窗口槽位**（与 ZouShiZsAll 不同）。
- **⚠️ 更正（2026-10-28，由 `pseudocode/zoushi_rec.c` 编写者发现并回报）**：我早先在派工单与本文件里把 `(20,84,20)/窗口0x10` 或 `(80,336,80)/窗口0x40` **错记到 ZouShimmd 名下**。实际这组「三参数 + 窗口」是 **ZouShiZsAll** 的。**两处的 `80.0/336.0` 是巧合同名、分别来自不同常量地址、且 ZouShimmd 无窗口槽** —— 极易混淆。以本节上两条为准。
- **ZouShimmd 后续链路**：线性插值 → 遍历 m0 记录，按 `status==1`/`status==3` 分两个实例，各自再找 `direction==±1`、找 `status==2`/`status==4` 的邻接记录 → 算两段「面积」积分（`[esp+0x9c]`/`[esp+0xac]`）比较 → **实例①写 `out = -3.0/-1.0/-2.0`，实例②写 `out = +3.0/+1.0/+2.0`** [A 骨架/写点；B 面积积分的业务含义]。
- **伪码 `pseudocode/zoushi_rec.c`**（43045 B / 660 行）：8 节 —— 数据结构（`cont`/`engine` 0xC8 B / m0 字段宏 / 14 个 PE 直读常量）、`CALCPROC_SKELETON` 宏、5 支逐支伪码、复用表、遗留 L1–L8。ZouShiZsAll 的 12 条缓冲**带 −4 槽位修正注释**、24 个 `out` 写点表 + 19 条记录回写表。
- **本批新钉死的容器事实**：`0x1003d910` 是 **W 构造函数**，把 `W+0x04/0x14/0x24/0x34/0x44/0x54/0x64/0x74/0x94` 共 **9 组** `{0,begin,end,allocEnd}` 全部清零（W 由 `0x1002c160` 用 `operator new(0xC8)` 分配 ⇒ **W 对象 = 0xC8 字节**）；`0x1006a5e0` = 0xA0 记录 `push_back`（快路径 `0x1006b1c0` copy、慢路径 `0x1006a930` grow）[A]。
- **✅ §3.9 教训二次验证**：本批**独立重踩**了 §3.9 记的解码坑 —— `malloc` 调用序列 `push ecx; call 0x1006b34a; mov [esp+X],eax; add esp,4` 中，位于 `add esp,4` **之前**的 `[esp+X]` 实际落在「平衡帧 X−4」槽位。据此 `0x10030b50` 的 12 条缓冲真实槽位是 `0x44/0x5c/0x48/0x4c/0x60/0x64/0x94/0x78/0x74/0x28/0x24/0x9c`；`0x10033760` 的 8 条是 `0x88/0x74/0x58/0x40/0xb4/0x64/0x20/0x78`。**不减去 4 会误判缓冲互相别名，进而误读全部写点**。两个不同批次、不同函数、不同分析者踩同一个坑 ⇒ §3.9 应作为**硬性检查步骤**固化。
- **复用已闭合链路**：`0x1003f150`（迭代器构造）、`0x1003f0d0`（迭代器定位，0xA0 步长）、`0x10056190`（WNMR 买卖点 64 KB 族）、`0x10060aa0`/`0x100616b0`（CHDUAN 前置）、`0x1006a830`（受检 `operator->`）、`0x1006f194`（assert）。记录布局与 §2.8/§2.9 完全一致：`[+0]` 1 基序号、`[+0x20]` 方向、`[+0x28]` 状态(1..4)、`[+0x0C]/[+0x50]/[+0x54]` 价格 [A]。
- 证据：`tools/re-inventory/zoushi2/`（5 份包装层 + 5 份 worker + 新增 `f_1003e0c0.txt` 核心 push_back 派发器、`f_1005cc00.txt` nzsqj 前置 4460 行、`f_1003e6c0.txt`/`f_1003e930.txt`、`f_1006a5e0.txt`）。

### 2.18 NChBi 杂项 + wnmr 旧版 + Kzq（F13+F15+F16，docs/52，7 支，2026-10-28 交付）

- **授权码**：Ref/Sta2 = **0xEA61**，Zj3/ZjNum = **0xEA62**，wnmr/wnmrpri = **0xEA63**（**包装层首见 EA63，此前仅 zsdg 用过**），Kzq = **0xEA6B**（第 11 号付费功能）。`0x10014e60` 内无按 code 分支，统一转发 `RDM_C!AuthApi::Authorize`；失败时把 `code − 0xEA60` 写进事件对象 [A]。
- **NChRef** = 笔引用：第 i 笔 bar 区间内输出「前 M 笔」的高/低/成交量/成交额/相对位置（N=1..6 六选一，跳表 `0x100019ec`）[A 结构 / B 命名]。
- **NChBiSta2** = 笔状态阶梯码：笔内写 `value` 或 `2*value`，延伸到下一笔末写 `3*value`，笔前空档写 `(cond?10:4)*dir`（门 = Item21.bit0）[A 结构 / C 编码语义]。
- **NChBiZj3 vs NChBiZj**：两者门（bit2）、值（`value`）、展开（4 路 0x84 + 尾 0x21）全同，**唯一实质差异 = 写点下标** —— Zj 用 `barIdx(+0x1d)`，Zj3 经 `Rec20[recIdx(+0x09)].endBar + 1` [A]。
- **NChBiZjNum**：`out[barIdx] = 运行计数`（语义引用 docs/30，本批只复核包装层 EA62 / 槽 +0x5c）[A]。
- **ctx6 语义升级为 IAT 直证**：`[0]=High [1]=Open [2]=Low [3]=Close [4]=Volume [5]=Amount`（RData.dll 六个 GetXxxBuffer）[A]。
- **wnmr 旧版（0x10039e10）vs WNMRNEW（0x1003a7c0）**：**框架逐行同构**（帧、malloc 溢出检查、float 转换、EA63 第二道门、`0x10060aa0/0x100616b0/0x10056190`、迭代器、stride 0xA0、`index-1` 写点、空档 `rep stosd`），**仅 2 处实质差异**：
  1. 旧版在 `0x10056190` 之后**多一次 `call 0x10060c00`**（全 .text 唯一调用点 `0x10039ea7`）—— 额外写 `status=3/4` 并回填 `price(+0x94)`；
  2. 旧版输出循环**缺少 `xor ebx,ebx`（游标归零）**（新版在 `0x1003a865` 有 `33 db`；旧版唯一一次归零在 `0x10039e4b`，之后 ebx 被转 float 循环用到 count）⇒ 静态读法下空档清零被跳过、写点可能落到 `out[count]` 之后。
- **wnmrpri 旧版（0x10039fb0）vs WNMRPRINEW（0x1003a960）**：**算法逐行同构**，差异纯在协议层 —— 旧 `ecx=ctx` + 3 栈参 `ret 0xc` + /GS&SEH 帧 + 迭代器在授权**前**取；新 `edx=ctx/ecx=count/eax=cell` + 1 栈参 `ret 4` + 裸帧 + 迭代器在授权**后**取。
- **旧版是废弃入口**：274 条内置公式中 `WNMR(` / `WNMRPRI(` 命中 **0** 条，3 个 WNMR 公式全部用 `WNMRNEW/WNMRPRINEW`；与上述 ② 的静态缺陷互相印证 [A]。
- **Kzq** = 跨周期引用上一周期数据：`昨收/昨高/昨低`（N=1/2/3 → Close/High/Low），命中条件 `dataDate < barDate ∧ ¬IsSameDateGroup(...)` [A+B]。
- **⚠️ 两处任务书归属勘误（由 worker 发现）**：
  1. `0x1003a130` 唯一调用方是 `CalcProc_chbis@0x10011d20`（CHBI 引擎封装，**不属于 wnmrpri**）；
  2. `0x1002a070` 是共享导出 `TAF_Context::GetOtherSymbolData`（4 个调用方），**不是 Kzq 的实现**。
- 证据：`tools/re-inventory/wnmr/`（新增 `f_10060c00.txt` 36KB、`auth_10014e60.txt`）。
- **遗留 [C]**：10 条（NChRef 越界风险、Sta2 编码语义、wnmr 旧版游标缺陷的运行时后果、`0x10060c00` 完整判据 793 条仅结构化摘要等），见 docs/52。

### 2.19 一根筋与 kxqj 族（F12+F14，docs/51，7 支，2026-10-28 交付）

- **7 支 `CalcProc_*`（`__thiscall`，`ret 0xc`，签名 `(this, int count, double* out, double** p)`）** [A]。
- **两种包装形态**：
  - **A 型（6 支：bdtd/ygjmm/scqd/kxqj/kxqjg/kxqjd）**：骨架**逐条一致**（懒初始化 → 授权 → 临时对象 vtable `0x1006f708` → worker → 析构 → `al=1`），差异只在授权码/worker 地址/是否 ebp 帧/worker 传参。
  - **B 型（ygj）**：纯 **chlib 薄包装**（44 条指令 / 1351 B），TAFLib 侧**零算法**：`if(!Auth(this,EA62)) memset(out,0)` → `Fetch6Buffers` → `api->vt[+0xC0](count,out,ctx,p)` → 恒返 1 [A 结构 / C 语义]。
- **授权码**：ygj/bdtd/ygjmm/scqd = `0xEA62`；**kxqj/kxqjg/kxqjd = `0xEA61`** [A]。
- **kxqj 三兄弟不是串行依赖，是「同脚手架 + 不同记录字段投影」**（**更正任务书里的「kxqj 串联依赖链」说法**）：三支 worker 互不调用，唯一共享骨架（克隆 `*(this[+0xB0])` → `0x1003f150` → 0xA0 stride 遍历），差别只在投影字段 `+0x7C` / `+0x80` / `+0x70`+`+0x74`+`+0x78` [A]。
  - **kxqjd `0x10039530`**：值 C（`+0x80` float）铺阶梯（`[上一尾, rec[+0x78])`）[A]。
  - **kxqjg `0x100393b0`**：与 kxqjd **逐行同构（119 条）**，唯一差异取 `+0x7C` [A]。
  - **kxqj `0x100391a0`**：区间标记序列 —— `+0x70==1` 的记录，起点 bar（`+0x74`）写 1.0、终点 bar（`+0x78`）写 2.0，其余清零 [A]。
  - 容器来源交叉到 chbi：`this[+0xB0]` 由 `chbi` 包装层 `0x1000f580 → 0x1002c1d0` 填充；若公式链未先跑 chbi 系，kxqj 输出全 0 [B]。
- **bdtd `0x1003b050`（77 KB / 2210 指令，三模式大引擎）**：`P=(int)p[2][0]`；P=1/2/3 各 = 7 次滚动极值（周期 2/4/6/12/24/48/96）+ 数组复制 → 均值（÷14 或 ÷28）→ **`SMA(X,6,2)`** 写 out；P 越界输出全 0 [A 结构 / B 业务]。唯一直接写 out = `out[k]=0.0`（`0x1003b115`）+ 三条 `SMA` 调用（`0x1003b9cd`/`0x1003c26b`/`0x1003cc55`）[A]。
- **scqd `0x100365f0`（MACD 二值判定）**：`DIF=EMA(X,Na)−EMA(X,Nb)`、`DEA=EMA(DIF,Nc)`，`out=((DIF−DEA)*0.5>0)?1.0:0.0`；默认参数 **(12,26,9)**（MACD 经典），另有 3 张缩放参数表（N1→(160,352,120)、N2→(40,88,30)、N3→(10,22,7.5)，PE `.rdata` 直读）[A 结构 / B 命名]。
- **ygjmm `0x1003abc0`（滑窗最小二乘斜率）**：`N=(int)p[1][0]`（≥2），逐 bar 求 `slope=Sxy/Sxx`（`Sxx=0/NaN` 退化 1.0），再扫描相邻斜率写 **±1.0**；定标常数 `0x1006fb78=43.0` [A 结构 / B 命名]。
- **新钉死 4 个通用 callee**：`0x1003cd50`/`0x1003d110` = 滚动极大值 `HHV(X,n)`（两种比较写法：`test ah,0x41; je` vs `test ah,5; jnp`）；`0x1003d090` = float 数组复制；`0x1003d460` = `SMA(X,6,2)`（常数 `2.0 @0x1006fb48`）[A]。
- 证据：`tools/re-inventory/wave4/`（7 份包装层 + 7 份 worker + 新增 `f_1003cd50.txt`/`f_1003d110.txt`/`f_1003d090.txt`/`f_1003d460.txt`）。
- **遗留 [C] 9 条**（摘要）：全部业务命名（已关闭 ygj chlib 实现项）、bdtd 模式 2 第二组极值归属、bdtd 模式 1 缓冲别名（HHV24 覆盖 HHV4，需动态复核）、scqd 参数表上游、ygjmm 定标常数 43.0 语义、ygjmm 第二趟三路分支真值表、kxqj 缺 idx 边界检查、三支 worker 返回值都走 `or eax,-1`（包装层丢弃无影响）、容器填充者 chbi（[B]）。

### 2.20 ygj chlib 侧实现闭环（2026-10-28 追加）

- **定位路径**：`f_100121a0`（ygj 包装层）→ `mov ecx,[esi+0xBC]`（chlib handle）→ `mov edx,[edx+0xC0]`（虚表 slot 48）→ `call edx`。`TAF_Calculator` 构造函数 `0x1df0` 通过 `CreateLib(auth)` 初始化 `this[+0xBC]`（chlib 句柄）；析构函数 `0x1fa0` 调用 `FreeLib`。
- **chlib 虚表 `0x10015214`**：slot 48（`+0xC0`）=`0x10006260`（383 条指令，SEH 帧，`ret 0x10`）[A]。
- **`chlib!0x10006260` = EMA(30, scale=0.01)**：
  - 签名：`__cdecl ema30(ctx, out, count, p)`，4 栈参 + ecx=thiscall
  - 输入缩放：`val = ftol((float)p[0][k])` × `0.01`（`0x100154f0=42.0` / `0x100154f8=13.0` 参与系数计算，`42-13=29=30-1`，系数 = `1/30`）
  - 前 30 条 bar：线性初始化 EMA（逐 bar 迭代 `out[k] = out[k-1]*(29/30) + val*(1/30)`）
  - 主循环（count-30 条）：同 EMA 递推
  - 第二道算法：`ctx->vt[0x10](out, count, p, ctx)` 回调（可能是平滑或归一化）[B]
  - 返回：`-1`（count=0/out=null）、`0`（第二道失败）、`1`（成功）
- **关键 callee**：`0x100148a0` = ftol 桩（double→int→double）；`0x10006c00` = 对齐 malloc（size×8）；`0x10011900` = ctx 析构（free + 清零前 3 槽）
- **证据**：`tools/re-inventory/wave4/ygj_chlib_10006260.txt`、`chlib_100148a0.txt`、`chlib_10006c00.txt`、`chlib_10011900.txt`
- **ygj 业务语义 [B]**：静态反汇编判定为「EMA(30) 一根筋」——对输入价格序列做 30 条 EMA 平滑后，再经 vt[0x10] 二次变换输出单值序列。需 GUI 触发公式 + frida 打点验证输出值是否为 EMA(30)。

### 2.21 段中枢与中枢统计族（F5+F6，docs/45，9 支，2026-10-28 补写闭环）

> ⚠️ **重要过程记录**：docs/45 原本**从未落盘**（编号 44→46 直接跳过，git 历史也无此文件），但 `pseudocode/chdzhongshu.c`（39 KB）与 `tools/re-inventory/chdzhongshu/`（14 份 dump）+ `macdarea/`（4 份）是完整交付的。2026-10-28 由 subagent 依据伪码+证据补写 docs/45（911 行 / S1–S14 / 遗留 10 条），并在核对时**纠正伪码 10 处实质错误**。

- **9 支函数**（全部 `bool __thiscall(this, int count, double* out, double** p)`，包装层 `ret 0xC`，授权码**统一 `0xEA61`**）：
  - `Chdzhongshu` `0x10010760` → worker `0x10035260`（87/139 指令）
  - `Chdzhongshug` `0x10010960` → `0x10035740`（ZG 投影，115 指令）
  - `Chdzhongshud` `0x10010a60` → `0x100358b0`（ZD 投影，115 指令）
  - `Zstj` `0x10010860` → `0x10035410`（`+0x28` 字段）
  - `dzstj` `0x10011de0` → `0x1003a490`（`+0x2c` 字段）
  - `dmmd` `0x10011060` → `0x10036820`（42 KB，1231 行）
  - `dmmd_t` `0x10011160` → `0x100376f0`（42 KB，1241 行）
  - `dnum` `0x10011260` → `0x100385d0`（33 KB，959 行）
  - `dsmmd` `0x10011720` → `0x100397f0`（4.4 KB，127 行）
- **只有 `Chdzhongshu` 一支做「现场计算」**：worker 先 `0x1003E410(W)` 重建容器，再 `0x10065790(W, ftol(p[0][0]))` 跑中枢计算，其余 8 支只读 W 做散射 [A]。
- **中枢计算引擎 `0x10065790`（4292 行 / 163 KB）**：写入 `+0x2C`=3/4、`+0x34`=2/4、`+0x64`=ZG、`+0x68`=ZD、`+0x5C`=aux、`+0x9C`=5/6、`+0x6C`=±1.0f；`+0x98` 是控制标志、**不在该引擎写** [A]。
- **`ZG = min(+0x0C)`、`ZD = max(+0x10)`**、`aux = 较高那一侧的 +0x0C`；「一支包含另一支」时**取包含方**（伪码 `.c` 写成被包含方，已勘误）[A]。
- **`Zstj`/`dzstj` 双胞胎**：265 指令仅 5 处 `cmp` 字段偏移不同（`+0x28` ↔ `+0x2C`）；`kind∈{1,3}` 才写符号位（>0 → 1，负向翻转），`=0` 时保持前值延展到 `count` [A]。
- **`Chdzhongshug/(d)`**：`out[serial-1] = (double)rec[+0x64]`（G）/ `rec[+0x68]`（D），无额外过滤，有 `index < count` 检查 [A]。
- **`dmmd` = 三段面积**：起点（`+0x24==-1`）→ 中枢（`+0x34==2`）→ 终点（`+0x24==+1`），面积 = `Σ|E[i]|`（`E[i] ≤ 0` 时乘 `-1.0` 再累加），终点价格按全段写 ±1，另一路写 ±2.0 标记通道 [A 机制 / B 业务]。
- **`dmmd_t` 与 `dmmd` 的差异不止一处**：下分支改为「`≤0` 取绝对值、`>0` 完全跳过」，上分支乘数 `-1.0`→`0.0`（即 `E[i]>0` 项被乘 0 不累加），且「±2.0 标记」写入点**后移到门 4 之后** ⇒ `dmmd_t` 把上下两支统一成「只算负向面积」口径 [A]。
- **`dnum` = 数「段号」**：对 `aux` 数组只算符号（不看绝对值），末尾 `aux[i]==1` 时把 1 记成累计段号的末段号（伪码 `.c` 写成「自由复位」已勘误）[A 结构 / B 业务]。
- **`dsmmd`**：`out[serial-1] = (rec[+0x98]==1) ? 0 : (double)ftol(rec[+0x6C])`，值来自 `0x10065790` 写的 ±1.0f [A]。
- **9 支全部以 `serial-1` 为下标散射**，`count` 只用于输出缓冲长度；`Chdzhongshug/(d)`、`Chdzhongshu`、`dsmmd`、`dnum` 在记录序号 ≥ count 时**越界写** [A]。
- **⚠️ §3.9 的 `esp` 槽位坑第三次出现**：`dnum` 的 5 个实参在伪码 `.c` 里全部偏大 4（真实 `sub esp,0x70` 而非 `0x78`），而 `dmmd` 的同一组字面值恰好正确 —— 同一批、同一伪码文件里两支函数一个错一个对，说明该坑与「是否手算过 push 数量」直接相关。已在 docs/45 §4.5 列 P1–P10 勘误表。
- **遗留 [C] 10 条**（见 docs/45 §五）：`+0x64/+0x68/+0x5C/+0x6C/+0x9C` 业务定名、`+0x0C/+0x10/+0x24/+0x34/+0x58` 语义、越界写运行时后果等，其中 7 条标注「素材未覆盖，需动态验证」。
- **证据**：`docs/45`（911 行）、`pseudocode/chdzhongshu.c`（39 KB）、`tools/re-inventory/chdzhongshu/`（14 份）+ `macdarea/`（4 份）。

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
| **Index/RLD 族 + NChBi 消费族（F2/F3）** | ✅ **docs/42 + docs/43 + pseudocode/{index_rld,nchbi_consumers}.c 已交付**（2026-10-28，§2.13）；剩余 [C]：s3..s6 类别顺序、SecArea 累加、BiPlan.bin 布局 |
| **笔中枢买卖点族（F4，4 支）** | ✅ **docs/44 + pseudocode/chbmmd.c + tools/re-inventory/chbmmd/（8+2 份 dump）已交付**（2026-10-28，§2.14）；纯静态，剩余 10 条 [C]（字段语义 / 买卖归属 / 面积常数），收口需一次 GUI 触发 + frida 打点 |
| **第 2 波（F4 / F5+F6 / F7）** | ✅ **全部交付**：F4 docs/44；**F5+F6 docs/45（⚠️ 曾漏落盘，2026-10-28 补写 911 行 / S1–S14，§2.21）** + `pseudocode/chdzhongshu.c`；F7 docs/46 + `pseudocode/macd_area.c`（§2.15） |
| **第 3 波（F8 / F9 / F10 / F11）** | ✅ **全部交付**：F8 docs/49 + `qjt.c`；**F9 docs/47 + `nchfx.c`（§2.16）**；**F10 docs/48（§2.17，`zoushi_rec.c` 补写中）**；F11 docs/50 + `rld_order.c` |
| **第 4 波（F12+F14 / F13+F15+F16）** | ✅ **全部交付**：F12+F14 docs/51 + `ygj_kxqj.c`（§2.19）；F13+F15+F16 docs/52 + `nch_misc_wnmr.c`（§2.18） |
| `docs/19` 看板 | ✅ 已刷新（verify_status.py --write，2026-10-28 ~13:00） |
| `inject_*_bypass` 四路 hook | ✅ 已挂 MainApp PID 8392（Authorize/perm/func/cmd）；⏸ 暂无 [AUTH] 命中，需 GUI 触发付费公式 |
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
9. **F4 后续（docs/44，10 条 [C]）**：一次性收口办法 = GUI 触发 BIMMD 系公式 + frida 打点，打印 `+0x28/+0x30/+0x50..0x5C/+0x6C/+0x9C` 的真实取值分布（可复用 `inject_*_bypass` 的 func hook 骨架）。若能拿到记录级分布，遗留 2/3/4/5 可同时闭合。
10. ~~F5+F6 段中枢族 / F7 MACD 面积 待启动~~ → ✅ 已完成（docs/46、§2.15）。**docs/45 曾漏落盘，2026-10-28 已补写（911 行 / S1–S14 / 遗留 10 条，§2.21）**，并纠正伪码 10 处错误。开工第一步照 §3.9：先按 DLL 原始字节线性反汇编核验 dump 完整性，再逐条读槽；含 `push;call;mov [esp+X]` 的序列一律先做 -4 修正（**该坑已在 F4、F10、F5+F6 三个批次被独立重踩，见 §3.9 红色提示框**）。
11. **F7/F9/F10 遗留 [C] 收口**（共 ~18 条）：`elem+0x24` 段端点戳语义、MACD 面积未做原生对拍、ZouShiZsAll 四组嵌套扫描的业务命名、ZouShimmd 面积积分的业务含义、raw 分型 `+0x09` 之外字段语义。收口办法同 §5.9：GUI 触发对应公式 + frida 打点打印字段真实取值分布。
12. ~~F12+F14 / F13+F15+F16 验收~~ → ✅ 全部验收完成（docs/51 §2.19、docs/52 §2.18）。
13. ~~全批收尾：刷新 `docs/19` 看板 + 汇总遗留 [C] 清单~~ → ✅ 本轮全部 61 支已验收（8 支核销 + 53 支本会话交付）；**遗留 [C] 汇总已落盘 `docs/53-遗留问题汇总.md`（79 条，严格 [C] 约 50 条；按收口方法分四类）**。⚠️ 看板曾漏登记 F5+F6 批次，见 §3.11。
14. **`esp` 槽位坑的自动化**（**已从"可选"提升为必做**）：在 `disasm_func.py` 加 `--fix-esp` 开关自动识别 `push;call;mov [esp+X]` 序列并输出修正后槽位表。理由：该坑已跨 3 个批次、3 个不同函数族重复出现（F4 ChBmmd / F10 ZouShiZsAll+ZouShimmd / F5+F6 dnum），且同一伪码文件内都会一支错一支对。
15. **下一波候选**：① ~~ygj 的 chlib 侧实现~~ → ✅ 已关闭（chlib!0x10006260 = EMA(30, scale=0.01)，文档 docs/51 §二.2）；② 动态对拍收口（GUI 触发付费公式 + frida 打点）——**bypass 四路已于 2026-10-28 全部停止、MainApp 8392 已退出（非崩溃），需重启客户端并重挂 bypass 才能继续**；③ 各批遗留 [C] 的字段语义批量收口（清单见 docs/53）。
16. **动态对拍执行清单（重启 MainApp 后）**：① 重启 `D:\a_ronglide\缠中说禅\MainApp.exe`；② 重挂 `inject_{authorize,perm,func_perm,cmd_perm}_bypass.py <新PID>` 四路；③ 挂 `tools/probe_legacy_c.js`（已写好，含 `[REC]` 记录写点 + `[YGJ]` chlib worker 探针）；④ 在 GUI 依次预览付费公式；⑤ 按 docs/53 §三「需 GUI 触发 + frida 打点」分类逐项取数。

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
- **笔中枢买卖点族（F4）**：`docs/44-笔中枢买卖点-第一批-Bmmd-Bsmmd-Leimmd.md`、`pseudocode/chbmmd.c`、`tools/re-inventory/chbmmd/`（f_1000fa10/1000fd10/1000fe10/1000ff10 包装层、f_1002c890/1002cb80/1002d0c0/1002e040 worker、f_10001d90/10001db0 临时对象 vtable）

---

## 7. 更新规约

1. 任何新错误/教训 → 立即追加 §3（分类编号）。
2. 任何新验证事实 → 追加 §2。
3. 任务进展/状态变化 → 更新 §4、§5。
4. 保持条目具体：写清路径、地址、字节、命令。
