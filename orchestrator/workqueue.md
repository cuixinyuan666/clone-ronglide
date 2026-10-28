# 逆向作战清单（剩余 ~70 付费函数）— orchestrator 主控

> 主控：Hermes 0-default（大脑）。worker = hermes profile 1-claude / 2-opencode / 3-codex / 4-deepseek-harness（元宝回报）。
> 纪律：worker 只写自己名下的 docs/NN-*.md 与 pseudocode/*.c；summary.md、本文件、看板由主控更新。
> git：每批验收合格后由主控 commit（用户已授权：每批落盘即 commit）。
> 回报：worker 完成/失败各发一条到元宝；主控每日汇总一条。
> 降载红线：物理内存 >90% → 立降并发；worker 15 分钟无输出 → kill 转串行。
> 动态对拍：只允许 notepad 宿主 spawn 新实例（frida_native_host.py 路线）；**禁止 attach MainApp PID 8392（用户自用实例）**。

## 已完成（不再排入）
ChBi(#44), NChBi(#43), ZouShiBi(#45), ChFxbi(#53), NChZs(#69)+L2M(#9)+Fj/Dg/HLTurn 消费链(docs31-36), ChZhongShu/G/D(#5,10,11), wnmrnew(#75), wnmrprinew(#76), CHDUAN 引擎链。

## 作战波次（引用次数降序 + 引擎聚类）

### 第 1 波（进行中）
| 包 | family | 函数 | worker | 交付 |
|---|---|---|---|---|
| F1 | NChZs 输出族 | NChZsG 0x10013370(25) NChZsD 0x100133e0(25) NChZsBs12 0x10013460(24) NChZsBs3 0x100134e0(8) | 1-claude | docs/41 |
| F2 | NChBi/NChZs 消费族 | NChBiSta 0x10012c40(12) NChBiZj 0x10012d20(4) NChFjZsNum 0x10013810(4) NChBiZjOrder 0x10012e00(2) NChMacdArea 0x10013a90(2) NChBhh 0x10012740(1) NChBhl 0x100127b0(1) NChSecArea 0x10013b10(1) | 2-opencode | docs/42 |
| F3 | MACD参数+Index/RLD 族 | IndexDuo 0x10008580(5) IndexKong 0x10008870(5) Macdnum 0x100105a0(3) IndexCount 0x100090f0(3) HyDuo 0x10008b50(1) IndexMA 0x10008e10(1) IndexCountInner 0x10009470(0) | 3-codex | docs/43 |

### 第 2 波（排队）
- F4 笔中枢买卖点：ChBmmd 0x1000fd10(6) ChBsmmd 0x1000ff10(5) ChLeimmd 0x1000fa10(1) ChBmmd_t 0x1000fe10(0) → docs/44
- F5 段中枢族：Chdzhongshu 0x10010760(8) dmmd 0x10011060(5) dsmmd 0x10011720(3) Chdzhongshug 0x10010960(1) Chdzhongshud 0x10010a60(1) dmmd_t 0x10011160(0) dnum 0x10011260(0) → docs/45
- F6 中枢统计：Zstj 0x10010860(3) dzstj 0x10011de0(1) → 并入 docs/45 或 44
- F7 MACD 面积：Chbimacds 0x10010b60(1) Chduanmacds 0x10010d60(1) Chbimacds_t 0x10010c60(0) Chduanmacds_t 0x10010e60(0) → docs/46

### 第 3 波（排队）
- F8 区间套：Qjtmm 0x100103a0(1) Qjtd 0x100104a0(1)
- F9 NChFx 族：NChFx 0x10012890(3) NChFxUpDn 0x10012970(2) NChFxOrder 0x100129e0(2) NChFxSta 0x10012900(0) NChBiFxNum 0x10012e70(0) NChBiSpeed 0x10012f50(0)
- F10 走势/递归：ZouShiZsAll 0x10010110(9) ZouShimmd 0x10010210(9) zsdg 0x10011a20(9) nzsqj 0x10011920(1) nzs 0x10011820(0)
- F11 RLD 订单：RLDOrder 0x10014160(12) RLDCycleOrder 0x10014270(0)

### 第 4 波（扫尾）
- F12 一根筋：ygj 0x100121a0(2) bdtd 0x10012220(1) ygjmm 0x10012320(0) scqd 0x10010f60(0)
- F13 NChBi 杂项：NChBiZjNum 0x10012ee0(1) NChRef 0x10012820(0) NChBiSta2 0x10012cb0(0) NChBiZj3 0x10012d90(0)
- F14 kxqj 三兄弟：kxqj 0x10011360(0) kxqjg 0x10011460(0) kxqjd 0x10011560(0)
- F15 wnmr 旧版：wnmr 0x10011b20(0) wnmrpri 0x10011c20(0)
- F16 独立扩展器：Kzq 0x10012420(1)（EA6B）
- 待核销：NChZsSel/SelPri/SelSlPri/SelSpPri/NChZsBreach/NChZsDg/NChZsFj/NChZs_L2 —— 先对照 docs/31-36 确认是否已覆盖，未覆盖才排入。

## 状态台账
| 时间 | 事件 |
|---|---|
| 2026-10-28 | 计划定稿（grill 三轮），第 1 波 F1/F2/F3 派发 |
