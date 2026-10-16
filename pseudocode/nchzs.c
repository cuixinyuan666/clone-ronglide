/* ============================================================================
 * nchzs.c — 融立德「NChZs（缠论中枢·新版）」逆向伪码（框架）
 * ----------------------------------------------------------------------------
 * 来源: TAFLib.dll (32-bit, PE 链接时间 2023-03-15) + chlib.dll (106496 B, 同日)
 * 证据: tools/re-inventory/nchzs/
 *         第一批: chlib_100045f0.txt / cond_chlib_100045f0.txt /
 *                 chlib_100046a0.txt / chlib_100046c0.txt /
 *                 chlib_100046e0.txt / chlib_10004700.txt /
 *                 chlib_worker_10006800.txt / chlib_worker_10006860.txt /
 *                 chlib_worker_100068c0.txt /
 *                 taf_10013*.txt / dump_vt_nchzs.py / vt_nchzs.txt /
 *                 family_recon.txt / nchzs1_wip.md
 *         第二批: scan_engine.py / chlib_100010d0.txt (ch_api ctor) /
 *                 chlib_1000e7c0.txt (engine ctor, vt 0x1001549c) /
 *                 chlib_1000e900.txt (reset) / chlib_1000e0b0.txt (setter) /
 *                 chlib_1000ebe0.txt (build) / chlib_1000e990.txt (C0 生产者) /
 *                 chlib_1000f680.txt (段生产者) / chlib_10004720.txt (Breach) /
 *                 chlib_10005a50.txt (SelPri) / cond_chlib_10004720+10005a50+100048a0.txt /
 *                 chzs_container_layout.txt / nchzs2_wip.md
 * 批次: 第一批 (docs/31) + 第二批 (docs/32), 2026-10-17
 * 置信度: [A]=实测已证(字节级) [B]=高(多路交叉) [C]=待仲裁/推断
 * ----------------------------------------------------------------------------
 * 整体链路（与 NChBi 不同: NChZs 走 TAFLib 包装 + chlib 转发器 + 引擎对象）:
 *   TAFLib CalcProc_NChZs(n, out, ...)  → Authorize(EA61/EA63)  [0x10014e60]
 *                                       → Fetch6Buffers(0x10006cc0)
 *                                       → vt[+0x78] = chlib 0x100045f0
 *   chlib 0x100045f0: memset(out) → this[+0x18]->vt[+0xc](...)  # 引擎真身转发
 *   ── 子功能 ──
 *   NChZsG / NChZsD     → worker 0x10006800 / 0x10006860  (中枢 ZG/ZD 价带展开)
 *   NChZsBs12 / Bs3     → worker 0x100068c0(mode 12 / 3)  (分类标志展开)
 * ==========================================================================*/

/* ---------------------------------------------------------------------------
 * 0. 关键地址速查
 * -------------------------------------------------------------------------*/
/*
 *  TAFLib.dll (ImageBase 0x10000000)
 *    0x10014e60  Authorize(code)                        授权谓词
 *    0x10013240  ?CalcProc_NChZs      (vt +0x78)  EA61(首)/EA63(后续)
 *    0x100132d0  ?CalcProc_NChZs_L2   (vt +0x78)  EA61/EA62/EA63 分层
 *    0x10013370  ?CalcProc_NChZsG     (vt +0x7c)  EA61
 *    0x100133e0  ?CalcProc_NChZsD     (vt +0x80)  EA61
 *    0x10013460  ?CalcProc_NChZsBs12  (vt +0x84)  EA61
 *    0x100134e0  ?CalcProc_NChZsBs3   (vt +0x88)  EA61
 *    0x10013560  ?CalcProc_NChZsBreach(vt +0x8c)  EA61
 *    0x100135e0  ?CalcProc_NChZsL2M   (vt +0x90)  EA61
 *    0x100136f0  ?CalcProc_NChZsDg    (vt +0x98)  EA63+EA61
 *    0x10013780  ?CalcProc_NChZsHLTurn(vt +0x9c)  EA63+EA61
 *    0x10013890  ?CalcProc_NChZsSel   (vt +0xa4)  EA62   (SelPri 三兄弟 +0xa8/ac/b0)
 *    0x10006cc0  取 6 行情缓冲 (H/O/L/C/V/A)  [与 NChBi 包装层同]
 *    0x10006bd22 memset 调用桩 (包装层清零)
 *
 *  chlib.dll (ImageBase 0x10000000)
 *    0x10015214  ch::ch_api 虚表
 *    0x100045f0  NChZs 主入口转发器 (NChZs / NChZs_L2 共享; ret 0x10)
 *    0x100046a0  NChZsG 薄包装  -> 0x10006800
 *    0x100046c0  NChZsD 薄包装  -> 0x10006860
 *    0x100046e0  NChZsBs12 薄包装 -> 0x100068c0 (mode=12)
 *    0x10004700  NChZsBs3  薄包装 -> 0x100068c0 (mode=3)
 *    0x10006800  段价带展开 (ZG)
 *    0x10006860  段价带展开 (ZD)
 *    0x100068c0  分类标志展开 (mode 12/3)
 *    0x1001494c  memset thunk   [与 NChBi 同]
 */

/* ============================================================================
 * 1. TAFLib 包装层: NChZs / NChZs_L2  (授权分层)
 * ==========================================================================*/

/* --- 1.1 NChZs (TAFLib 0x10013240, ret 0xc) [A] -------------------------- */
bool CalcProc_NChZs(int n, double* out, void* arg3)
{
    int code = (this->counter_0xb8 <= 0) ? 0xEA61 : 0xEA63;
    if (!Authorize(code)) {                       /* 0x10014e60 */
        memset(out, 0, n * sizeof(double));       /* 0x1006bd22 */
        return false;
    }
    void* buf[6];                                 /* H/O/L/C/V/A */
    Fetch6Buffers(&buf);                          /* 0x10006cc0 */
    this->counter_0xb8 += 1;                      /* ★ 层计数器自增 */
    /* ch_api*(this[+0xbc]) -> vt[+0x78] */
    return this->chapi_0xbc->vt_0x78(n, out, buf, arg3);
}

/* --- 1.2 NChZs_L2 (TAFLib 0x100132d0, ret 0xc) [A] ---------------------- */
bool CalcProc_NChZs_L2(int n, double* out, void* arg3)
{
    int c = this->counter_0xb8;
    bool auth;
    if (c <= 0)       auth = Authorize(0xEA61);
    else if (c == 1)  auth = Authorize(0xEA62);
    else              auth = Authorize(0xEA63) && Authorize(0xEA62);
    if (!auth) { memset(out, 0, n * sizeof(double)); return false; }
    void* buf[6];
    Fetch6Buffers(&buf);
    this->counter_0xb8 += 1;
    return this->chapi_0xbc->vt_0x78(n, out, buf, arg3);   /* ★ 同一实现 */
}

/* ============================================================================
 * 2. chlib 主入口转发器 0x100045f0 (NChZs / NChZs_L2 共享, ret 0x10) [A]
 * ==========================================================================*/
int nchzs_dispatch(int n, double* out, void* a3, void* a4)   /* thiscall */
{
    void* eng = this[+0x18];                      /* 引擎对象 */
    double* pbase = a3[+4];                       /* a3 = {?, base, ...} */
    memset(pbase, 0, n * sizeof(double));         /* 0x1001494c */
    if (a3[0] == 0 || a3[8] == 0) return -1;      /* 门 G3/G4 */
    if (!eng->vt[+4]()) return -1;                /* G5: 无参授权/有效性虚调用 */
    eng->vt[+0xc](n, pbase, a3[0], a3[8], a4);    /* G6: 5 参真工作 */
    helper_0x1000e990(n, eng);                    /* G7 */
    if (eng->vt[+8]() != 0 || eng == NULL) return -1;   /* G8 */
    helper_0x10006700(this);                      /* G9 */
    return 0;
}

/* ============================================================================
 * 3. 子功能薄包装 + 共享 worker
 * ==========================================================================*/

/* --- 3.1 NChZsG (chlib 0x100046a0) / NChZsD (0x100046c0) [A] ------------ */
int nchzs_G(int n, double* out, void* a3)   /* ret 0x10 */
{
    return rec_price_expand_0x10006800(this[+0x18], n, out);   /* ZG */
}
int nchzs_D(int n, double* out, void* a3)
{
    return rec_price_expand_0x10006860(this[+0x18], n, out);   /* ZD */
}

/* --- 3.2 worker 0x10006800(G=ZG) / 0x10006860(D=ZD) [A] ----------------- */
/* 两支逐句同构, 唯一差别 = 价字段偏移 (G: ptr-0x3c ; D: ptr-0x30) */
int rec_price_expand(engine_t* eng, int n, double* out, int price_off)
{
    memset(out, 0, n * sizeof(double));
    Rec5d* base = eng->segs_0x30;                 /* [eng+0x30] */
    int   cnt   = eng->segcnt_0x3c;               /* [eng+0x3c] */
    if (!base || !cnt) return -1;
    char* ptr = (char*)base + 0x55;               /* i=0 循环指针 */
    do {
        if (ptr[-0x41] & 1) {                     /* 段 flags.bit0 = 有效 */
            int A = *(int*)(ptr);
            int B = *(int*)(ptr + 4);
            double price = *(double*)(ptr + price_off);   /* G: -0x3c ; D: -0x30 */
            for (int k = A; k <= B; ++k) out[k] = price;
        }
        ptr += 0x5d;                              /* ★ stride 0x5d */
    } while (--cnt);
    return 0;
}

/* --- 3.3 NChZsBs12 (0x100046e0) / NChZsBs3 (0x10004700) [A] ------------ */
int nchzs_Bs12(int n, double* out)   /* ret 0x10; 只传 n/out */
{
    return flag_scatter_0x100068c0(this[+0x18], n, 12);
}
int nchzs_Bs3(int n, double* out)
{
    return flag_scatter_0x100068c0(this[+0x18], n, 3);
}

/* --- 3.4 worker 0x100068c0 (分类标志散射; ret 8 = 2 参) [A] ------------- */
int flag_scatter(engine_t* eng, int n, int mode)
{
    memset(out, 0, n * sizeof(double));
    Rec18* base = eng->cls_0x40;                  /* [eng+0x40] */
    int    cnt  = eng->clscnt_0x2c;               /* [eng+0x2c] */
    if (!base || !cnt) return -1;
    char* ptr = (char*)base + 0x14;
    do {
        int v;
        if (mode == 12) {                         /* Bs12: 3 选 1 */
            v = ptr[1] ? (signed char)ptr[1]
              : ptr[0] ? (signed char)ptr[0]
              : (signed char)ptr[3];
        } else {                                  /* Bs3: 按 span 缩放 */
            signed char dl = (signed char)ptr[2];
            void* p = *(void**)(ptr - 8);
            v = 0;
            if (dl != 0 && p != NULL) {
                int span = *(int*)((char*)p + 0xc) - *(int*)((char*)p + 8) + 1;
                v = dl * (span > 3 ? 1 : 10);     /* 位技巧: 1 或 10 */
            }
        }
        int idx = *(int*)(ptr - 0x14);
        if (idx >= 0 && idx < n) out[idx] = (double)v;
        ptr += 0x18;                              /* ★ stride 0x18 */
    } while (--cnt);
    return 0;
}

/* ============================================================================
 * 4. 数据结构（本批已确权部分）
 * ==========================================================================*/
/* 段记录 Rec5d (stride 0x5d = 93 B); 绝对偏移基于 rec_i = segs + i*0x5d [B] */
typedef struct Rec5d {
    uint8_t  _hdr[0x14];   /* +0x00..0x13 头部 20B, 语义 [C] */
    uint8_t  flags;        /* +0x14  bit0 = 有效 */
    uint8_t  _pad0[4];
    double   zg;           /* +0x19  ZG 中枢上沿 (G 用) */
    uint8_t  _pad1[4];
    double   zd;           /* +0x25  ZD 中枢下沿 (D 用) */
    uint8_t  _pad2[0x18];
    int32_t  barIdx;       /* +0x41  (Bs worker 用) */
    uint8_t  _pad3[0x10];
    int32_t  A;            /* +0x55  区间起 */
    int32_t  B;            /* +0x59  区间止 */
} Rec5d;                   /* sizeof = 0x5d */

/* 分类记录 Rec18 (stride 0x18 = 24 B); 相对 ptr(base+0x14) */
typedef struct Rec18 {
    int32_t  barIdx;       /* +0x00  (idx = [ptr-0x14]) */
    uint8_t  _pad0[8];
    void*    p;            /* +0x0c  (span 源; [ptr-8]) */
    uint8_t  b0, b1, b2, b3;  /* +0x14..+0x17 (mode12 取 b1/b0/b3; mode3 取 b2) */
} Rec18;                   /* sizeof = 0x18 */

/* 引擎对象 (this[+0x18]) — 多容器 [A 相对偏移] */
typedef struct engine_t {
    uint8_t  _pad0[0x2c];
    int32_t  clscnt;       /* +0x2c */
    void*    segs;         /* +0x30  段数组 base */
    uint8_t  _pad1[8];
    int32_t  segcnt;       /* +0x3c */
    void*    cls;          /* +0x40  分类数组 base */
} engine_t;

/* ============================================================================
 * 5. 遗留 [B]/[C]
 * ==========================================================================*/
/*
 *  [A] 段记录偏移 (rec = segs + i*0x5d) —— 第二批已闭合 (见 6.2)
 *  [C] 段 rec+0x15..0x18 / 0x29..0x40 / 0x45..0x54 未知区语义
 *  [A] 引擎对象 this[+0x18]: ctor 0x1000e7c0, 虚表 0x1001549c (第二批已闭合, 6.1)
 *  [A] vt[+4]=reset(0x1000e900) / vt[+0xc]=setter(0x1000e0b0) / vt[+8]=build(0x1000ebe0) (6.3/6.5)
 *  [B] "G/D"=ZG/ZD 已由 Breach 的 fcomp 反证; "Bs" 字面 3/12 = 模式开关; this[+0xb8] 层计数器语义
 *  [A] C0 生产者 = 0x1000e990 (核心体 helper); [C] 0x1000eb80 / 0x10006700 未展开
 *  [A] 第二批: NChZsL2M(0x100048a0) 无递归 (递归假设证伪, 7.4)
 *  [A] 第二批: SelPri/SelSlPri/SelSpPri 三支逐字节同构
 *  [C] 构建链中段 8 支 (0x1000f8c0/fa40/fc60/ff80/10ee0/10f80/11170/11360) 未展开
 *  [C] 本批未做动态验证 (frida 预备包待用户在场)
 */

/* ============================================================================
 * 6. 第二批: 核心体引擎 (docs/32 T1)
 * ==========================================================================*/
/*
 * 6.1 引擎身份 [A]
 *   ch_api ctor 0x100010d0 (ret 8): this[+0x18] = new(0x68) + ctor 0x1000e7c0
 *   engine ctor 0x1000e7c0 (ret 4): engine[0x00] = &vt_engine (0x1001549c)
 *                                   engine[+0x1c] = 9; 其余清零   (对象大小 0x68)
 *   引擎虚表 0x1001549c (5 槽):
 *     +0x00 0x1000e850  dtor
 *     +0x04 0x1000e900  reset
 *     +0x08 0x1000ebe0  build      (返 int; !=0 -> 核心体返 -1)
 *     +0x0c 0x1000e0b0  setter     (ret 0x14, 5 参)
 *     +0x10 0x1000ed20  dispatch   (1 -> 0x10011500 / 2 -> 0x10011660 / 0x65 -> 0x100117b0)
 *
 * 6.2 引擎容器与记录 (详表: tools/re-inventory/nchzs/chzs_container_layout.txt) [A]
 *   C0: engine[+0x20] base / engine[+0x2c] count / stride 0x31   分型-笔序列
 *   C1: engine[+0x30] base / engine[+0x38] cap / engine[+0x3c] count / stride 0x5d  中枢段
 *   C2: engine[+0x40] base / stride 0x18 (count = C0.count)      分类标志
 *   C3: engine[+0x4c] base / stride 0x1d                         段点输出
 *   V : engine[+0x5c] beg / engine[+0x60] end / 元素 0x74 = 4 x 0x1d
 *
 *   struct Rec5D {            // C1: stride 0x5d = 93
 *     int    mode;            // +0x00  buildSegment arg3
 *     int    self;            // +0x04  写入前的 C1.count
 *     int    startBar;        // +0x08
 *     int    endBar;          // +0x0c
 *     int    dir;             // +0x10  +1 / -1
 *     u8     flags;           // +0x14  bit0 = 有效
 *     u8     pad[4];          // +0x15
 *     double ZG;              // +0x19  中枢上沿 (G worker / Breach dir!=-1)
 *     u8     pad2[4];         // +0x21
 *     double ZD;              // +0x25  中枢下沿 (D worker / Breach dir==-1)
 *     u8     pad3[0x18];      // +0x2d
 *     int    barIdx;          // +0x41  (Bs worker)
 *     u8     pad4[0x10];      // +0x45
 *     int    A;               // +0x55  输出区间起
 *     int    B;               // +0x59  输出区间止
 *   };
 *   struct Rec31 {            // C0: stride 0x31 = 49
 *     int    dir;             // +0x00
 *     int    lo;              // +0x04  子区间起
 *     int    hi;              // +0x08  子区间止
 *     int    mark;            // +0x0c  =1 当值 in {-2,+2}
 *     u8     pad[4];          // +0x10
 *     int    idxA;            // +0x11  -> C3[+0x09] (dir==-1 支)
 *     int    idxB;            // +0x15  -> C3[+0x09] (dir!=-1 支)
 *     double p1;              // +0x19  -> C3[+0x0d]
 *     double p2;              // +0x21  -> C3[+0x15]
 *     double p3;              // +0x29  条件写
 *   };
 *
 * 6.3 核心体 0x100045f0 主路径 [A]  (ret 0x10, 4 参)
 *   int NChZs_core(ch_api* this, int n, double* out, TDesc* a3, TArg* a4)
 *   {
 *     memset(out, 0, n*8);                                   // 0x1001494c
 *     if (a3[0] == 0 || a3[8] == 0) return -1;               // 两指针非空门
 *     engine = this[+0x18];
 *     engine->vt[+4]();                                      // 0x1000e900 reset
 *     engine->vt[+0xc](n, a3[0], a3[8], a3[4], a3);          // 0x1000e0b0 setter
 *     sub_1000e990(n, a4[0]);                                // 生产 C0
 *     if (engine->vt[+8]() != 0) return -1;                  // 0x1000ebe0 build
 *     if (this[+0x18] == 0) return -1;
 *     sub_10006700(this);
 *     return 0;
 *   }
 *   // 失败出口 0x10004689: or eax,-1 ; pop edi/esi/ebp/ebx/ecx ; ret 0x10
 *
 * 6.4 setter 0x1000e0b0 [A]  (ret 0x14)
 *   { engine[+4]=a2; engine[+8]=a3; engine[+0xc]=a4; engine[+0x10]=a5; engine[+0x14]=a1; }
 *
 * 6.5 build 0x1000ebe0 [A]
 *   int build(engine)
 *   {
 *     if (!C0.count || !C0.base || !engine[+0x28]) return -1;
 *     n = C0.count;
 *     resize(&C1, n*2); memset(C1.base, 0, n*0xba); C1.count = 0;
 *     resize(&C2, n);   memset(C2.base, 0, n*0x18);
 *     resize(&C3, n);   memset(C3.base, 0, n*0x1d);
 *     reset(&engine[+0x58]);
 *     for (i = 0; i < n; ) { r = buildSegment(engine, i, n, 0); i = (r > 0 ? r : i) + 1; }
 *     for (k = 0; k < C1.count; k++) {                 // C1 -> C3 后处理
 *        Rec5D* rec = &C1[k];
 *        if (!(rec->flags & 1)) continue;
 *        idx = rec->startBar + 1;
 *        if (idx < 0 || idx >= n) break;
 *        Rec1D* dst = (Rec1D*)((char*)C3.base + idx*0x1d);
 *        Rec31* src = (Rec31*)((char*)C0.base + idx*0x31);
 *        dst->valid = 1; dst->barIdx = idx;
 *        dst->dir = (src->dir == -1) ? +1 : -1;
 *        dst->idx = (src->dir == -1) ? src->idxA : src->idxB;
 *        dst->p1  = src->p1;  dst->p2 = src->p2;
 *     }
 *     return 0;
 *   }
 *
 * 6.6 段生产者 0x1000f680 [A]  (ret 0xc, 3 参)
 *   int buildSegment(engine [ecx], int i, int n, int mode)
 *   {
 *     if (C1.count >= engine[+0x38]) return -1;              // 容量门
 *     Rec5D* rec = &C1[C1.count]; memset(rec, 0, 0x5d);
 *     rec->mode = mode;  rec->self = C1.count;
 *     r = sub_1000f8c0(i, n); if (r < 0) return -1;
 *     sub_10011170(engine, rec);
 *     ... // 在 0x1000fa40 / 10ee0 / 10f80 / 0x1000fc60 / 0x1000ff80 判据下推进/收尾
 *     rec->flags |= 1;                                       // 有效
 *     // 有效性: span = endBar - startBar + 1 >= 3 且 dir in {+1,-1}
 *   }
 *
 * 6.7 C0 生产者 0x1000e990 [B]  (ret 8, 2 参)
 *   入参: n (a1), priceArray (a2)。init C0 (resize n) -> engine[+0x2c]=0 ->
 *   逐 bar 生成记录: 写 p2(+0x21)/p3(+0x29), mark(+0x0c)=1 当值 in {-2,+2}, count++。
 */

/* ============================================================================
 * 7. 第二批: 三兄弟与 L2M 侦察 (docs/32 T2/T3)
 * ==========================================================================*/
/*
 * 7.1 NChZsBs3 (0x10004700) [A]
 *   { eax = a1; edi = a2; push 3; push eax; eax = this[+0x18]; call 0x100068c0; }
 *   // 与 NChZsBs12 唯一差别 = 字面量 3 vs 12 (模式开关)。 0 个 x87 条件。
 *
 * 7.2 NChZsBreach (0x10004720) [A 结构 / B 语义]  (ret 0x10, 4 参, 2 个 x87 条件)
 *   int breach(this, n, out, a3, a4)
 *   {
 *     memset(out, 0, n*8);
 *     engine = this[+0x18];
 *     if (!C0.count || !C0.base || !C1.count || !C1.base) return -1;   // 非空门
 *     for (s = 0; s < C1.count; s++) {
 *        Rec5D* rec = &C1[s];
 *        if (!(rec->flags & 1)) continue;
 *        if (rec->endBar - rec->startBar + 1 <= 3) continue;   // 需 span >= 4
 *        for (idx = rec->startBar + 4; idx <= rec->endBar + 1; idx++) {
 *           Rec31* c0 = (Rec31*)((char*)C0.base + idx*0x31);
 *           if (c0->dir != rec->dir) continue;
 *           cnt = 0;
 *           for (k = c0->lo; k <= c0->hi; k++) {
 *              double p = price[k];
 *              if (rec->dir != -1) { if (!(p <= rec->ZG)) cnt++; }   // fcomp vs rec+0x19
 *              else                { if (  p >= rec->ZD ) cnt++; }   // fcomp vs rec+0x25
 *           }
 *           out[idx] = (double)cnt;    // 计数 (上/下越界次数)
 *        }
 *     }
 *     return 0;
 *   }
 *   // x87 直证: cond_chlib_10004720.txt 2 条件 (price vs [edx+0xd]=ZG / [edx+0x19]=ZD)
 *
 * 7.3 NChZsSelPri (0x10005a50) [A]  (ret 0x10, 4 参, 0 个 x87 条件)
 *   int selpri(this, n, out, a3, a4)
 *   {
 *     memset(out, 0, n*8);
 *     engine = this[+0x18];
 *     beg = engine[+0x5c]; end = engine[+0x60];
 *     cnt = (beg ? (end - beg) / 0x74 : 0);        // 魔数 0x8d3dcb09 => /116
 *     for (e = 0; e < cnt; e++) {
 *        for (j = 0; j < 4; j++) {                 // 4 x 0x1d 子记录
 *           sub = beg + e*0x74 + j*0x1d;
 *           idx = *(int*)(sub + 0x00);  val = *(double*)(sub + 0x04);
 *           if (0 <= idx && idx <= n) out[idx] = val;
 *        }
 *     }
 *     return 0;
 *   }
 *   // SelPri / SelSlPri(0x10005bb0) / SelSpPri(0x10005d10) 三支逐字节同构
 *   //   (diff 仅跳转地址位移); NChZsSel(0x100058f0) 形态不同(有前置 setup)。
 *
 * 7.4 NChZsL2M (0x100048a0) 递归假设证伪 [A]
 *   // 695 行, ret 0x10, sub esp,0x14; 全部直接调用仅 2 处:
 *   //   0x100148a0 (_ftol2) 与 0x1001494c (memset)  => 无自调用/无递归
 *   // 双数组遍历 (imul 0x31 + add 0x5d, 读 C0/C1), 24 处 x87 比较
 *   //   (189 基本块 / 10 conflicts, cond_chlib_100048a0.txt)
 *   // 两类条件: (a) fcomp price vs mem:[edx]; (b) fcom 0.0 vs mem:[ecx+-k*0x31] (符号判定)
 *   // 收口建议: 第三批按支配树切 ~6 段 + x87 条件表逐段复核; 无需追递归栈。
 */
