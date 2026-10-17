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
 * 批次: 第一批 (docs/31) + 第二批 (docs/32) + 第三批 (docs/33) + 第四批 (docs/34)
 *       + 第五批 (docs/35, 招牌成员 Fj/Dg/HLTurn + mode 0x66) + 第六批 (docs/36, L2M 四模式), 2026-10-18
 * 第三批新增: 构建链中段 8 支 (seg_init/seg_extend/seg_endcheck/seg_wrapup/
 *              c2_reg_up/c2_reg_down/seg_finalize/seg_advance) + C1 段记录语义升级
 *              (ZG/ZD/GG/DD 四值 + 下标对 + A/B 输出区间) + 段入册器 0x1000f0e0
 * 证据(第三批): chlib_1000f8c0/1000fa40/1000fc60/1000ff80/10010ee0/10010f80/
 *              10011170/10011360.txt (+cond_*)  chzs_c1_semantics.txt
 *              build_chain_mid.txt  nchzs_build_graph.txt  nchzs3_wip.md
 *              chlib_1000edb0/1000edd0/1000edf0/1000ee30/1000f0e0/1000f200.txt
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

/* ============================================================================
 * 8. 第三批: C1 段记录语义升级 (docs/33 T2)   [A 偏移] -> [A 语义]
 *    权威表: tools/re-inventory/nchzs/chzs_c1_semantics.txt
 * ==========================================================================*//*
 * struct Rec5D {              // C1 段记录, stride 0x5d (93 B)
 *   int    mode;              // +0x00  建段模式 (buildSegment arg2)      1000f6bf
 *   int    self;              // +0x04  自身下标 (= 写入前的 C1.count)     1000f6c8
 *   int    startBar;          // +0x08  段起始 bar                       1000f917
 *   int    endBar;            // +0x0c  段当前终止 bar (随扫描前推)        1000f914/fb2d/fb7a
 *   int    dir;               // +0x10  方向 +1 / -1 (= C0[startBar].dir) 1000f91a/91d
 *   u8     flags;             // +0x14  bit0 有效 / bit1 已收尾 / bit2 端点已登记
 *   int    zgIdx;             // +0x15  ZG 所在 bar 下标
 *   double ZG;                // +0x19  ★中枢上沿 = min(相邻高点)        1000f967
 *   int    zdIdx;             // +0x21  ZD 所在 bar 下标 (下标, 非价!)
 *   double ZD;                // +0x25  ★中枢下沿 = max(相邻低点)        1000f98f
 *   int    ggIdx;             // +0x2d  GG 所在 bar 下标
 *   double GG;                // +0x31  ★段内最高 = max(高点)            1000edcb (判据直证)
 *   int    ddIdx;             // +0x39  DD 所在 bar 下标
 *   double DD;                // +0x3d  ★段内最低 = min(低点)            1000edeb (判据直证)
 *   int    barIdx;            // +0x41  (Bs worker 用; 写点未直证)         [B]
 *   int    slotBar[4];        // +0x45  slotBar[slot] = bar 下标 (slot: 3/4/5/6) 10010f55
 *   u32    pad;               // +0x55  -- 见下 A/B --
 *   int    A;                 // +0x55  ★输出 bar 区间起 = C0[startBar+1].idx  1000f14e
 *   int    B;                 // +0x59  ★输出 bar 区间止 = C0[endBar].idx      1000f161
 * };
 *
 * 8.1 四组「(bar 下标, 价)」对 [A]
 *    ZG (+0x19) min(高) <-> zgIdx (+0x15)     ZD (+0x25) max(低) <-> zdIdx (+0x21)
 *    GG (+0x31) max(高) <-> ggIdx (+0x2d)     DD (+0x3d) min(低) <-> ddIdx (+0x39)
 *    不变式: DD <= ZD <= ZG <= GG
 *
 * 8.2 flags(+0x14) 位台账 [A(bit0..2)]
 *    bit0 = 1  段有效      : 0x1000f680 的 1000f800 / 1000f853 / 1000f8a5  `or byte [edi+0x14],1`
 *    bit1 = 2  已收尾      : 0x1000ff80 的 10010008..10010014  `(flags & 0xfe) | 2`
 *    bit2 = 4  端点已登记  : 0x10010ee0 的 10010f5f (dir=+1) / 0x10010f80 的 10010ff7 (dir=-1)
 *
 * 8.3 C0 记录 p1/p2/p3 语义 [A]
 *    C0[t].p1 (+0x19) = 高(high)    C0[t].p2 (+0x21) = 低(low)    C0[t].p3 (+0x29) = 疑 收/中价 [B]
 *    C0[t].idxA (+0x11) / idxB (+0x15) = 分型点 bar 下标 (dir 分派)
 */

/* ============================================================================
 * 9. 第三批: 构建链中段 8 支伪码 (docs/33 T1)  全部上游 = 0x1000f680
 *    汇总表: tools/re-inventory/nchzs/build_chain_mid.txt
 * ==========================================================================*//*
 * 9.0 派发器 0x1000f680 buildSegment (ret 0xc; ecx=engine; 栈=(i, n, mode))
 *   int buildSegment(Engine* eng, int i, int n, int mode)
 *   {
 *     if (C1.count >= C1.cap) return -1;                       // 容量门
 *     rec = &C1[C1.count]; memset(rec, 0, 0x5d);
 *     rec->mode = mode;  rec->self = C1.count;
 *     r = seg_init(rec, eng, i, n);          if (r < 0) return -1;   // #1
 *     seg_finalize(eng, rec);                                        // #7
 *     for (k = r + 1; k < n; ) {
 *        e = seg_extend(rec, eng, k);                                // #2
 *        if (e > 0) {
 *           seg_advance(eng, rec);                                  // #8
 *           if (seg_endcheck(eng, rec, &flag) > 0)                  // #3
 *               return seg_wrapup(eng, rec, flag);                  // #4  (内含递归)
 *           break;
 *        }
 *        seg_advance(eng, rec);
 *        if (c2_reg_up(eng, rec, k)   > 0) goto L_up;               // #5
 *        if (c2_reg_down(eng, rec, k) > 0) goto L_down;             // #6
 *        if (C0[k].dir != rec->dir) break;
 *        k++;
 *     }
 *   L_up:   if (rec->dir ==  1) return seg_wrapup(eng, rec, 1);
 *   L_down: if (rec->dir == -1) return seg_wrapup(eng, rec, 1);
 *   L_tail: rec->flags |= 1;  return <endBar 相关>;    // 段有效
 *   }
 *
 * 9.1 #1 0x1000f8c0 seg_init (ret 8; ecx=rec; eax=engine; 栈=(i,n))  [A]
 *   int seg_init(Rec5D* rec, Engine* eng, int i, int n)
 *   {
 *     if (!rec) return -1;
 *     if (i < 0 || i + 3 > n) return -1;
 *     C0 = eng[+0x20];
 *     if (C0[i].dir == -1) { if (!(C0[i].p2 > C0[i+2].p1)) return -1; }   // 1000f903
 *     else                 { if (!(C0[i].p1 > C0[i+2].p2)) return -1; }   // 1000f944
 *     rec->endBar = i + 2;  rec->startBar = i;  rec->dir = C0[i].dir;
 *     rec->ZG = min(C0[i].p1, C0[i+2].p1); rec->zgIdx = <取者>;   // +0x15/+0x19
 *     rec->ZD = max(C0[i].p2, C0[i+2].p2); rec->zdIdx = <取者>;   // +0x21/+0x25
 *     rec->GG = max(C0[i].p1, C0[i+2].p1); rec->ggIdx = <取者>;   // +0x2d/+0x31
 *     rec->DD = min(C0[i].p2, C0[i+2].p2); rec->ddIdx = <取者>;   // +0x39/+0x3d
 *     k = sub_1000f180(...);
 *     if (k < 0 || k >= eng[+0x3c]) return rec->endBar;
 *     if (rec->dir == -1) sub_10010ee0(*(C1base + k*0x5d));
 *     else                sub_10010f80(...);
 *     return rec->endBar;
 *   }
 *   // 失败口 0x1000f94e / 0x1000f955(尾): or eax,-1; ret 8
 *
 * 9.2 #2 0x1000fa40 seg_extend (ret 8; edi=rec; 栈=(engine,i))  [A]
 *   int seg_extend(Rec5D* rec, Engine* eng, int i)
 *   {
 *     if (i < 0 || i >= eng[+0x2c]) return -1;              // C0 越界门
 *     if (C0[i].dir == rec->dir)    return -1;              // 非转折点
 *     if (eng[+0x00] != 0) {                                // 非首段: 与前段比对
 *        k = sub_1000f200(eng[+0x3c], rec->dir);
 *        if (k >= 0 && C1[k].dir == rec->dir) {
 *           if (rec->dir == -1) { if (C1[k].GG <  C0[i].p2) goto alt; }
 *           else                { if (C1[k].DD >  C0[i].p1) goto alt; }
 *        }
 *     }
 *     span = rec->endBar - rec->startBar + 1;
 *     if (span > 3) {
 *        // ★ 中枢重叠门: [ZD,ZG] 与 C0[i] 的 [low,high] 必须相交
 *        if (rec->dir == -1) { if (!(rec->ZG >= C0[i].p2 && rec->ZD <= C0[i].p1)) return -1; }
 *        else                { if (!(rec->ZD <= C0[i].p1 && rec->ZG >= C0[i].p2)) return -1; }
 *        rec->endBar = i;  sub_1000edb0(eng, rec, i);  sub_1000edd0(eng, rec, i);
 *        return i;
 *     } else {
 *        rec->endBar = i;                                   // 短段: 与 C0[startBar(±1)] 重评
 *        rec->ZG/ZD/GG/DD 与 +0x15/+0x21/+0x2d/+0x39 重写; sub_1000edb0/edd0;
 *        return i;
 *     }
 *   }
 *   // 拒收口 0x1000fa6b / 0x1000fac1 / 0x1000fb04 / 0x1000fb5f / 0x1000fc08
 *
 * 9.3 #3 0x1000fc60 seg_endcheck (ret 0xc; eax=rec; 栈=(engine,i,*flag))  [A]
 *   int seg_endcheck(Rec5D* rec, Engine* eng, int i, int* flag)
 *   {
 *     *flag = 1;
 *     span = rec ? rec->endBar - rec->startBar + 1 : 0;
 *     eax  = (span > 3) ? span : span;
 *     if (eax >= eng[+0x1c] /* = 9 */) return i;
 *     if (rec->mode == 0) {
 *        if (sub_1000fc10(eng) & 1) *flag = 2;
 *        return i;
 *     }
 *     k = sub_1000f180(...);
 *     if (k < 0) return -1;
 *     seg = &C1[k];
 *     if (C0base == 0) return -1;
 *     if (seg->dir != rec->dir) return -1;
 *     s = seg->endBar - seg->startBar + 1;  if (s > 3) return -1;
 *     if (rec->dir == -1) {
 *        if (rec->ggIdx != seg->endBar) return -1;
 *        if (rec->ddIdx != seg->endBar) return -1;
 *        if (!(C0[rec->startBar].p2 > C0[seg->endBar].p2)) return -1;
 *     } else {
 *        if (rec->ddIdx != seg->endBar) return -1;
 *        if (rec->ggIdx != seg->endBar) return -1;
 *        if (!(C0[scale(seg->startBar)].p1 < C0[...].p1)) return -1;
 *     }
 *     return i;
 *   }
 *
 * 9.4 #4 0x1000ff80 seg_wrapup (ret 8; eax=engine; 栈=(rec,mode))  ★含递归  [A]
 *   int seg_wrapup(Engine* eng, Rec5D* rec, int mode)
 *   {
 *     if (!rec) return -1;
 *     s = sub_1000fdf0(eng, rec);
 *     if (mode == 2) {                                       // 「密集」模式: 四次候选扫描
 *        if (sub_10010070(eng)      > 0) return mode;
 *        if (sub_100100d0(eng)      > 0) return mode;
 *        if (sub_100101c0(eng)      > 0) return mode;
 *        if (sub_100102c0(eng, rec) > 0) return mode;
 *        s = rec->startBar;
 *     }
 *     if (sub_10010d60(eng, rec) > 0) return mode;
 *     k = sub_1000fe50(rec, s, rec->endBar, eng);
 *     if (k < 0) return -1;
 *     rec->flags = (rec->flags & 0xfe) | 2;                  // 已收尾
 *     sub_1000f0e0(eng);
 *     sub_1000f070(rec->endBar, rec->startBar);
 *     if (sub_1000f680(eng, rec->startBar, k + 1, rec) > k) return ...;   // ★★ 递归
 *     sub_1000f010(eng, k);
 *     if (sub_1000f680(eng, <cursor>, eng[+0x2c], rec) > ...) return ...;  // ★★ 递归
 *     return ...;
 *   }
 *
 * 9.5 #5 0x10010ee0 c2_reg_up (ret 4; ecx=eng; eax=rec; esi=idx; 栈=rec2)  [A]
 *   int c2_reg_up(Engine* eng, Rec5D* rec, int idx, Rec5D* newRec)
 *   {
 *     if (!newRec) return -1;
 *     if (idx < 0 || idx >= eng[+0x2c]) return -1;
 *     c0 = &C0[idx];
 *     if (c0->dir != +1)          return -1;
 *     if (!(newRec->ZG > c0->p2)) return -1;
 *     slot = 2;  slot = sub_1000edf0(slot);         // 归一化
 *     if (slot <= 8 && !(c0->flags & 1) && c0->dir == +1) {
 *        C2 = eng[+0x40] + idx*0x18;                // ★ stride 0x18
 *        C2[+0x00]                   = c0->idxB;    // c0[+0x15]
 *        *(Rec5D**)(C2 + 4 + slot*4) = newRec;
 *        *(u8*)(C2 + 0x14 + slot)    = 0xfd;
 *        newRec->slotBar[slot]       = idx;         // newRec[+0x45 + slot*4]
 *     }
 *     if (newRec->dir == +1) newRec->flags |= 4;
 *     return idx - 1;
 *   }
 *
 * 9.6 #6 0x10010f80 c2_reg_down (ecx=eng; ebx=rec; esi=idx)  [A]   // 对称支
 *   // 门: rec!=0 && C0[idx].dir == -1 && rec->ZD <= C0[idx].high
 *   // C2[idx][+0x00] = c0->idxA (c0[+0x11]); 标志字节 = 3; rec[+0x45+slot*4] = idx
 *   // if (rec->dir == -1) rec->flags |= 4;  return idx - 1;
 *
 * 9.7 #7 0x10011170 seg_finalize (ret 4; eax=engine; 栈=rec)  [A]
 *   int seg_finalize(Engine* eng, Rec5D* rec)
 *   {
 *     if (!rec) return -1;
 *     if (!(rec->endBar - rec->startBar + 1 > 3)) return -1;
 *     if (rec->dir == -1) {
 *        if (!(C0[rec->endBar].p1 > C0[rec->startBar].p1)) return -1;
 *        if (!(C0[rec->endBar].p3 < C0[rec->startBar].p3)) return -1;
 *        slotByte = 4;
 *     } else {
 *        if (!(C0[rec->endBar].p2 < C0[rec->startBar].p2)) return -1;
 *        if (!(C0[rec->endBar].p3 < C0[rec->startBar].p3)) return -1;
 *        slotByte = 0xfc;
 *     }
 *     k = sub_1000f200(eng[+0x3c], rec->dir);
 *     slot = (k >= 0) ? (rec->dir == -1 ? 5 : 0xfb) : (rec->dir == -1 ? 5 : 0xf9);
 *     sub_1000ee30(eng, slotByte /* / slot */, rec, ...);      // ★ 写 C3
 *     return rec->endBar;
 *   }
 *
 * 9.8 #8 0x10011360 seg_advance (ret 8; eax=engine; 栈=(engine, rec))  [A]
 *   int seg_advance(Engine* eng, Rec5D* rec)
 *   {
 *     if (!rec) return -1;
 *     span = rec->endBar - rec->startBar + 1;
 *     if (!(span > 3))          return -1;
 *     if (span >= eng[+0x1c])   return -1;        // ★ = 9: 段长上限
 *     i = rec->endBar + 1;
 *     if (i >= eng[+0x2c]) return -1;
 *     if (rec->dir == -1) { if (!(C0[i].p1 > rec->GG)) return -1; }
 *     else                { if (!(C0[i].p2 < rec->DD)) return -1; }
 *     k = sub_1000f200(eng[+0x3c], rec->dir);
 *     sub_1000f1c0(eng, k);
 *     ... // C0[startBar±1].p3 单调性复核
 *     slot = <5 / 6 / 0xfa / 0xfb by (k>=0, dir)>;
 *     sub_1000ee30(eng, slot, ...);               // ★ 写 C3
 *     return rec;
 *   }
 */

/* ============================================================================
 * 10. 第三批: 关键下游 (语义直证链)
 * ==========================================================================*//*
 * 10.1 0x1000edb0  GG 更新器 (12 行, 无栈参; esi=C0 下标; eax=engine; edx=rec)  ★★ [A]
 *      if (C0[esi].p1 > rec->GG) { rec->ggIdx(+0x2d) = esi; rec->GG(+0x31) = C0[esi].p1; }
 *      // 判据: fcomp [edx+0x31]; test ah,0x41; jne -> skip  => 仅当 C0.p1 > rec.GG 才写
 *      //  => 独立确认 +0x31 = GG = max(high)
 *
 * 10.2 0x1000edd0  DD 更新器 (12 行, 同参)  ★★ [A]
 *      if (C0[esi].p2 <= rec->DD) { rec->ddIdx(+0x39) = esi; rec->DD(+0x3d) = C0[esi].p2; }
 *      // 判据: fcomp [edx+0x3d]; test ah,5; jp -> skip  => 仅当 C0.p2 <= rec.DD 才写
 *      //  => 独立确认 +0x3d = DD = min(low)
 *
 * 10.3 0x1000f0e0  ★★★ 段入册器 (61 行, ret 4; esi=rec; arg0=engine)  [A]
 *      int commit_segment(Rec5D* rec, Engine* eng)
 *      {
 *        if (!rec) return -1;
 *        span = rec->endBar - rec->startBar + 1;
 *        if (!(span > 3 ? span : span) >= 3) return -1;       // 段长门 eax < 3 -> -1
 *        if (C1.count >= C1.cap) return -1;
 *        t = &C0[rec->startBar + 1];
 *        rec->A (+0x55) = (t->dir == -1) ? t->idxA(+0x15) : t->idxB(+0x11);
 *        u = &C0[(span > 3) ? rec->endBar : rec->endBar - 1];
 *        rec->B (+0x59) = (u->dir == -1) ? u->idxB(+0x15) : u->idxA(+0x11);
 *        C1.count += 1;                                       // ★ 唯一入册点
 *        return rec->endBar;
 *      }
 *
 * 10.4 0x1000f200 前段查找器 (34 行, ret 4; esi=engine; eax=起扫下标(内部-1); arg0=dir 过滤)
 *      从 C1[eax-1] 反向扫, 返回首个 flags.bit0=1 && span>3 && (dir==arg0 || arg0==0) 的段下标; 无则 -1
 *
 * 10.5 0x1000edf0 slot 归一化 (10 行)  [B]
 *      jmp [eax*4 + 0x1000ee0c];  表项 = 4 个 `ret` 常量桩 (返回 0/1/2/3) => 0..3 恒等映射
 *
 * 10.6 0x1000ee30 C3 写入器 (138 行, ret 8; ecx=engine; al=slotByte; 栈=(arg0, rec))  [C 未展开]
 *      // 段 → C3/V 的映射; 本批只确权调用形态与 slot 字节取值集合 {3,4,5,6,0xfa,0xfb,0xfc,0xfd}
 */

/* ============================================================================
 * 11. 第三批: 勘误与遗留
 * ==========================================================================*//*
 * 勘误 1: ZG/ZD 推导纠正 —— +0x25 = max(low) 而非 min; 修正后与 0x1000edb0/edd0 判据
 *         及 0x1000fa40 重叠门三方自洽。 (初稿误读 jp 目标)
 * 勘误 2: 0x1000f680 非仅被 build 调用 —— 0x1000ff80(seg_wrapup) 内递归调用它 2 次;
 *         构建链为「外层迭代 + 内层递归」双层。 (docs/32 表述修正)
 * 勘误 3: engine[+0x1c] = 9 的用途确认 = 段长上限 (0x10011360 判 span >= 9 停止推进);
 *         撤销 docs/32 的 [C]。 升级 [A]
 * 勘误 4: docs/32「C1 +0x21 属 C0」进一步明确 —— C1 的 +0x21 = zdIdx (下标, 非价),
 *         与 C0 的 +0x21(low) 是同偏移不同容器, 两处解读均成立。
 *
 * 遗留 [B]/[C] (第四批更新):
 *   [A] slot 字节语义已闭合 -> 见 §12.2 归一化表 (只取决于 |slot|; 符号 = 方向门)
 *   [A] C1 +0x45+slot*4 = bar 下标, 由 0x1000ee30 写 (第四批直证, 撤 [B])
 *   [B] C1 +0x45..0x54 部分槽位仍无写入者 (本批见得 4 槽)
 *   [B] C0 +0x29 (p3) 语义: 本批确认为「可加每 bar 标量」, 区间求和后作段评分 (面积/量?)
 *   [A] 0x1000ee30 = C3/C2 写入器 (第四批已展开, §12)
 *   [A] 0x100110a0 / 0x10011010 = C0.p3 区间求和器 (第四批勘误: 非「插值/价查询」, §13.1)
 *   [A] 0x1000fc10 / 0x1000fdf0 / 0x1000fe50 / 0x10010d60 四支收尾辅助已展开 (§14)
 *   [B] 0x1000fe50 的候选生成器 0x1000f490 / 0x1000f5b0 未展开
 *   [C] V 子记录 +0x00 标签字节实际取值; v2(+0x0d) 三 mode 定值表
 *   [C] 本批未做动态验证 (frida 预备包待用户在场)
 */

/* ============================================================================
 * 12. 第四批: C3/C2 写入器 0x1000ee30 + slot 归一化 (docs/34 T1)
 * ==========================================================================*/
/*
 * 12.1 签名 [A]  (ret 8; 4 处调用点直证)
 *
 *   void sub_1000ee30(Engine* eng /*arg0, ebp*/, Rec* rec /*arg1*/,
 *                     int i /*ecx*/, signed char slot /*al*/)
 *   {
 *     if (rec == 0) return;                                  // 1000ee30
 *     if (i < 0 || i >= eng->count /*[+0x2c]*/) return;       // 1000ee46 / ee4e
 *     if (abs(slot) - 1 > 8) return;                          // slot in +-1..+-9
 *     s = sub_1000edf0(abs(slot) - 1);                        // 归一槽 0..3
 *     if (s < 0) return;
 *     Rec31* c0 = &C0[i];                                     // [eng+0x20] + i*0x31
 *     if (c0->mark /*[+0xc]*/ & 1) return;
 *     if (slot < 0 && c0->dir /*[+0x00]*/ != +1) return;       // 方向门
 *     if (slot > 0 && c0->dir                != -1) return;    // 方向门
 *     C2[i].id       (+0x00)     = (c0->dir == -1) ? c0->idxA(+0x11) : c0->idxB(+0x15);
 *     C2[i].ptr      (+4 + s*4)  = rec;
 *     C2[i].slotB    (+0x14 + s) = slot;
 *     rec[+0x45 + s*4]           = i;
 *     if (slot == 0xfa || slot == 0xf8) goto MIRROR_A;
 *     if (slot == 6    || slot == 8)    goto MIRROR_B;
 *     return;
 *   MIRROR_B:  j = i + 2;  if (j >= eng->count) return;
 *              if (!(C0[j].p1(+0x19) < C0[i].p1)) return;
 *              if (C0[j].mark & 1) return;
 *              newSlotRaw = (slot == 6) ? 9 : 2;                  // (slot!=6)-1 & 7 + 2
 *              goto EMIT2;
 *   MIRROR_A:  j = i + 2;  if (j >= eng->count) return;
 *              if (!(C0[j].p2(+0x21) > C0[i].p2)) return;
 *              if (C0[j].mark & 1) return;
 *              newSlotRaw = (slot == 0xfa) ? 0xF7 : 0xFE;         // (slot!=0xfa)-1 & 0xF9 + 0xFE
 *   EMIT2:     s2 = sub_1000edf0(abs((s8)newSlotRaw) - 1);        // 两路均 -> 槽 1
 *              C2[j].id = (C0[j].dir == -1) ? C0[j].idxA : C0[j].idxB;
 *              C2[j].ptr  [+4 + s2*4] = rec;
 *              C2[j].slotB[+0x14+s2]  = newSlotRaw;              // 存原始字节
 *              rec[+0x45 + s2*4]      = j;
 *   }
 *
 * 12.2 slot 归一化表 0x1000edf0 [A]
 *   jmp dword ptr [eax*4 + 0x1000ee0c]; 表体 0x1000ee0c..0x1000ee2f = 9 x 4 字节
 *   目标桩: 0x1000edf7(ret 0) / 0x1000edfa(ret 1) / 0x1000ee00(ret 2) / 0x1000ee06(ret 3)
 *     idx = |slot|-1 :  0  1  2  3  4  5  6  7  8
 *     槽             :  0  1  2  3  3  3  3  0  1
 *   raw slot -> 槽:  3->2  4/5/6->3  8->0   0xfd->2  0xfc/0xfb/0xfa->3  0xf8->0
 *   => 只取决于 |slot|; 符号仅决定方向门 (负 => C0.dir==+1; 正 => C0.dir==-1)
 *   => C2 的 4 并发槽: 槽2="+-3" / 槽3="+-4,+-5,+-6" / 槽0="+-8" / 槽1=仅镜像分支
 *   (第一批列出的 {3,4,5,6,0xfa,0xfb,0xfc,0xfd} 之外, 本批补齐 {8, 0xf8})
 *
 * 12.3 C2 记录布局 (stride 0x18) [A]
 *   +0x00     i32  C0 分型 id (dir==-1 取 idxA(+0x11), 否则 idxB(+0x15))
 *   +0x04+s*4 ptr  段记录指针 rec (s = 归一槽 0..3)
 *   +0x14+s   i8   该槽的 slot 原始字节 (不归一)
 *   调用者: 0x1001126a(seg_finalize) / 0x1001146b / 0x10011484 / 0x100114e7(seg_advance)
 */

/* ============================================================================
 * 13. 第四批: 消费侧产线闭环 (docs/34 T2)
 * ==========================================================================*/
/*
 * 13.1 ★ 勘误: 0x100110a0 / 0x10011010 = C0.p3 区间求和器 (不是「插值/价查询」)
 *   double sum_p3     (Engine* eng, int b /*ebx*/, int a /*eax*/)   // 0x10011010, ret 4
 *   { ST0 = SUM_{i=a..b} C0[i].p3 /*+0x29*/; }                      // 无方向过滤
 *   double sum_p3_dir (Engine* eng, int b, int a /*edx*/, int dir /*edi*/)  // 0x100110a0, ret 8
 *   { ST0 = SUM_{i=a..b, C0[i].dir(+0x00)==dir} C0[i].p3; }
 *   结果留在 ST(0)；循环单位 = C0 下标 (= bar 下标)。
 *   直证用途: 0x10011360 @10011442 (call sum_p3 后 fcomp [edi+0x29]);
 *             0x10011170 @100112ff/@10011314 (连调 sum_p3_dir x2 后 fcompp)。
 *   => p3 = 可加每 bar 标量, SUM = 区间累计量(面积/量) [B]; 两支服务段择取评分 [A 结构]
 *
 * 13.2 V 向量 (engine[+0x5c]/[+0x60]) 产线 [A]
 *   engine vt[+0x10] = 0x1000ed20 (dispatch, ret 4, arg = mode)
 *     mode 0        -> 返 -1
 *     mode 1        -> 0x10011500   (dir +1 族, span 门 >= 8)
 *     mode 2        -> 0x10011660   (dir +1 族, span 门 >= 6)
 *     mode 0x65(101)-> 0x100117b0   (dir -1 族, span 门 >= 6)
 *     入口前: 0x10012550 对 V 紧致化 (回写 engine[+0x60])
 *
 *   三支同构:
 *     循环 i (C2 += 0x18, C0 += 0x31):
 *       c2 = C2[i];
 *       if ((s8)c2.slotB[0](+0x14) < 0)      ptr = c2.ptr[0](+4);
 *       else if ((s8)c2.slotB[3](+0x17) < 0) ptr = c2.ptr[3](+0x10);
 *       else continue;
 *       if (!ptr || ptr->dir(+0x10) != DIR) continue;
 *       span = ptr->endBar(+0xc) - ptr->startBar(+8) + 1;
 *       if (!(span >= SPAN_MIN)) continue;              // mode1:8; mode2/0x65:6
 *       if (i - ptr->startBar + 1 != 8) continue;
 *       if (C0[i].dir != DIR) continue;
 *       if (C0[startBar..i-1].p2 关系门) continue;       // 逐 bar fcomp
 *       idx = ptr->idxB(+0x15);  if (idx > limit) continue;
 *       for (; idx <= limit; idx++) if (price[idx] 满足 fcomp) break;   // price = engine[+8]
 *       组装 Rec1D; V.push_back(0x10011a70, &sub);
 *
 * 13.3 ★★ V 0x1d 子记录布局 (生产者写点 + SelPri 读点 双向确证) [A]
 *   +0x00  u8   标签 (生产者未显式写)
 *   +0x01  i32  barIdx      (prod: 10011619 [esp+0x19]; Sel: 10005b20 [eax-0x1d] / 10005b86 [eax])
 *   +0x05  f64  v1          (prod: 1001160e [esp+0x1d]; Sel: 10005b2f [eax-0x19] / 10005b92 [eax+4])
 *   +0x0d  f64  v2          (prod: 1001161d [esp+0x25]; Sel 不读)
 *   +0x15  f64  v3 = 0.0    (prod: 10011627 [esp+0x2d]; Sel 不读)
 *   每 0x74 组 = 4 x 0x1d 子记录; 组内偏移 base + {0,1,2,3}*0x1d
 *   0x10011a70 = 单子记录 push_back (容量按 0x74 组计量, magic 0x8d3dcb09)
 *   0x10012550 = 0x1d 块搬移/紧致化 (n=(last-first)/0x74; dst = arg + n*0x1d)
 *   勘误: docs/32 记 {i32 barIdx@+0x00, f64 价@+0x04} 为错位 1 字节
 *
 * 13.4 SelPri 消费路径 (0x10005a50, ret 0x10) [A] —— 校正后
 *   memset(out, 0, n*8);
 *   V = engine[+0x5c]..engine[+0x60]; cnt = (end-beg)/0x74;
 *   for (e=0; e<cnt; e++)
 *     for (j=0; j<4; j++) {
 *        sub = V.beg + e*0x74 + j*0x1d;
 *        idx = *(i32*)(sub+0x01);  val = *(f64*)(sub+0x05);
 *        if (0 <= idx && idx <= n) out[idx] = val;     // 上界 = arg0 = n
 *     }
 *   闭环: 构建链 -> C1 段 -> C2 并发槽(0x1000ee30) -> vt[+0x10] dispatch(mode 1/2/0x65)
 *         -> 0x10011500/60/b0 -> 0x10011a70 push -> V -> SelPri/SelSlPri/SelSpPri -> out[barIdx]
 */

/* ============================================================================
 * 14. 第四批: 四支收尾辅助 (docs/34 T3)
 * ==========================================================================*/
/*
 * 14.1 0x1000fc10 — seg_overlap_check (ret 无栈参; eax=engine, ebx=rec; 返回 al=bool) [A]
 *   prevIdx = 0x1000f200(engine, rec->dir /*[+0x10]*/);
 *   if (prevIdx < 0) return 0;
 *   prev = &C1[prevIdx];
 *   if (prev->dir != rec->dir) return 0;
 *   if (rec->dir == -1) return (prev->GG(+0x31) >= rec->DD(+0x3d));
 *   else                return (prev->DD(+0x3d) <= rec->GG(+0x31));
 *   => 语义: 前一同向有效段 [DD,GG] 与当前段 [DD,GG] 相交谓词。 x87 2 条。
 *
 * 14.2 0x1000fdf0 — find_prev_valid (ret 无栈参; ebx=rec, edi=engine; 返回 bar 下标) [A]
 *   if (rec->self(+4) - 1 < 0) return rec->startBar(+8) + 2;
 *   for (k = rec->self - 1; k >= 0; k--) {
 *      seg = &C1[k];                       // stride 0x5d
 *      if (seg->dir != rec->dir) continue;
 *      if (!(seg->flags(+0x14) & 1)) continue;
 *      return rec->startBar;
 *   }
 *   return rec->startBar + 2;
 *
 * 14.3 0x1000fe50 — scan_candidate (ret 0xc; 含 SEH 帧 + 局部 vector stride 0xc) [A 结构/B 语义]
 *   若 rec->dir == -1 -> 0x1000f490(&vec, engine, arg); 否则 0x1000f5b0(...);
 *   cnt = (vec.end - vec.beg) / 0xc;
 *   for (e=0; e<cnt; e++) {
 *      idx = vec[e]->[+8];
 *      if (idx + 4 >= C0.count) break;
 *      a = &C0[idx+1];  b = &C0[idx+2];
 *      if (a->dir == -1) { if (!(a->p2 <= b->p1)) { free vec(0x10013f00); return idx; } }
 *      else              { if (!(a->p1 >= b->p2)) { free vec; return idx; } }
 *   }
 *   => 门 = 相邻 C0 记录价格区间相交 (dir 分派)。 x87 2 条。
 *
 * 14.4 ★ 0x10010d60 — split_rebuild (ret 4; ecx=engine(edi), ebx=rec) [A]
 *   span_m1 = rec->endBar(+0xc) - rec->startBar(+8);   e = span_m1 + 1; if (span<=3) e = span;
 *   if (e < engine[+0x1c] /*=9 段长上限*/) return -1;
 *   r1 = 0x1000fdf0(rec, engine);
 *   c  = 0x1000fe50(rec, engine, r1, rec->endBar);
 *   if (c + 1 < rec->endBar - 3) return -1;
 *   if (c + 4 >= engine[+0x2c])  return -1;
 *   p  = &C0[c];
 *   ... dir 分派 8 条 fcomp (p 与 C0[c+-k] 之 p1/p2) ...
 *   c2 = 0x1000fe50(rec, engine, r1, c - 1);
 *   if (c2 < 0) return -1;
 *   rec->flags = (rec->flags & 0xFE) | 2;              // ★ 置 bit1「已收尾」 (10010e7a)
 *   0x1000f0e0(engine, rec);                           // ★ 段入册 (C1.count++)
 *   0x1000f070(rec->startBar, rec->endBar);
 *   a = 0x1000f680(engine, rec->startBar, c2 + 1, rec);      // ★ 递归 buildSegment #1
 *   b = 0x1000f680(engine, newIdx, engine[+0x2c], rec);      // ★ 递归 buildSegment #2
 *   return max(a, b);
 *   => 语义: 收尾(flags|=2 + 入册) + 段分裂 + 递归再建两子段。
 *   => ★ 本支是 0x1000f680 「内层递归」的真实发起者 (docs/33 勘误②的落点)。
 *
 * 14.5 接线
 *   0x1000f200 前段查找器 <- 14.1     0x1000f0e0 段入册器 <- 14.4
 *   0x1000f680 buildSegment <- 14.4 (递归 x2)        engine[+0x1c]=9 段长上限 <- 14.4
 */

/* =====================================================================
 * 第五批 (docs/35) — 招牌成员消费链 + mode 选用者
 *   15. 包装层骨架 (TAFLib) + C3 真实字段布局
 *   16. NChZsFj  0x10005020  (C3 端点直译)
 *   17. NChZsDg  0x10005160  (段内极值点)
 *   18. NChZsHLTurn 0x10005480 (段起点/转折点)
 *   19. 共用收尾补点器 0x100069b0 = ±2 唯一来源
 *   20. mode 1/2/0x66 生产者 + 可达性判定 (vt[+0x10] 无调用者)
 * ===================================================================== */

/*
 * 15. 包装层 (TAFLib) 与 C3 真实布局
 *
 * 15.1 三个导出包装完全同构 (ret 0xc: n, out, arg3)
 *   NChZsFj=0x10013660  NChZsDg=0x100136f0  NChZsHLTurn=0x10013780
 *
 *   char wrapper(int n, double *out, int a3) {          // ecx = ch_api*
 *     int code = (this[+0xb8] > 1) ? 0xEA63 : 0xEA61;   // ★ 层计数器
 *     if (!Authorize(0x10014e60, code)) {               // ★ 未授权
 *       memset(out, 0, n * 8);                          // ★ 清零(不是报错!)
 *       return 0;
 *     }
 *     int buf[6]; Fetch6Buffers(0x10006cc0)(this, buf);
 *     void **api = this[+0xbc];
 *     fn = api->vt[+0x94 | +0x98 | +0x9c];              // ch_api 虚表 0x10015214
 *     fn(n, out, buf, a3);
 *     return 1;
 *   }
 *
 * 15.2 ch_api 虚表 0x10015214 实测 (相邻槽)
 *   +0x80 0x100046c0   +0x84 0x100046e0   +0x88 0x10004700   +0x8c 0x10004720
 *   +0x90 0x100048a0   +0x94 0x10005020(Fj)  +0x98 0x10005160(Dg)  +0x9c 0x10005480(HLTurn)
 *   +0xa0 0x10005810   +0xa4 0x100058f0   +0xa8 0x10005a50   +0xac 0x10005bb0   +0xb0 0x10005d10
 *
 * 15.3 ★ C3 记录 (stride 0x1d) 真实布局 —— 三支交叉实证，取代 docs/34 五节旧记
 *   +0x00 i32  dir        ±1 方向                  (Fj fild [e]; Dg/HLTurn fild [ecx-5])
 *   +0x04 u8   valid      bit0 = 有效              (三支 test byte [e+4],1)
 *   +0x05 i32  c0Index    笔序号 (C0 下标)          (Fj 送 0x100069b0 起点; Dg imul 0x31 索引 C0)
 *   +0x09 i32  barIdx     bar 下标 (out[]/价格数组) (三支 [e+9] 做 *8)
 *   +0x0d f64  hi         高价 = C0.p1 (+0x19)      (0x1000ebe0 后处理)
 *   +0x15 f64  lo         低价 = C0.p2 (+0x21)
 *   注: C0 侧 p1(+0x19)=高、p2(+0x21)=低 —— 由 GG/DD 更新器 0x1000edb0/edd0 判据确权。
 *   注: engine[+8] = 高价数组、engine[+0xc] = 低价数组 (本批确权)。
 */

/*
 * 16. NChZsFj  0x10005020  (384 行, ret 0x10) — C3 端点直译器, 0 个 x87 比较
 *
 *   int NChZsFj(int n, double *out, void *buf, int a3) {
 *     memset(out, 0, n * 8);                              // 0x1001494c
 *     Eng *e = this[+0x18];
 *     if (!e[+0x20] || !e[+0x4c] || !e[+0x2c]) return -1;  // C0.base / C3.base / C0.count
 *     int last = -1, i = 0;
 *     if (e[+0x2c] >= 4) {                                 // 0x10005072
 *       C3Rec *p = (C3Rec *)e[+0x4c];
 *       for (; i < e[+0x2c] - 3; i += 4) {                 // 4x 展开, 指针 +0x74
 *         for (s = 0; s < 4; s++) {
 *           C3Rec *r = p + (i + s);
 *           if ((r->valid & 1) && r->barIdx >= 0 && r->barIdx < n) {
 *             out[r->barIdx] = (double)r->dir;             // ★ fild dword[r] -> fstp qword
 *             last = i + s;
 *           }
 *         }
 *       }
 *     }
 *     for (; i < e[+0x2c]; i++) { /* 尾循环 0x100050f7: 同一逻辑 */ }
 *     if (last > 0 && last < n - 1)                        // 0x10005126
 *       tail(out, e[+0x20], e[+0x2c], C3[last].dir, C3[last].c0Index + 3);  // 0x100069b0, eax=起点
 *     return 0;
 *   }
 *   => 语义: 逐条把 C3 的两个端点按方向打 ±1; 末尾用补点器补一个 ±2。
 *   => 上界用 C0.count、步进用 C3 的 0x1d ⇒ 隐含 C3.count == C0.count。
 */

/*
 * 17. NChZsDg  0x10005160  (260 行, ret 0x10) — 段内极值点 (顶/底)
 *
 *   int NChZsDg(int n, double *out, void *buf, int a3) {
 *     memset(out, 0, n * 8);
 *     Eng *e = this[+0x18];
 *     double *hi = e[+8], *lo = e[+0xc];                  // ★ [esp+0x20]/[esp+0x10] (+4 换算)
 *     if (!e[+0x2c] || !e[+0x4c] || !e[+0x2c]) return -1;
 *     Vec0x1d tmp; tmp.resize(e[+0x2c]);                  // 0x10006b60: imul esi,0x1d
 *     m = 0;
 *     for (i = 0; i < e[+0x2c]; i++)                      // 0x100051ef: 过滤复制 29 字节
 *       if ((C3[i].valid & 1) && C3[i].barIdx >= 0) tmp[m++] = C3[i];
 *     if (m <= 0) goto done;
 *     lastBest = -1;
 *     for (k = 0; k < m; k++) {
 *       cur = tmp[k];
 *       acc = (cur.dir == 1) ? hi[cur.barIdx] : lo[cur.barIdx];
 *       best = cur.c0Index;                             // [B] 下标种类混用隐患
 *       j0 = (k == 0) ? 0 : tmp[k-1].c0Index + 3;       // 前段 0x1000526f
 *       for (j = j0; j <= cur.c0Index; j++) {           // C0 stride 0x31
 *         loIdx = (C0[j].dir == -1) ? C0[j].idxB : C0[j].idxA;
 *         hiIdx = (C0[j].dir == -1) ? C0[j].idxA : C0[j].idxB;
 *         if (loIdx <= lastBest) continue;
 *         for (b = loIdx; b <= hiIdx && b <= n - 1; b++) {
 *           if (cur.dir == 1) { if (acc <= hi[b]) { acc = hi[b]; best = b; } }   // max(高)
 *           else              { if (acc >  lo[b]) { acc = lo[b]; best = b; } }   // min(低)
 *         }
 *       }
 *       // 后段 0x10005332: cur.c0Index+3 .. tmp[k+1].c0Index-3, 同一逻辑
 *       out[best] = (double)cur.dir;                    // 0x100053f9
 *     }
 *     if (lastBest > 0 && lastBest < n - 1)
 *       tail(out, e[+0x20], e[+0x2c], tmp[lastBest].dir, lastBest + 3);
 *   done: free(tmp); return 0;
 *   }
 *   => 语义: 升笔取段内最高高价、降笔取段内最低低价 ⇒ out[极值 bar] = ±1。
 *   => x87 4 个比较站点: 0x100052cf(高,max) / 0x100052e0(低,min) / 0x100053a2 / 0x100053b3。
 */

/*
 * 18. NChZsHLTurn  0x10005480  (318 行, ret 0x10) — 段起点 / 转折点
 *
 *   int NChZsHLTurn(int n, double *out, void *buf, int a3) {
 *     memset(out, 0, n * 8);
 *     Eng *e = this[+0x18];
 *     double *hi = e[+8], *lo = e[+0xc];                  // [esp+0x30]/[esp+0x34]
 *     if (!e[+0x20] || !e[+0x4c] || !e[+0x2c]) return -1;
 *     Vec0x1d tmp; tmp.resize(e[+0x2c]);                  // 过滤复制同 Dg
 *     if (m <= 0) goto done;
 *     accMin = +DBL_MAX; accMax = -DBL_MAX;               // 0x100154c0 / 0x100154c8, fld st(1) x2
 *     best = -1;
 *     for (k = 0; k < m; k++) {
 *       cur = tmp[k];
 *       if (k == 0) out[cur.barIdx] = (double)cur.dir;    // ★ 首点直打 0x10005562
 *       for (j = k+1; j < m && tmp[j].dir != cur.dir; j++) ;   // 找下一个同向记录
 *       if (j >= m) { /* 尾处理 0x10005599 */ continue; }
 *       idx0 = max(cur.barIdx, best);
 *       if (n - idx0 < 4) { /* 短路径 0x10005759: 单步扫到 n, 无 limit */ }
 *       else {
 *         limit = tmp[j].barIdx;                          // 0x100055fe
 *         for (b = idx0 + 2; b < limit; b += 4) {         // 4x 展开, 4 个块
 *           if (cur.dir == 1) { if (accMin > lo[b]) accMin = lo[b], hit = b; }      // min(低)
 *           else              { if (accMax <= hi[b]) accMax = hi[b], hit = b; }     // max(高)
 *         }
 *       }
 *       if (hit >= 0) {                                   // 0x100057c5
 *         out[hit] = (cur.dir == 1) ? +1.0 : -1.0;        // setne + lea eax,[eax*2-1]
 *         best = hit;
 *       }
 *     }
 *   done: free(tmp); return 0;
 *   }
 *   => 语义: 升笔取段内最低低价(起涨低点)、降笔取段内最高高价(起跌高点) ⇒ 转折点标注。
 *   => 与 Dg 方向相反; 10 个比较站点 (4 个展开块 + 尾块)。
 */

/*
 * 19. 共用收尾补点器 0x100069b0 (ret 0x10, ★ 第 5 参走 eax 寄存器)
 *   void tail(double *out, C0Rec *C0, int end, int dir) {   // eax = start
 *     int best = -1;
 *     if (dir == 1) {
 *       double mx = DBL_MAX;                        // 0x100154c0
 *       for (j = start; j < end; j++)               // 4x 展开, stride 0x31
 *         if (C0[j].p2 > mx) { mx = C0[j].p2; best = j; }        // p2 = 低
 *       if (best >= 0) out[C0[best].idxB] = -2.0;   // 0x100154e0
 *     } else {
 *       double mn = -DBL_MAX;                       // 0x100154c8
 *       for (j = start; j < end; j++)
 *         if (C0[j].p1 < mn) { mn = C0[j].p1; best = j; }        // p1 = 高
 *       if (best >= 0) out[C0[best].idxA] = +2.0;   // 0x100154b8
 *     }
 *   }
 *   => ★ ±2 值域的唯一来源; 与 C0[+0x0c]「分型标记 = 1 当值 ∈ {−2,+2}」互为印证。
 *   => xref 仅 2 处: 0x10005148(Fj) 0x10005448(Dg); HLTurn 不调用。
 */

/*
 * 20. mode 1/2/0x66 生产者 与 可达性判定
 *
 * 20.1 dispatch 0x1000ed20 (vt[+0x10], ret 4, arg0 = u8 mode, ecx = engine)
 *   if (mode == 0) return -1;
 *   0x10012550(&engine[+0x5c]);                       // V 紧致化
 *   movzx eax,[ebp+8]; sub 1 -> je 0x10011500          // mode 1
 *                      sub 1 -> je 0x10011660          // mode 2
 *                      sub 0x64 -> jne fail            // ★ mode = 0x66 (前批记 0x65, 勘误)
 *                      call 0x100117b0
 *
 * 20.2 三支 producer 对照 (arg0 = engine; 唯一出口 0x10011a70 push_back)
 *   | 项 | mode 1 | mode 2 | mode 0x66 |
 *   | C0 门 | count<=1 退出 | count<=2 退出 | 同 m2 |
 *   | C2 子对象 | p[0x10]==+1 | +1 | -1 |
 *   | span 门 | >=8 | >=6 | 同 m2 |
 *   | 相位门 | i-lo+1==8 | i-lo==8 | 同 m2 |
 *   | 单调门 | C0[i+1].p2 > C0[lo..i].p2 | C0[i-1].p2 < C0[i].p2 | C0[i-1].p1 > C0[i].p1 |
 *   | 起点 | C0[i+1].idxB | C0[i].idxB | C0[i].idxA |
 *   | 上界 | C0[i+2].idxA 否则 engine[+0x14]-1 | 同 | idxB 版 |
 *   | 数组 | engine[+8] | engine[+8] | engine[+0xc] |
 *   | 命中 | price < C0[i].p2 | price < C0[i-1].p2 | price > C0[i-1].p1 |
 *   | V.v1/v2 | C0[i].p2 / C0[i+1].p2 | C0[i].p2 / C0[i-1].p2 | C0[i].p1 / C0[i-1].p1 |
 *   | V.v3 | 0.0 | 0.0 | 0.0 |
 *   V 记录 {u8 tag(未写), i32 bar@+1, f64 v1@+5, f64 v2@+0xd, f64 v3@+0x15} = 0x1d
 *   push_back 0x10011a70: 向量 = {begin engine[+0x5c], end engine[+0x60], cap engine[+0x64]},
 *                         元素 0x1d (魔数 0x8d3dcb09 = 2^36/0x1d)。
 *
 * 20.3 ★ 可达性: 无选用者
 *   chlib .text 100% 覆盖: call 0x1000ed20 = 0; call/jmp [reg+0x10] = 0; 字节级 FF /2,/4 disp8=0x10 = 0
 *   0x1000ed20 的唯一引用 = .rdata+0x4ac (虚表槽 0x100154ac)
 *   TAFLib .text 100% 覆盖: call/jmp [reg+0x10] = 0; 全部 mem-call 指向导入表 0x1006f0xx
 *   => dispatch + 三支 producer + push_back 为不可达子图 (待 frida 终判, [C])
 *
 * 20.4 limit 源
 *   engine[+0x14] = n (setter 0x1000e0b0 第 5 槽) -> limit = engine[+0x14]-1 兜底
 *   engine[+0x18] 三支 producer 内 0 次读取 (派单假设勘误)
 */

/* ============================================================================
 * 21. NChZsL2M — 0x100048a0 (695 insns, ret 0x10)  [第六批 docs/36]
 *
 * 证据: chlib_100048a0.txt / l2m_cfg.txt (支配树, cfg_blocks.py) /
 *       l2m_x87sim.txt / l2m_modes.txt / taf_100135e0.txt
 * 包装: TAFLib 0x100135e0 (code 0xEA61) -> ch_api vt[+0x90]
 *
 * 21.1 外形 [A]
 *   int L2M(this /*ecx*/, int n, double* out, void* buf6, void* P)   ret 0x10
 *   P   = (int)(*(double**)P)[0]                     ; 0x100048b0 fld [[a4]] + _ftol2
 *   memset(out, 0, n*8)                              ; 0x100048d6
 *   switch (P) { 1,2,3,4 } else return 0
 *   返回: 0 成功 / 0 当 P 越界或 C1.count==0 / -1 当 7 重非空门失败
 *
 * 21.2 七重非空门 [A]  (任一为 0 -> 0x1000500f: or eax,-1)
 *   buf6[+0xc] | C0.base | C0.count | C1.base | C1.count | C2.base | (C0.base, C1.count 复判)
 *   ★ 唯一失败口; 与 Fj/Dg/HLTurn 的 3 重门相比, L2M 同时依赖 C0/C1/C2
 *
 * 21.3 局部槽 (★ 栈槽 +4: 基线 = add esp,0xc 之后)
 *   [esp+0x14]=C0.base (mode1/2 内复用为 C1 循环计数)  [esp+0x10]=C0.count
 *   [esp+0x1c]=C2.base                                [esp+0x18]=mode3/4 尾部游标
 *
 * 21.4 mode 1 / mode 2 —— C1 段 -> C0 笔 隔笔扫描 [A]
 */
int L2M(int n, double* out, void* buf6, void* Pv)
{
    int P = (int)(*(double**)Pv)[0];
    memset(out, 0, n * 8);
    engine_t* e = this->engine;                       /* this[+0x18] */
    C0_t* C0 = e->C0_base;  int c0n = e->C0_count;
    C1_t* C1 = e->C1_base;  int c1n = e->C1_count;
    C2_t* C2 = e->C2_base;
    if (!buf6 || (int*)buf6[3] == 0 || !C0 || !c0n || !C1 || !c1n || !C2) return -1;

    if (P == 1 || P == 2) {
        int dirWant = (P == 1) ? -1 : +1;
        for (int r = 0; r < c1n; ++r) {               /* 0x1000494a / 0x100049e5 */
            C1_t* rec = &C1[r];
            if (!(rec->flags /*+0x14*/ & 1)) continue;
            int S = rec->startBar /*+0x08*/, E = rec->endBar /*+0x0c*/;
            if (E - S + 1 <= 3) continue;             /* span >= 4 */
            if (rec->dir /*+0x10*/ != dirWant) continue;
            if (S + 3 > E) continue;                  /* 冗余 (span>=4 已蕴含) */
            for (int i = S + 3; i <= E; i += 2) {     /* 0x1000497c / 0x10004a17 */
                if (C0[i].mark /*+0x0c*/ & 1) continue;
                if (P == 1) {
                    if (!(rec->ZG /*+0x19*/ > C0[i].p2 /*+0x21*/)) continue;  /* 0x10004985 */
                    if (!(C0[S].p2          > C0[i].p2))          continue;  /* 0x10004997 */
                    out[C0[i].idxB /*+0x15*/] = 1.0;                          /* 0x100049a3 */
                } else {
                    if (!(rec->ZD /*+0x25*/ < C0[i].p1 /*+0x19*/)) continue;  /* 0x10004a20 */
                    if (!(C0[S].p1          < C0[i].p1))          continue;  /* 0x10004a32 */
                    out[C0[i].idxA /*+0x11*/] = 1.0;                          /* 0x10004a3e */
                }
            }
        }
        return 0;                                     /* 0x100049bd / 0x10004a58 */
    }

    /* 21.5 mode 3 / mode 4 —— C2 槽状态机 (结构 [A] / 语义 [B])
     *   4 路展开: trip = ((n-5)>>2)+1, 标量尾起点 trip*4+1, 尾循环 k < c0n
     *   C2 与 C0 同下标同步 (esi += 0x60 = 4*0x18, ecx += 0xc4 = 4*0x31)
     *   | mode | SEED slotB[1] | DIRGATE | 参考 | 写点 |
     *   |  3   | -2 (0xFE)     |  +1     | k-1  | idxB |
     *   |  4   | +2            |  -1     | k-1  | idxB |
     *   x87: 栈深 4 (fldz, fld st(0), fld st(1), fld1), 退出 4 次 fstp
     *        单元素窗口净栈恒等; 写入值 = 常驻 fld1 = 1.0 [B]
     */
    if (P == 3 || P == 4) {
        int seed    = (P == 3) ? -2 : +2;
        int dirGate = (P == 3) ? +1 : -1;
        int haveRef = 0;
        double refLo = 0, refHi = 0;                  /* 对应 x87 常驻槽 */
        for (int k = 1; k <= c0n - 1; ++k) {          /* 0x10004ab0 / 0x10004d89 */
            if (C0[k].mark & 1) continue;
            signed char s2 = C2[k].slotB[2] /*+0x16*/;
            if (s2 == -3 || s2 == +3) {               /* 0xFD / 0x03 -> 结构边界 */
                haveRef = 0;
                if (C2[k].slotB[1] /*+0x15*/ == seed) {
                    haveRef = 1; refLo = C0[k-1].p2; refHi = C0[k-1].p1;
                }
                continue;
            }
            if (haveRef && C0[k].dir == dirGate &&
                refLo < C0[k].p2 && refHi > C0[k].p1)  /* 前一笔完全包含当前笔 */
                out[C0[k].idxB] = 1.0;                 /* 0x10004bbc 等 4 写点 + 尾 0x10004d0b */
            if (C2[k].slotB[1] == seed) {              /* 0x10004ad1 公共尾: 打锚 */
                haveRef = 1; refLo = C0[k-1].p2; refHi = C0[k-1].p1;
            }
        }
        return 0;                                     /* 0x10004d3f / 0x10004fdb */
    }
    return 0;                                         /* 0x10004fd3: P 越界 */
}

/* ============================================================================
 * 22. 遗留基元 6 支  [第六批 docs/36 §六]
 *
 * 22.1 0x1000f010  C3 单条写入器  [A]
 *   void c3_write(engine_t* e, int i)      ; e=esi, i=edx
 *   if (i >= e->C0_count) return;
 *   C3 = e->C3_base + i*0x1d;  C0 = e->C0_base + i*0x31;
 *   C3->valid(+4)=1; C3->c0Index(+5)=i;
 *   if (C0->dir==-1) { C3->dir(+0)=+1; C3->barIdx(+9)=C0->idxA(+0x11); }
 *   else             { C3->dir(+0)=-1; C3->barIdx(+9)=C0->idxB(+0x15); }
 *   C3->hi(+0xd)=C0->p1(+0x19); C3->lo(+0x15)=C0->p2(+0x21);
 *   ★ 与第五批 C3 布局逐字段吻合, 且给出 dir = -C0.dir 的直证
 *
 * 22.2 0x1000f070  C3 区间打标器  [A]
 *   for (i = start; i <= end && i < e->C0_count; ++i)
 *       C3[i].valid = (C3[i].valid & 0xFE) | 2;       ; bit1 = 已收尾
 *
 * 22.3 0x1000f0b0  C3 反向查有效  [A]
 *   C3_t* f(engine_t* e, int i) { for (; i >= 0; --i) if (C3[i].valid & 1) return &C3[i]; return 0; }
 *
 * 22.4 0x1000f490 / 0x1000f5b0  候选点收集器双胞胎  [A]
 *   void collect(engine_t* e, int start, int end, vector<Rec12>* v)
 *   {   ; e=ecx, start=eax, end=[esp+0x24]; v = 调用方栈上对象 (v[+4]=begin, v[+8]=end)
 *       vector_init(0x10011da0, v);
 *       for (i = start; i <= end && i < e->C0_count; i += 2) {
 *           Rec12 r; r.price = (A) ? C0[i].p1(+0x19) : C0[i].p2(+0x21);
 *                    r.pen   = i;                       // {f64 @+0, i32 @+8} = 12 B
 *           push_back(0x10011ba0, v, &r);
 *       }
 *       std::reverse(v->begin, v->end);                  // 0x1000f570..f599, 步长 0xc
 *   }
 *   A: 0x1000f490 取 p1 (高) ; B: 0x1000f5b0 取 p2 (低)
 *   选择者: 0x1000fe96 / 0x100107ac / 0x10010974  均为 if (rec.dir == -1) A else B
 *           => 下跌段取高点序列, 其余取低点序列
 *
 * 22.5 0x10013f00  MSVC 局部展开 / EH 辅助  [B] (非业务)
 *   funclet 0x10014870 + 0x10014440; 两分支均 call 0x10013f00 自递归做链式展开
 * ==========================================================================*/
