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
 * 批次: 第一批 (docs/31, 2026-10-17)
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
 *  [B] 段记录绝对偏移 (rec = segs + i*0x5d, 循环 ptr = rec+0x55)
 *  [C] 段 rec+0x00..0x13 的 20B 头部语义 (疑嵌套子结构)
 *  [C] 引擎对象 this[+0x18] 的类定义与构造点 (未查 ctor)
 *  [C] this[+0x18]->vt[+4] / vt[+0xc] / vt[+8] 的实现 (引擎真身, 第二批)
 *  [C] "G/D"=ZG/ZD、"Bs" 命名 (字面 3/12); this[+0xb8] 层计数器语义
 *  [C] helper 0x1000e990 / 0x1000eb80 / 0x10006700 用途
 *  [C] 本批未做动态验证 (frida 预备包待用户在场)
 */
