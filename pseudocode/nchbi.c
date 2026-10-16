/* ============================================================================
 * nchbi.c — 融立德「NChBi（缠论笔·新版）」逆向伪码（骨架）
 * ----------------------------------------------------------------------------
 * 来源: TAFLib.dll (32-bit, PE 链接时间 2023-03-15) + chlib.dll (106 KB, 同日)
 * 定位: 导出 ?NChBi @0x10012a50 (TAFLib)  ->  虚调用 chlib!ch::ch_api::vt[+0x34]
 * 证据: tools/re-inventory/nchbi/
 *         nchbi_entry.txt                   (TAFLib 包装层 0x10012a50-0x10012c38)
 *         chlib_vtable_and_factory.txt      (chlib CreateLib/ctor/ch_api 虚表)
 *         chlib_worker_10002340.txt         (chlib 工作函数 377 insn)
 *         cond_chlib_10002340.txt           (x87_sim.py 条件表, 10 条)
 *         reuse_probe.txt                   (复用判定探针)
 *         nchbi1_wip.md                     (本批工作稿)
 * 批次: NChBi 第一批 (docs/25, 2026-10-17)
 * 置信度: [A]=实测已证(字节级) [B]=高(多路交叉) [C]=待仲裁/推断
 * ----------------------------------------------------------------------------
 * 整体链路:
 *   公式 NCHBI(count, out[], P)
 *     -> NChBi @0x10012a50 (TAFLib 包装层, __thiscall, ret 0xc)
 *          P = (int) *(double*) *(double**) param        // 0x1006bc70 = _ftol2
 *          if (P == 0 || P == 51) {                       // ★ 与 CHBI 不同: 多了 P==0
 *              if (!Authorize(0xEA62)) { memset(out, 0, count*8); return 0; }
 *          }
 *          evt = new(0x30); ctor 0x10001cc0(evt);        // 与 CHBI 同一事件对象 ctor
 *          evt->str = this[+0xC] + 4;                    // std::string::operator=
 *          shared_ptr h = 0x1001c110(evt);               // ★ 与 CHBI 同一 shared_ptr 桩
 *          DmcApi::PushEvent(h);                         // RDM_C! 图表事件推送
 *          ctx6 = { H, O, L, C, V, A } 缓冲指针;         // 0x10006cc0 -> RData!XTAData
 *          switch (P) {                                  // ★ P 短路表 (包装层)
 *            case 11: *P_out = 2.0; return 1;
 *            case 12: *P_out = 1.0; return 1;
 *            case 21: *P_out = 4.0; return 1;
 *            case 22: *P_out = 3.0; return 1;
 *            case 31: *P_out = 6.0; return 1;
 *            case 32: *P_out = 5.0; return 1;
 *            case 51: *P_out = 0.0; return 1;
 *          }
 *          ch_api = this[+0xBC];                         // chlib!CreateLib(ch_auth*)
 *          return ch_api->vt[+0x34](count, out, &ctx6, param);   // ★ 真工作函数
 *     -> chlib!0x10002340  (工作函数)  —— 见下
 * ==========================================================================*/

/* ---------------------------------------------------------------------------
 * 0. 关键地址速查
 * -------------------------------------------------------------------------*/
/*
 *  TAFLib.dll (ImageBase 0x10000000)
 *    0x10012a50  ?NChBi              包装层 (本批主角)
 *    0x10012c40  ?NChBiSta           槽 +0x38
 *    0x10012cb0  ?NChBiSta2          槽 +0x3c
 *    0x10012d20  ?NChBiZj            槽 +0x44
 *    0x10012e00  ?NChBiZjOrder       槽 +0x4c
 *    0x10012e70  ?NChBiFxNum         槽 +0x58
 *    0x10012f50  ?NChBiSpeed         槽 +0x60
 *    0x10001cc0  事件对象 ctor (与 CHBI 同)
 *    0x10001f6a  this[+0xBC] = ch_api*   (ctor 内)
 *    0x10006cc0  取 6 行情缓冲 (H/O/L/C/V/A)
 *    0x1001c110  boost::shared_ptr 构造桩 (与 CHBI 同)
 *    0x1001c940  shared_count ctor
 *    0x1006bc70  _ftol2  (double -> int)   ← 勘误: 非"P 转码器"
 *    0x10014e60  Authorize(this, code)
 *
 *  chlib.dll (ImageBase 0x10000000, 只导出 CreateLib/FreeLib)
 *    0x10001010  ?CreateLib@ch_api@ch@@SAPAV12@PAVch_auth@2@@Z
 *    0x100010d0  ch_api::ch_api(ch_auth*)   → [this] = vtable 0x10015214
 *    0x10015214  ch_api vtable (槽 +0x18..+0xC4 全部为缠论组实现)
 *    0x10002340  ★ NChBi 真工作函数 (vt[+0x34])
 *    0x10002770  NChBiSta 工作函数 (vt[+0x38])
 *    0x10006670  count 早退检查  [C]
 *    0x10009930  内部数据准备    [C]
 *    0x100148a0  chlib 自带 _ftol2
 *    0x1001494c  chlib 自带 memset
 *    0x100154c0  double +DBL_MAX   (argmin 种子)
 *    0x100154c8  double -DBL_MAX   (argmax 种子)
 */

/* ---------------------------------------------------------------------------
 * 1. 数据结构
 * -------------------------------------------------------------------------*/

/* ctx6: 由 TAFLib 0x10006cc0 填的 6 个行情缓冲指针 (RData.dll!XTAData::Get*Buffer)
 *        [A] IAT: 0x1006f254/258/250/240/280/2dc                              */
typedef struct Ctx6 {
    const double *high;     /* +0x00  GetHighBuffer()   */
    const double *open;     /* +0x04  GetOpenBuffer()   */
    const double *low;      /* +0x08  GetLowBuffer()    */
    const double *close;    /* +0x0c  GetCloseBuffer()  */
    const double *volume;   /* +0x10  GetVolumeBuffer() */
    const double *amount;   /* +0x14  GetAmountBuffer() */
} Ctx6;                                          /* [A] */

/* ch_auth: 授权回调对象 (TAFLib 侧实例在 .data 0x10083c58)，虚表槽 +0x04 = 复核 */
typedef struct ch_auth ch_auth;                  /* [C] 完整布局未解剖 */

/* ch_api: chlib.dll 的缠论库句柄，仅 0x24 字节
 *   ctor 0x100010d0: [0]=vtable, [4]=auth, [8..0x20]=0                        */
typedef struct ch_api {
    void    **vt;          /* +0x00  = 0x10015214                              */
    ch_auth  *auth;        /* +0x04  CreateLib 入参                            */
    void     *sub;         /* +0x08  ...                                       */
    void     *engine;      /* +0x10  子对象: 其 vt[+4]/vt[+0xc] 被工作函数调用  */
    char      _pad[0x24 - 0x14];
} ch_api;                                        /* [A(前 0x14)] */

/* 事件对象 (0x30B): 包装层创建、经 DmcApi::PushEvent 推送，不参与算法
 *   ctor 0x10001cc0; [+8]=1; [+0xc]=0; [+0x10]=1(byte); [+0x14]=std::string   */
typedef struct EvtObj {
    void        **vt;      /* +0x00 */
    int           f08;     /* +0x08 = 1      */
    int           f0c;     /* +0x0c = 0      */
    unsigned char f10;     /* +0x10 = 1      */
    char          _pad11[3];
    void         *str;     /* +0x14  std::string (自 this[+0xC]+4 赋值)         */
    char          _pad[0x30 - 0x18];
} EvtObj;                                        /* [A] */

/* ---------------------------------------------------------------------------
 * 2. TAFLib 包装层  ?NChBi @0x10012a50
 * -------------------------------------------------------------------------*/

/* [A] 逐句对应 tools/re-inventory/nchbi/nchbi_entry.txt */
int __thiscall NChBi(void *this_, int count, double *out, double **param)
{
    int mode = (int)*(*param);                   /* 0x10012a87 fld; 0x1006bc70 _ftol2 */

    /* --- 授权门: P == 0 或 P == 51 (CHBI 只有 P == 51) [A] --- */
    if (mode == 0 || mode == 51) {               /* 0x10012a90 test/je; a94 cmp/jne */
        if (!Authorize(this_, 0xEA62)) {         /* 0x10012a99 push 0xea62; a a0 call */
            memset(out, 0, (size_t)count * 8);   /* 0x10012ab9 call 0x1006bd22 */
            return 0;                            /* 0x10012ac2 xor al,al */
        }
    }

    /* --- 事件对象 (与 CHBI 逐句同构) [A] --- */
    EvtObj *evt = (EvtObj *)operator_new(0x30);  /* 0x10012ad9 push 0x30; 0x1006b32c */
    if (evt) {
        evt = ctor_10001cc0(evt);                /* 0x10012af4 call 0x10001cc0 */
        evt->f08 = 1;                            /* 0x10012b0e */
        evt->f0c = 0;                            /* 0x10012b15 */
        std_string_assign(&evt->str, (char *)this_ + 0xc + 4);  /* 0x10012b26 [0x1006f07c] */
        evt->f10 = 1;                            /* 0x10012b33 */
    }
    shared_ptr_t h = shared_ptr_from_raw(0x1001c110, evt);       /* 0x10012b37 ★ 复用点 */
    DmcApi_PushEvent(&h);                        /* 0x10012b45 [0x1006f220] */
    release_shared_ptr(&h);                      /* 0x10012b5a..b80 引用计数递减 */

    /* --- 取 6 个行情缓冲 [A] --- */
    Ctx6 ctx6;
    get_ctx6_0x10006cc0(this_, &ctx6);           /* 0x10012b8d */

    /* --- ★ P 短路表 (包装层) [A] --- */
    switch (mode) {
        case 11: **param = 2.0; return 1;        /* 0x10012b97 [0x1006fb48] */
        case 12: **param = 1.0; return 1;        /* 0x10012ba7 fld1 */
        case 21: **param = 4.0; return 1;        /* 0x10012bb7 [0x1006fcd8] */
        case 22: **param = 3.0; return 1;        /* 0x10012bcf [0x1006fc90] */
        case 31: **param = 6.0; return 1;        /* 0x10012bd8 [0x1006fcd0] */
        case 32: **param = 5.0; return 1;        /* 0x10012bec [0x1006fcc0] */
        case 51: **param = 0.0; return 1;        /* 0x10012bfd fldz */
        default: break;                          /* 0x10012bfb jne 0x10012c06 */
    }

    /* --- ★ 真工作函数: ch::ch_api 虚调用 [A] --- */
    ch_api *api = *(ch_api **)((char *)this_ + 0xbc);      /* 0x10012c09 */
    void **vt   = api->vt;                                  /* 0x10012c0f */
    int (*fn)(ch_api *, int, double *, Ctx6 *, double **) =
        (void *)((uint32_t *)vt)[0x34 / 4];                 /* 0x10012c11 */
    fn(api, count, out, &ctx6, param);                      /* 0x10012c22 */
    return 1;                                               /* 0x10012c24 mov al,1 */
}

/* ---------------------------------------------------------------------------
 * 3. chlib 工作函数  ch_api::vt[+0x34] = 0x10002340
 * -------------------------------------------------------------------------*/

/* [A] 逐句对应 tools/re-inventory/nchbi/chlib_worker_10002340.txt (377 insn)
 * 前置: 0x10006cc0 已把 H/O/L/C/V/A 填进 ctx6  (chlib 只用 ctx6[0]=high, ctx6[2]=low) */
int __thiscall ch_api_vt34(ch_api *self, int count, double *out, Ctx6 *ctx6, double **param)
{
    int mode = (int)*(*param);                   /* 0x1000235b fld; 0x100148a0 _ftol2 → ebx */
    int winLen = -1;                             /* 0x1000245d mov [esp+0xc], -1 [B] */
    int idx = -1;                                /* edi 初值, 见下 */

    memset(out, 0, (size_t)count * 8);           /* 0x10002381 call 0x1001494c */
    if (ctx6->high == NULL) return -1;           /* 0x10002389 */
    if (ctx6->low  == NULL) return -1;           /* 0x10002394 */

    /* --- 第二道授权门: 仅 mode == 0 时 [A] --- */
    if (mode == 0) {                             /* 0x1000239e test ebx,ebx; jne skip */
        if (self->auth == NULL) return -1;       /* 0x100023a0 cmp [esi+4],ebx; je -> -1 */
        if (!self->auth->vt[1](0xEA62))          /* 0x100023ae [edx+4]; push 0xea62 */
            return -1;                           /* 0x100023ba */
    }
    if (early_check_0x10006670(count)) return -1;/* 0x100023c8 */
    prepare_0x10009930(self->engine, ...);       /* 0x100023e6 + engine vt[+4]/vt[+0xc] */

    /* --- 分型内核: 两个 argmax/argmin 循环 [A] --- */
    if (/* 分支选择由 [esp+0xc] 状态 */ true) {
        /* 顶分型候选: H 缓冲 argmax
         *   0x1000260b fld [-DBL_MAX];  比较 ctx6->high / [esi+edx*8]
         *   0x10002629 test ah,5; jp  → 跳转成立 = >=|==|U  (即 ST0 不更小 → 保持)  */
        idx = argmax_over(ctx6->high, winLen, /*seed=*/-DBL_MAX_CONST /* chlib!0x100154c8 */);
        /* 0x10002624 fcom [ecx-0x10] ... 0x1000266e add ecx,0x20  (4 个 double 展开)
         * 0x10002687 fcom [esi+edx*8]   尾段单步                                       */
    } else {
        /* 底分型候选: L 缓冲 argmin
         *   0x100026a9 fld [+DBL_MAX];  0x100026c9 test ah,0x41; jne → 跳转成立 = <=|==|U  */
        idx = argmin_over(ctx6->low, winLen, /*seed=*/+DBL_MAX_CONST /* chlib!0x100154c0 */);
    }

    if (idx < 0) return -1;                      /* 0x1000273b test edi,edi; jl 0x10002757 */
    /* out[idx] = ... ; return 0/1 —— 第二批补全 [C] */
    return 1;                                    /* [C] 具体出口值待仲裁 */
}

/* ---------------------------------------------------------------------------
 * 4. 复用判定速记 [A]
 * -------------------------------------------------------------------------*/
/*
 *  0x1001c110  boost::shared_ptr(evt*) 构造桩   → 复用 (NChBi 0x10012b37 / CHBI 0x1000f692)
 *  0x10001cc0  事件对象 ctor                    → 复用 (NChBi 0x10012af4 / CHBI 0x1000f656)
 *  0x1003eba0  CHBI/CHDUAN m[2] 拆表            → 不复用
 *  0x10053540  CHDUAN prep                      → 不复用
 *  0x1003ef00  CHBI 方向标注                    → 不复用
 *  0x1002c1d0  CHBI 真工作函数                  → 不复用 (NChBi 走 chlib 虚接口)
 */

/* ---------------------------------------------------------------------------
 * 5. 勘误与待仲裁 (docs/25 §七)
 * -------------------------------------------------------------------------*/
/*
 *  [勘误 A] 0x1006bc70 不是"P 转码器", 是 _ftol2 (double->int)。
 *            ⇒ NChBi 的 P 比较全是整数比较; (int)P 截断取整。
 *  [勘误 A] "NChBi 与 ChBi 共用工作函数" 的早期假定不成立:
 *            共用仅限包装层辅助 (0x1001c110 / 0x10001cc0 / 0x10006cc0)。
 *  [修正 B] 缠论组绑定不止 7 个导出: ch_api 虚表槽 +0x18..+0xc4 (36+ 处) 全是。
 *  [待仲裁 C] 槽 +0x40/+0x48/+0x50/+0x54/+0x5c/+0x64 对应的导出名。
 *  [待仲裁 C] chlib 0x10002340 的 [esp+0xc](窗口长度) 来源; 0x10006670/0x10009930 语义。
 *  [待仲裁 C] NCHBISTA 返回码 -3/+3/0 的判定 (第二批: chlib 0x10002770)。
 *  [待仲裁 C] NChBi 与 NChBiSta 是否共享 [this+0x10] 子对象。
 */

/* ---------------------------------------------------------------------------
 * 6. 第二批待办
 * -------------------------------------------------------------------------*/
/*
 *  [ ] chlib 0x10002770 (NChBiSta) 逐条解剖 → 输出码 -3/+3/0 判定条件
 *  [ ] chlib 0x10006670 / 0x10009930 / 0x100148a0 / engine vt[+4]/vt[+0xc] 语义
 *  [ ] chlib 数据流: ctx6(H/O/L/C/V/A) → 内部容器 → out[]
 *  [ ] 输出向量与 NCHBISTA / NCHBIZJ 组合 (顶/底/笔/段) 交互
 *  [ ] frida 动态验证: 挂 TAFLib 0x10012a50 + chlib base+0x10002340
 */
