/* ============================================================================
 * nchbi.c — 融立德「NChBi（缠论笔·新版）」逆向伪码
 * ----------------------------------------------------------------------------
 * 来源: TAFLib.dll (32-bit, PE 链接时间 2023-03-15) + chlib.dll (106 KB, 同日)
 * 定位: 导出 ?NChBi @0x10012a50 (TAFLib)  ->  虚调用 chlib!ch::ch_api::vt[+0x34]
 * 证据: tools/re-inventory/nchbi/
 *         第一批: nchbi_entry.txt / chlib_vtable_and_factory.txt /
 *                 chlib_worker_10002340.txt / cond_chlib_10002340.txt /
 *                 reuse_probe.txt / nchbi1_wip.md
 *         第二批: chlib_worker_10002770.txt / cond_chlib_10002770.txt /
 *                 chlib_worker_10002900.txt / chlib_prep_10009930.txt /
 *                 family_slots.txt / family_slots_full.txt /
 *                 map_family_slots.py / nchbi2_wip.md
 * 批次: 第一批 (docs/25) + 第二批 (docs/26) + 第三批 (docs/27) + 第四批 (docs/28), 2026-10-17
 * 置信度: [A]=实测已证(字节级) [B]=高(多路交叉) [C]=待仲裁/推断
 * ----------------------------------------------------------------------------
 * 整体链路:
 *   NCHBI(count, out[], P)    → 算「结构」并填充容器 → out[] = 极值 bar 索引
 *   NCHBISTA(count, out[])    → 只读容器 → out[] = 逐 bar 的 {±1,±2,±3,±10} 编码
 *   ★ NCHBISTA 必须在同一实例上「先跑 NCHBI」才有数据（自身不触发计算）[A]
 * ==========================================================================*/

/* ---------------------------------------------------------------------------
 * 0. 关键地址速查
 * -------------------------------------------------------------------------*/
/*
 *  TAFLib.dll (ImageBase 0x10000000)
 *    0x10012a50  ?CalcProc_NChBi          包装层 (vtable slot +0x34)
 *    0x10012c40  ?CalcProc_NChBiSta       包装层 (slot +0x38)
 *    0x10012cb0  ?CalcProc_NChBiSta2      包装层 (slot +0x3c)
 *    0x10012d20  ?CalcProc_NChBiZj        (slot +0x44)
 *    0x10012d90  ?CalcProc_NChBiZj3       (slot +0x48)   ← 第二批新定名
 *    0x10012e00  ?CalcProc_NChBiZjOrder   (slot +0x4c)
 *    0x10012e70  ?CalcProc_NChBiFxNum     (slot +0x58)
 *    0x10012ee0  ?CalcProc_NChBiZjNum     (slot +0x5c)   ← 第二批新定名
 *    0x10012f50  ?CalcProc_NChBiSpeed     (slot +0x60)
 *    0x10001cc0  事件对象 ctor (与 CHBI 同)
 *    0x10001f6a  this[+0xBC] = ch_api*   (ctor 内)
 *    0x10006cc0  取 6 行情缓冲 (H/O/L/C/V/A)
 *    0x1001c110  boost::shared_ptr 构造桩 (与 CHBI 同)
 *    0x10014e60  Authorize(this, code)
 *    0x1006bc70  _ftol2  (double -> int)   ← 勘误: 非"P 转码器"
 *
 *  chlib.dll (ImageBase 0x10000000, 只导出 CreateLib/FreeLib)
 *    0x100010d0  ch_api::ch_api(ch_auth*)   → [this] = vtable 0x10015214
 *    0x10015214  ch_api vtable (+0x18..+0xcc 共 50 槽已映射到 TAFLib 导出名)
 *    0x10002340  ★ NChBi 工作函数      (vt[+0x34])  —— 计算并填充容器
 *    0x10002770  ★ NChBiSta 工作函数   (vt[+0x38])  —— 只读容器, 展开成逐 bar 编码
 *    0x10002900  NChBiSta2 工作函数    (vt[+0x3c])  —— 带乘数变体
 *    0x10006670  容器准备器 (obj8+obj_c)              [A 第二批]
 *    0x10009930  chlib 版「P -> 类型码」跳表          [A 第二批]
 *    0x100148a0  chlib 自带 _ftol2
 *    0x1001494c  chlib 自带 memset
 *    0x100153ec  obj8  vtable  [this+0x8]
 *    0x10015474  obj_c vtable  [this+0xc]
 *    0x10015438  obj10 vtable  [this+0x10]
 *    0x1001544c  obj14 vtable  [this+0x14]
 *    0x10015488  obj1c vtable  [this+0x1c]
 *    0x100154b0  double 2^32
 *    0x100154b8  double 2.0            (flag bit3 → 值 ×2)
 *    0x100154c0  double +DBL_MAX       (argmin 种子)
 *    0x100154c8  double -DBL_MAX       (argmax 种子)
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

typedef struct ch_auth ch_auth;                  /* [C] */

/* ch_api: chlib.dll 缠论库句柄；ctor 0x100010d0 实测子对象布局 [A(第二批)] */
typedef struct ch_api {
    void    **vt;          /* +0x00  = 0x10015214                                 */
    ch_auth  *auth;        /* +0x04  CreateLib 入参                               */
    void     *obj8;        /* +0x08  new(0x2c) vt 0x100153ec  记录表产出者          */
    void     *obj_c;       /* +0x0c  new(0x38) vt 0x10015474  派生器                */
    void     *obj10;       /* +0x10  new(0x60) vt 0x10015438  结果容器(项数组)      */
    void     *obj14;       /* +0x14  new(0x68) vt 0x1001544c                       */
    void     *obj18;       /* +0x18  new(0x60) init 0x1000e7c0                     */
    void     *obj1c;       /* +0x1c  new(0x3c) vt 0x10015488  (+0x1c=12,+0x20=26,+0x24=9) */
    char      _pad[0x24 - 0x20];
} ch_api;                                        /* [A] */

/* obj8 ([this+8], 0x2cB, vt 0x100153ec) —— 「记录表」产出者 [A] */
typedef struct Obj8 {
    void  **vt;            /* +0x00 = 0x100153ec (4 槽: 0x100094b0/9500/9530/e0b0) */
    /* vt[+0x04] = 0x10009500  预清
     * vt[+0x08] = 0x10009530  校验(返回非0 => 失败)
     * vt[+0x0c] = 0x1000e0b0  主计算(全族共用)                                  */
    char   _pad1[0x18 - 8];
    unsigned char prepared;/* +0x18  已备标志 (0/1)                                 */
    char   _pad2[0x1c - 0x19];
    Rec20 *recs;           /* +0x1c  记录表 (0x20 字节/条)                          */
    char   _pad3[0x28 - 0x20];
    int    nrecs;          /* +0x28  记录数                                          */
} Obj8;

/* 记录 (0x20B/条, obj8[+0x1c] 指向的表元素) [A] */
typedef struct Rec20 {
    int start;             /* +0x00  起 bar 索引   */
    int end;               /* +0x04  止 bar 索引   */
    char _pad[0x20 - 8];
} Rec20;

/* obj10 ([this+0x10], 0x60B, vt 0x10015438) —— 结果容器 [A(第二批)] */
typedef struct Obj10 {
    void  **vt;            /* +0x00 = 0x10015438 (0x100098d0/99e0/9a20/e0b0...)     */
    char   _pad1[0x1c - 8];
    int    typeCode;       /* +0x1c  0x10009930 写入的 P 类型码                     */
    int    m20;            /* +0x20  = obj8[+0x1c]  (记录表镜像指针)                */
    int    m24;            /* +0x24  = obj8[+0x28]  (记录数镜像)                    */
    int    m28;            /* +0x28  = obj_c[+0x28]                                 */
    int    m2c;            /* +0x2c  = obj_c[+0x34]                                 */
    void  *items;          /* +0x30  端点项数组 (0x21 字节/条)                      */
    char   _pad2[0x3c - 0x34];
    int    nitems;         /* +0x3c  项数                                           */
} Obj10;

/* 端点项 (0x21B/条, obj10[+0x30] 指向的数组元素)
 * 步长 0x21 由两处独立代码交叉确证 (0x10002770 `add esi,0x21` /
 *                                   0x10002340 `add eax,0x84` = 4×0x21)      [A] */
typedef struct Item21 {
    int   value;           /* +0x00  值 v (≡ ±1), 输出时按段缩放                    */
    unsigned char flags;   /* +0x04  bit0 = 有效项 ; bit3(0x08) = 值 ×2             */
    char  _pad1[0x09 - 0x05];
    int   recIdx;          /* +0x09  → obj8 记录表索引 (NChBiSta 用, 须 < nrecs)    */
    char  _pad2[0x1d - 0x0d];
    int   barIdx;          /* +0x1d  → out[] bar 索引 (NChBi 用, 须 < count)        */
    char  _pad3[0x21 - 0x21];
} Item21;

/* ---------------------------------------------------------------------------
 * 2. TAFLib 包装层  ?NChBi @0x10012a50   (第一批, 不变)
 * -------------------------------------------------------------------------*/

/* [A] 逐句对应 tools/re-inventory/nchbi/nchbi_entry.txt */
int __thiscall NChBi(void *this_, int count, double *out, double **param)
{
    int mode = (int)*(*param);                   /* 0x10012a87 fld; 0x1006bc70 _ftol2 */

    /* --- 授权门: P == 0 或 P == 51 (CHBI 只有 P == 51) [A] --- */
    if (mode == 0 || mode == 51) {
        if (!Authorize(this_, 0xEA62)) {         /* 0x10012aa0 */
            memset(out, 0, (size_t)count * 8);   /* 0x10012ab9 call 0x1006bd22 */
            return 0;
        }
    }

    /* --- 事件对象 (与 CHBI 逐句同构) [A] --- */
    EvtObj *evt = (EvtObj *)operator_new(0x30);
    if (evt) {
        evt = ctor_10001cc0(evt);
        evt->f08 = 1; evt->f0c = 0;
        std_string_assign(&evt->str, (char *)this_ + 0xc + 4);
        evt->f10 = 1;
    }
    shared_ptr_t h = shared_ptr_from_raw(0x1001c110, evt);       /* 0x10012b37 复用点 */
    DmcApi_PushEvent(&h);                        /* 0x10012b45 */
    release_shared_ptr(&h);

    /* --- 取 6 个行情缓冲 [A] --- */
    Ctx6 ctx6;
    get_ctx6_0x10006cc0(this_, &ctx6);           /* 0x10012b8d */

    /* --- ★ P 短路表 (包装层, 与 chlib 0x10009930 逐值相同) [A] --- */
    switch (mode) {
        case 11: **param = 2.0; return 1;
        case 12: **param = 1.0; return 1;
        case 21: **param = 4.0; return 1;
        case 22: **param = 3.0; return 1;
        case 31: **param = 6.0; return 1;
        case 32: **param = 5.0; return 1;
        case 51: **param = 0.0; return 1;
        default: break;
    }

    /* --- ★ 真工作函数: ch::ch_api 虚调用 [A] --- */
    ch_api *api = *(ch_api **)((char *)this_ + 0xbc);
    int (*fn)(ch_api *, int, double *, Ctx6 *, double **) =
        (void *)((uint32_t *)api->vt)[0x34 / 4];
    fn(api, count, out, &ctx6, param);
    return 1;
}

/* ---------------------------------------------------------------------------
 * 2b. TAFLib 包装层  ?NChBiSta @0x10012c40   (第二批新增) [A]
 * -------------------------------------------------------------------------*/
/* [A] 逐句对应 0x10012c40-0x10012cac (反汇编见 docs/26 §2) */
int __thiscall NChBiSta(void *this_, int count, double *out)
{
    if (!Authorize(this_, 0xEA61)) {             /* 0x10012c4a push 0xea61; 0x10014e60 */
        memset(out, 0, (size_t)count * 8);       /* 0x10012c6b call 0x1006bd22 */
        return 0;                                /* 0x10012c73 xor al,al */
    }
    Ctx6 ctx6;
    get_ctx6_0x10006cc0(this_, &ctx6);           /* 0x10012c83 (填了但下游不用) */
    ch_api *api = *(ch_api **)((char *)this_ + 0xbc);
    int (*fn)(ch_api *, int, double *, Ctx6 *, void *) =
        (void *)((uint32_t *)api->vt)[0x38 / 4];  /* 0x10012c93 = chlib 0x10002770 */
    fn(api, count, out, &ctx6, /*arg4=*/0);
    return 1;                                    /* 0x10012ca6 mov al,1 */
}
/* ★ 与 NChBi 包装层的差别: ① 授权码 EA61(非 EA62); ② 无 P 短路表;
 *   ③ 不调任何 prep —— 容器必须由同实例上的 NChBi(vt+0x34) 预先填好 [A] */

/* ---------------------------------------------------------------------------
 * 3. chlib 容器基础设施   (第二批新增)
 * -------------------------------------------------------------------------*/

/* [A] 0x10006670(this, count) -> 0 ; 逐句对应 docs/26 §4 */
int __thiscall prep_containers(ch_api *self, int count)
{
    Obj8 *o8 = (Obj8 *)self->obj8;
    if (!o8->prepared) {                          /* 0x10006673 cmp byte [eax+0x18],0 */
        o8->vt[+0x04]();                          /* 0x10006685 = 0x10009500 */
        o8->vt[+0x0c](count, ...);                /* 0x10006696 = 0x1000e0b0 主计算 */
        if (o8->vt[+0x08]() != 0) return -1;      /* 0x100066a0 = 0x10009530 */
    }
    ObjC *oc = (ObjC *)self->obj_c;
    if (!oc->prepared) {                          /* 0x100066b0 cmp byte [ecx+0x18],0 */
        oc->vt[+0x04](); oc->vt[+0x0c](count, ...);
        oc->m20 = o8->recs;                       /* 0x100066e0 [ecx+0x20] = [eax+0x1c] */
        oc->m24 = o8->nrecs;                      /* 0x100066e3 [ecx+0x24] = [eax+0x28] */
        oc->vt[+0x08]();
    }
    return 0;
}

/* [A] 0x10009930(P) -> obj10.typeCode ; chlib 版「P -> 类型码」跳表 */
int code_of_P(void *obj10, int P)
{
    obj10->typeCode = P;                          /* 0x10009936 [eax+0x1c] = ecx */
    if ((unsigned)(P - 11) <= 0x28)               /* 0x10009933/936 ja */
        return obj10->typeCode = jump_table_100099a8[P - 11];
    return P;
}
/* 跳表值: 11->2, 12->1, 21->4, 22->3, 31->6, 32->5, 其它->0  [A]
 * 与 TAFLib 包装层 NChBi 的 switch 常量表 **逐值相同** ⇒ 同一 P 编码双实现 */

/* ---------------------------------------------------------------------------
 * 4. chlib 工作函数  ch_api::vt[+0x38] = 0x10002770  (NChBiSta) ★ 第二批主角
 * -------------------------------------------------------------------------*/

/* [A] 逐句对应 tools/re-inventory/nchbi/chlib_worker_10002770.txt (130 insn, ret 0x10) */
int __thiscall ch_api_vt38_sim(ch_api *self, int count, double *out, void *ctx6, void *arg4)
{
    (void)ctx6; (void)arg4;                       /* ★ 完全不使用 ctx6/arg4 [A] */
    Obj8  *o8  = (Obj8  *)self->obj8;             /* [esi+8]   */
    Obj10 *o10 = (Obj10 *)self->obj10;            /* [esi+0x10] */

    memset(out, 0, (size_t)count * 8);            /* 0x1000278c call 0x1001494c */

    /* --- 四道前置门 (全为「非空 + 授权」) [A] --- */
    if (o8->recs == NULL)            return -1;   /* 0x100027a6 [[esi+8]+0x1c] */
    if (o10->items == NULL)          return -1;   /* 0x100027ba [[esi+0x10]+0x30] */
    if (self->auth == NULL)          return -1;   /* 0x100027c2 [esi+4] */
    if (!self->auth->vt[1](0xEA61))  return -1;   /* 0x100027cc-db  ★ EA61 (非 EA62) */

    /* --- 主循环: 遍历 obj10 的端点项 (0x21 B/条) [A] --- */
    int cur = 0;                                  /* ecx = 段间传递值 v */
    int eax = 0;                                  /* 输出 bar 游标 */
    for (int k = 0; k < o10->nitems; k++) {       /* 0x100027e7 cmp [esp+0x24],ecx */
        Item21 *it = (Item21 *)((char *)o10->items + k * 0x21);
        if (!(it->flags & 1)) { cur = it->value; continue; }   /* 0x10002804 je */

        int idx = it->recIdx;                     /* 0x1000280a [esi] */
        if (idx < 0 || idx >= o8->nrecs) break;   /* 0x1000280e jl / 0x10002818 jae -> 断链 */
        if (cur == 0) cur = -it->value;           /* 0x10002822 neg ecx (首项取反) [C] */

        Rec20 *rec = (Rec20 *)((char *)o8->recs + idx * 0x20);  /* 0x1000282a `shl edx,5` */

        /* 段 A: 填充 [eax, rec->start) 为 cur*10 [A] */
        while (eax < rec->start && eax < count) { /* 0x1000282e jge / 0x10002834 jae */
            out[eax++] = (double)(cur * 10);      /* 0x10002836-46 (lea/add ×5×2) */
        }
        /* 段 B: 区间 [rec->start .. rec->end] 为 cur (bit3 时 cur*2) [A] */
        while (eax <= rec->end && eax < count) {  /* 0x1000284e jg / 0x10002855 jae */
            out[eax++] = (it->flags & 8)          /* 0x10002859 test [esi-5],8 */
                       ? (double)(cur * 2)        /* 0x1000285e-67 add ebx,ebx */
                       : (double)cur;             /* 0x1000286d fild [esi-9] */
        }
        /* 段 C: 端点 bar (rec->end 之后第一格) 为 cur*3  ★ 输出码 ±3 的唯一来源 [A] */
        if (eax > 0 && eax < count)               /* 0x1000287b jle / 0x10002881 jae */
            out[eax++] = (double)(cur * 3);       /* 0x10002883-94 (lea ×3) */

        cur = it->value;                          /* 0x10002898 传给下一条 */
    }

    /* --- 尾广播: 剩余 out[eax..count-1] 全填最后一个 cur*10 [A] --- */
    if (eax < count) {                            /* 0x100028b3 jae */
        out[eax] = (double)(cur * 10);            /* 0x100028b7-c4 */
        /* 0x100028c9-d8 rep movsd: 把刚写的 8 字节前向复制到 out[eax+1..count-1] */
        for (int j = eax + 1; j < count; j++) out[j] = out[eax];
    }
    return 0;                                     /* 0x100028dd xor eax,eax */
}

/* ---------------------------------------------------------------------------
 * 5. ★ 输出码判定表 (NCHBISTA 的 -3/+3/0 闭环) [B]
 * -------------------------------------------------------------------------*/
/*
 *  前提: Item21.value ≡ ±1 (方向: +1 顶 / -1 底) [C 待动态确认]
 *
 *  | 输出值 | 产生段 | 地址(0x1000...)  | 语义                                  |
 *  | ------ | ------ | ---------------- | ------------------------------------- |
 *  |  ±3    | 段 C   | 10002883-94      | **端点/分型 bar** (=-3 底分型 / +3 顶) |
 *  |  ±1    | 段 B   | 1000286d         | 记录区间内部 bar (笔内)                |
 *  |  ±2    | 段 B   | 1000285e-67      | 区间内 flag.bit3 置位的 bar (×2 加权)  |
 *  |  ±10   | 段 A / 尾 | 10002836-46 / 100028b7-d8 | 区间外的填充段                |
 *  |   0    | memset | 1000278c         | 未被任何记录覆盖的 bar                 |
 *
 *  ⇒ **用户公式 `SELECT(VAR2=-3)` 命中的 = 每个结构区间结束后的端点 bar**
 *    （段 C 是 `-3` 的唯一产生路径）[A(路径) / B(语义)]。
 *  ⇒ 函数体无任何 `-3/+3` 立即数 (全文仅 `or eax,0xffffffff` 一处)，且 **x87 条件 0 条**
 *    （只有 fild/fstp 整数→double）⇒ 输出码 100% 由 value 缩放产生 [A]。
 */

/* ---------------------------------------------------------------------------
 * 6. 兄弟对照: 0x10002900 (NChBiSta2, vt[+0x3c]) [B]
 * -------------------------------------------------------------------------*/
/* 与 0x10002770 同族同形 (memset + Authorize + 读 obj8/obj10 表 + ret 0x10)，
 * 差异: 缩放改用 `imul ebx,esi` 系列 (乘数来自局部) 而非 `lea/add` ⇒ 带可配置乘数。
 * 证据: chlib_worker_10002900.txt (0x10002900-0x10002d4f / 失败 0x10002d69) */

/* ---------------------------------------------------------------------------
 * 7. ch_api 虚表槽 -> TAFLib 导出名 全映射 (第二批) [A]
 * -------------------------------------------------------------------------*/
/* 工具: tools/re-inventory/nchbi/map_family_slots.py ; 证据: family_slots.txt
 *   +0x18 NChBhh/NChBh  0x10001590      +0x48 NChBiZj3     0x10002fc0
 *   +0x1c NChBhl        0x10001690      +0x4c NChBiZjOrder 0x10003180
 *   +0x20 NChRef        0x10001790      +0x58 NChBiFxNum   0x10003680
 *   +0x24 NChFx         0x10001a10      +0x5c NChBiZjNum   0x100038b0
 *   +0x28 NChFxSta      0x10001bd0      +0x60 NChBiSpeed   0x10003a90
 *   +0x2c NChFxUpDn     0x10001d90      +0x78 NChDuanKh/Kl/Kd/NChZs/NChZs_L2 0x100045f0
 *   +0x30 NChFxOrder    0x10002190      +0x7c..+0xb0 NChZs* 族
 *   +0x34 NChBi         0x10002340      +0xb8 NChMacdArea  0x10006190
 *   +0x38 NChBiSta      0x10002770      +0xbc NChSecArea   0x10006240
 *   +0x3c NChBiSta2     0x10002900      +0xc4 Xuech/Xuech2  0x10006470
 *   +0x44 NChBiZj       0x10002ea0
 *  8 个槽在 TAFLib .text 内无引用 (字节扫描): +0x40/+0x50/+0x54/+0x64/+0x68/+0x6c/+0x70/+0x74
 */

/* ---------------------------------------------------------------------------
 * 8. 勘误与待仲裁
 * -------------------------------------------------------------------------*/
/*
 *  [勘误 A] 0x1006bc70 / 0x100148a0 都是 _ftol2, 不是"P 转码器"。
 *  [勘误 A] NChBi 与 NChBiSta 的授权码不同: EA62 vs **EA61**。
 *  [勘误 A] "NChBi 与 NChBiSta 各自独立" 不成立: 二者 **共享 obj8/obj10 容器**,
 *           NChBi 填、NChBiSta 读 (见 §2b/§4 注释)。
 *  [修正 A] ch_api 子对象布局全部解出 (第二批): +8/+0xc/+0x10/+0x14/+0x18/+0x1c。
 *  [修正 A] ch_api 虚表槽 +0x18..+0xcc 共 50 槽已映射到 TAFLib 导出名。
 *  [已结案 A] Item21.value 恒为 ±1(或0) —— 第三批确权: value = raw[+0x00],
 *             raw 生产者 0x1000e1c0 只写 {0,+1,-1}; 故 ±3 = 3×value 为唯一来源 (见 §11)
 *  [待仲裁 C] Item21 的 recIdx@+0x09 与 barIdx@+0x1D 为何都是「+1 未对齐」偏移
 *             (疑 struct 为手写字节流序列化; 两函数各自只读其中一个字段)。
 *  [已结案 A] ±2 / ±10 语义 —— ±2 = flags bit3 触发 ×2; ±10 = NChBiSta 段A 缩放;
 *             ±3 = NChBiSta 段C; 三者均为同一 ±1 基值的整数倍 (见 §11)
 *  [待仲裁 C] 8 个无 TAFLib 调用者的槽 (+0x40 等) 的命名归属。
 *  [待仲裁 C] 0x10002770 段 A 的 `cur = -it->value` 首项取反语义。
 */

/* ---------------------------------------------------------------------------
 * 9. 下一批 (第三批) 待办
 * -------------------------------------------------------------------------*/
/*
 *  [ ] Out 向量深挖: 用 frida 在 0x10002770/0x10002340 出口 dump out[] 与 Item21,
 *      确认 value 值域与 ±3/±2/±10 的实际分布 (闭环 §5 的 [B] -> [A])
 *  [ ] NChBiZj (0x10002ea0) / NChBiZjOrder (0x10003180) 链: 笔转折与序号
 *  [ ] NChBiSta2 (0x10002900) 的乘数来源 (哪个参数/哪个内部状态)
 *  [ ] chlib 内部对 8 个未启用槽的调用点扫描
 */

/* ============================================================================
 * 10. 第三批: NChBiZj / NChBiZjOrder 链  (2026-10-17, docs/27)
 * ----------------------------------------------------------------------------
 * 证据: tools/re-inventory/nchbi/
 *         chlib_worker_10002ea0.txt / cond_chlib_10002ea0.txt   (NChBiZj)
 *         chlib_worker_10003180.txt / cond_chlib_10003180.txt   (NChBiZjOrder)
 *         chlib_fill_10006c00.txt / chlib_worker_100038b0.txt
 * ==========================================================================*/

/* ---------------------------------------------------------------------------
 * 10.1 NChBiZj  —— ch_api vt[+0x44] = chlib 0x10002ea0   授权码 0xEA61
 *      语义: Item21 的「散射器」: 把 flags bit2 置位者的 value 写到 out[barIdx]
 * -------------------------------------------------------------------------*/
/*
 * [A] int __thiscall NChBiZj(int count, double *out, int a3, int a4)
 *     // a3/a4 本函数内未引用
 * {
 *     memset(out, 0, count * 8);
 *     obj10 = this[+0x10];
 *     BASE  = obj10[+0x30];               // Item21 数组, stride 0x21
 *     CNT   = obj10[+0x3c];
 *     if (BASE == 0)          return -1;
 *     if (this[+4] == 0)      return -1;  // ch_auth*
 *     if (!Authorize(0xEA61)) return -1;  // vt[+4]
 *
 *     for (i = 0; i < CNT; i++) {
 *         it = BASE + i*0x21;
 *         if (!(it->flags & 4)) continue;         // ★ bit2 = 配对确认的 Zj 项
 *         idx = it->barIdx;                       // +0x1d
 *         if (idx < 0 || idx >= count) continue;
 *         out[idx] = (double) it->value;          // +0x00 (int32)
 *     }
 *     return 0;
 * }
 * // x87 条件 0 条; 不读 obj8; 依赖 NChBi 先填充 obj10。
 */

/* ---------------------------------------------------------------------------
 * 10.2 NChBiZjOrder —— ch_api vt[+0x4c] = chlib 0x10003180   授权码 0xEA61
 *      语义: 先跑 ZjNum 得间隔计数 → 阈值过滤 → 按记录序列重排
 * -------------------------------------------------------------------------*/
/*
 * [A] int __thiscall NChBiZjOrder(int count, double *out, int a3, void *a4)
 *     // a4 -> double* 阈值指针
 * {
 *     THR = (int)( *(double*)(*a4) );
 *     memset(out, 0, count * 8);
 *
 *     obj8  = this[+8];  obj10 = this[+0x10];
 *     A = obj8[+0x1c];  B = obj8[+0x28];       // Rec20 数组(stride 0x20) / 条数
 *     BASE = obj10[+0x30]; CNT = obj10[+0x3c]; // Item21 / 条数
 *     if (A == 0)    return -1;
 *     if (BASE == 0) return -1;
 *
 *     vector<double> vec;                      // 本地, 三指针
 *     vec.resize(count);                       // 0x10006c00
 *     if (vt[+0x5c](count, vec.begin(), a3, a4) != 0) {   // = NChBiZjNum
 *         vec.~vector();  return -1;
 *     }
 *     // ★ 授权门在调用 ZjNum 之后
 *     if (this[+4] == 0 || !Authorize(0xEA61)) { vec.~vector(); return -1; }
 *
 *     for (i = 0; i < CNT; i++) {
 *         it = BASE + i*0x21;
 *         if (!(it->flags & 1))  continue;             // bit0 有效
 *         if (  it->flags & 8)   continue;             // 排除 ×2 档
 *         r = it->recIdx;                              // +0x09
 *         if (r < 0 || r >= B)   continue;
 *         if (r + 1 >= B)        continue;
 *         if (fabs(vec[it->barIdx]) < THR) continue;   // barIdx @+0x1d
 *         out[ *(int*)(A + (r+1)*0x20) ] = (double) it->value;   // Rec20[r+1].startBar
 *     }
 *     vec.~vector();
 *     return 0;
 * }
 * // "Order" = 按记录序列(下一段起始 bar)重排, 不是"序号排序"。
 */

/* ---------------------------------------------------------------------------
 * 10.3 NChBiZjNum —— ch_api vt[+0x5c] = chlib 0x100038b0   授权码 0xEA62
 *      语义: 输出「间隔计数」cnt
 * -------------------------------------------------------------------------*/
/*
 * [A] int NChBiZjNum(int count, double *out, int a3, int a4)
 * {
 *     memset(out, 0, count*8);
 *     BASE = obj10[+0x30]; CNT = obj10[+0x3c];
 *     if (BASE == 0 || this[+4] == 0) return -1;
 *     if (!Authorize(0xEA62)) return -1;
 *
 *     int cnt = 0, lastVal = 0;
 *     for (i = 0; i < CNT; i++) {
 *         it = BASE + i*0x21;
 *         if (it->flags & 1) {                       // bit0: Zj 点
 *             if (0 <= it->barIdx && it->barIdx < count)
 *                 out[it->barIdx] = (double) cnt;
 *             cnt = 0;
 *             lastVal = it->value;                   // 供下轮比较
 *         } else if (it->flags & 4) {                // bit2: 非 Zj 点(待确认)
 *             if (it->value != lastVal) cnt++;
 *         }
 *     }
 *     return 0;
 * }
 */

/* ============================================================================
 * 11. 第三批: Out 静态深挖 —— Item21 生产链确权 (docs/27 §三)
 * ==========================================================================*/
/*
 * 生产链 (自下而上):
 *   bar[] (obj_c[+0x20], stride 0x20)
 *     --0x1000e1c0--> raw[] (obj_c[+0x28], stride 0x1D, value∈{0,+1,-1}) [A]
 *     --NChBi 0x10002340 拷 obj_c[+0x28]/[+0x34] -> obj10[+0x28]/[+0x2c]-->
 *   obj10.vt[+8] = 0x10009a20 (按 obj10[+0x1c] 类型码分派)
 *     ├ code 0 (P=51) -> 0x10009a50  flags∈{0x01,0x21,0x11} | 0x08
 *     └ code 1..6     -> 0x10009dd0  flags∈{0x00,0x10,0x20} | 0x08
 *                          └ 0x1000b000 -> Item21[j].flags |= 4  (Zj 配对确认) [A]
 *   -> Item21[] (obj10[+0x30], stride 0x21, count obj10[+0x3c])
 *
 * Item21 布局 [A]:
 *   +0x00 i32 value   ∈ {0,+1,-1}          <-- 本批结案 docs/26 待仲裁 #1
 *   +0x04 u8  flags   bit0|bit3|bit4|bit5 (code0) / bit3|bit4|bit5 (code1..6)
 *                     bit2 = "Zj 配对确认" (0x1000b000)
 *   +0x05 i32 ordinal (1-based 源序号)
 *   +0x09 i32 recIdx  <- raw[+0x05]
 *   +0x0d f64         <- raw[+0x0d]
 *   +0x15 f64         <- raw[+0x15]
 *   +0x1d i32 barIdx  <- raw[+0x09]   (out 目标下标)
 *
 * 结案:
 *   #1 Item21.value ≡ ±1(或0) [A] => ±3 = 3×value (NChBiSta 段C) 是 ±3 的唯一来源
 *   #3 ±2 = flags bit3 触发 ×2 (NChBi 0x100024a6 & NChBiSta 段B)  [A]
 *      ±10 = NChBiSta 段A 缩放 [A];  ±3 = 段C [A];  均非独立值域
 *   bit2 = "已被 0x1000b000 配对确认为 Zj 点" [A]
 *
 * 授权码汇总: NChBi / ZjNum = 0xEA62 ; NChBiSta / Zj / ZjOrder = 0xEA61
 *
 * 待仲裁(第三批遗留 -> 第四批结算):
 *   [A] 0x1000a250 配对查找规则      -> 见 §12.2 (前向扫最近 flags&1)
 *   [A] 0x1000a060,0x1000a080 取值   -> 见 §12.3 (bar HIGH/LOW)
 *   [A] 0x1000abb0 复核判据          -> 见 §12.5 (value 相反 + 几何分离)
 *   [C] ZjNum 的 cnt 是「间隔笔数」还是「间隔 bar 数」(需 frida 对拍)
 *   [C] ZjOrder 的 a3 / a4 在 TAFLib 侧实参来源
 */

/* ============================================================================
 * 12. 第四批: 生产端分型几何 + Zj 配对链 (docs/28)
 * ==========================================================================*/

/* ---------------------------------------------------------------------------
 * 12.1 obj_c fill 0x1000e1c0 —— 标准缠论 3 根 K 线分型 [A]
 * ---------------------------------------------------------------------------
 * bar 布局 (obj_c[+0x20], stride 0x20, n = obj_c[+0x24]):
 *   +0x00 i32 idxA           索引 -> obj_c[+0x08][] (double 数组, len obj_c[+0x14])
 *   +0x04 i32 idxB           索引 -> obj_c[+0x0c][] (double 数组, len obj_c[+0x14])
 *   +0x08 i32 refHiIdx       TOP 时写入 raw[+0x09]
 *   +0x0c i32 refLoIdx       BOTTOM 时写入 raw[+0x09]
 *   +0x10 f64 HIGH
 *   +0x18 f64 LOW
 *
 * raw 记录 (obj_c[+0x28], stride 0x1D=29B, n = obj_c[+0x34]):
 *   +0x00 i32 value  ∈ {+1 顶, -1 底}          (初值缓冲 0, 未命中不 emit)
 *   +0x04 u8  flags  bit0 = 单调确认通过; bit1 = 尾根合成分型
 *   +0x05 i32 barIdx = i (分型中心 bar 序号; 初值 -1)
 *   +0x09 i32 refIdx = bar[i].+0x08 (顶) 或 bar[i].+0x0c (底)
 *   +0x0d f64 neuHi  TOP->cur.HIGH   / BOTTOM->max(prev.HIGH,next.HIGH)
 *   +0x15 f64 neuLo  TOP->min(prev.LOW,next.LOW) / BOTTOM->cur.LOW
 *   (Item21 = raw 29B + 尾部 i32 barIdx -> 33B, 见 §11)
 */
static int objc_fill_fractal(obj_c *o)          /* 0x1000e1c0 */
{
    if (!o->n_bars || !o->bars) return -1;      /* obj_c[+0x24]/[+0x20] */
    reserve_raw(o->raw, o->n_bars);             /* 0x10006b60 */
    o->raw_count = 0;                           /* obj_c[+0x34] */

    for (int i = 0; i < o->n_bars; i++) {
        const bar *b = &((bar*)o->bars)[i];      /* stride 0x20 */

        /* 主路径: 需左右邻居 (1 <= i <= n-2) */
        if (i >= 1 && i + 1 < o->n_bars) {
            const bar *p = b - 1, *q = b + 1;
            int val = 0;
            /* 顶分型: 4 条 "邻居 < 本根" */
            if (p->HIGH < b->HIGH && p->LOW < b->LOW &&
                q->HIGH < b->HIGH && q->LOW < b->LOW) {
                val = +1;
                emit(o, b->refHiIdx, +1,
                     b->HIGH, fmin(p->LOW, q->LOW),
                     confirm_top(o, i, i+1));    /* 0x1000e450 -> flags bit0 */
            /* 底分型: 4 条 "邻居 > 本根" */
            } else if (p->HIGH > b->HIGH && p->LOW > b->LOW &&
                       q->HIGH > b->HIGH && q->LOW > b->LOW) {
                val = -1;
                emit(o, b->refLoIdx, -1,
                     fmax(p->HIGH, q->HIGH), b->LOW,
                     confirm_bot(o, i, i+1));    /* 0x1000e500 -> flags bit0 */
            }
        }

        /* 尾路径: 仅当 obj_c[+0x1c]!=0 且为末根, 只查 prev vs cur 2 条 */
        if (o->flag1c && i >= 1 && i + 1 == o->n_bars && o->raw_count > 0) {
            const bar *p = b - 1;
            if (p->HIGH < b->HIGH && p->LOW < b->LOW)
                emit_tail(o, b->refHiIdx, +1, b->HIGH, p->LOW);   /* flags |= 2 */
            else if (p->HIGH > b->HIGH && p->LOW > b->LOW)
                emit_tail(o, b->refLoIdx, -1, p->HIGH, b->LOW);   /* flags |= 2 */
        }
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * 12.2 确认器 (flags bit0) 0x1000e450(顶) / 0x1000e500(底) [A]
 * ---------------------------------------------------------------------------
 * 语义: 新分型须相对「上一条已发射记录」通过同向单调确认。
 *   顶(0x1000e450): B[idx2] < C[idx1]  且  C[idx2] < raw_last[+0x15]
 *   底(0x1000e500): C[idx2] > B[idx1]  且  B[idx2] > raw_last[+0x0d]
 * 其中 B = obj_c[+0x08][], C = obj_c[+0x0c][];
 *   idx1 = bar[i].+0x04, idx2 = bar[i+1].+0x00;
 *   raw_last[+0x15] = 上一顶的 min(prev.LOW,next.LOW)  ("确认低", 须逐步降低)
 *   raw_last[+0x0d] = 上一底的 max(prev.HIGH,next.HIGH) ("确认高", 须逐步升高)
 * 通过 -> 返回 1 (调用处写 raw[+0x04] |= 1), 否则 0 (仍 emit, 但标为未确认)
 */

/* ---------------------------------------------------------------------------
 * 12.3 obj10 成员补映射 [A]
 * ---------------------------------------------------------------------------
 *   +0x1c i32 type   类型码 0=P51 1=P12 2=P11 3=P22 4=P21 5=P32 6=P31
 *   +0x30 Item21*    Item21 数组基址 (stride 0x21)
 *   +0x3c i32 n      Item21 项数
 *   +0x44 i32 cur    "当前活动项" 游标
 *   +0x48 i32 = -1
 *   +0x4c i32 = 0
 *   +0x50       子对象/向量 (传入 0x1000ba30)
 *   +0x20 bar*   bar 数组 (stride 0x20)     +0x24 i32 n_bars
 *   +0x08/+0x0c double* 两条索引数组;  +0x14 长度
 */

/* ---------------------------------------------------------------------------
 * 12.4 配对查找族 [A]
 * ---------------------------------------------------------------------------
 * 0x1000a250(o, i) : 向前扫 i-1.. 返回最近 flags&1 的 j  (无距离/值约束), 无则 -1
 * 0x1000a290(o, i) : 向前扫, 返回最近 value==1 且 flags&1 的 j   ("最近有效顶")
 * 0x1000a2d0(o, i) : 向前扫, 返回最近 value==-1 且 flags&1 的 j  ("最近有效底")
 * 0x1000a060(o, i) : bar[i].HIGH  (= obj[+0x20][i*0x20 + 0x10]), 越界 0.0
 * 0x1000a080(o, i) : bar[i].LOW   (= obj[+0x20][i*0x20 + 0x18]), 越界 0.0
 * 0x1000a190(o, i) : 激活项 -> flags = (flags & ~2) | 1;  cur=+0x44=i; +0x48=-1; +0x4c=0;
 *                    若 flags&0x10 则级联清理 i+1
 * 0x1000a210(o, i) : 失效项 -> 仅当 flags&1: flags = (flags & ~5) | 2;
 *                    if (i >= cur) cur = 0x1000a250(o, i)
 */
static int pair_find_any(obj10 *o, int i)       /* 0x1000a250 */
{
    if (i < 0 || i >= o->n) return -1;
    for (int j = i - 1; j >= 0; j--)
        if (o->it[j].flags & 0x01) return j;
    return -1;
}

/* ---------------------------------------------------------------------------
 * 12.5 复核判据 0x1000abb0(o, j, i) [A 骨架] —— 顶底合法对校验
 * ---------------------------------------------------------------------------
 *   1. j < 0                      -> true
 *   2. i<0 || i>=n || j>=i        -> false
 *   3. value[j] == value[i]       -> false   (必须一顶一底)
 *   4. itTop := value==1 的项; itBot := 另一项
 *   5. 按 o->type 分支:
 *        {0,1,2}(P51/12/11): bot.+0x0d < top.+0x0d 且 bot.+0x15 < top.+0x15
 *        {5,6}  (P32/31)   : 用 refIdx 邻域 min-LOW / max-HIGH 极值比较
 *        {3,4}  (P22/21)   : 无附加
 *   6. 公共 tail: bar[bot.refIdx].HIGH < bar[top.refIdx].HIGH
 *              且 bar[bot.refIdx].LOW  < bar[top.refIdx].LOW   -> true   (几何分离)
 *   被 0x1000b000 第 6 步调用; 通过 -> Item21[j].flags |= 4 (Zj 配对确认)
 */
static int pair_recheck(obj10 *o, int j, int i)  /* 0x1000abb0 */
{
    if (j < 0) return 1;
    if (i < 0 || i >= o->n || j >= i) return 0;
    if (o->it[j].value == o->it[i].value) return 0;

    item21 *top = (o->it[j].value == 1) ? &o->it[j] : &o->it[i];
    item21 *bot = (top == &o->it[j])     ? &o->it[i] : &o->it[j];

    switch (o->type) {
    case 0: case 1: case 2:                       /* P51 / P12 / P11 */
        if (!(bot->f0d < top->f0d && bot->f15 < top->f15)) return 0;
        break;
    case 5: case 6:                               /* P32 / P31 */
        /* 邻域 min-LOW / max-HIGH 极值比较 (结构见 docs/28 §2.6 类 B) */
        break;
    default: break;                               /* P22 / P21 */
    }
    /* 公共 tail: 几何分离 */
    if (!(bar_HIGH(o, bot->refIdx) < bar_HIGH(o, top->refIdx))) return 0;
    if (!(bar_LOW (o, bot->refIdx) < bar_LOW (o, top->refIdx))) return 0;
    return 1;
}

/* ---------------------------------------------------------------------------
 * 12.6 合并/延伸 driver 0x1000b100(o, count) -> {0,1,2} [B] (用途标注)
 * ---------------------------------------------------------------------------
 *   count < 2 -> 0;  j = 0x1000a250(o, count);  j<0 -> 0
 *   取 itCur = Item21[count], itJ = Item21[j]
 *   若 itCur.value != itJ.value:
 *        value==1 -> 0x1000a290 找最近有效顶, 比 HIGH; 成功 return 1
 *        else      -> 0x1000a2d0 找最近有效底, 比 LOW;  成功 return 2
 *   若相等(同向): 走"延伸/吞并" (0x1000b20b 起)
 *        用 0x1000a060/a080 比 refIdx 处 HIGH/LOW; 0x1000abb0 复核; 0x1000ae50 复验
 *        命中 -> 0x1000b000 置 bit2; 0x1000a190/a210 增删项; 迭代上限 0x14(20)
 *   => NChBi 族「笔序列构造主驱动」, 非本批 out 消费者
 */

/* ---------------------------------------------------------------------------
 * Item21.flags 位台账 (第四批汇总) [A]
 *   bit0 0x01 有效/已确认项 (配对扫描只看它: 0x1000a250/a290/a2d0)
 *   bit1 0x02 已失效/取消   (0x1000a210 置; 0x1000a190 清)
 *   bit2 0x04 Zj 配对确认   (0x1000b000; NChBiZj 的散射门)
 *   bit3 0x08 ×2 标记       (docs/27)
 *   bit4 0x10 级联清理标志  (0x1000a190)
 *   bit5 0x20 后项联动标志  (0x1000a190)
 *
 * 第四批遗留:
 *   [B] bar 数组填充者 / bar[+0x00..+0x0c] 四个 i32 语义
 *   [B] 0x1000abb0 类 B(P32/31) 与类 A 的分支不等式方向
 *   [C] ZjNum cnt 语义 / ZjOrder a3,a4 来源 / 8 个无调用者槽 / 本批未做动态验证
 */
