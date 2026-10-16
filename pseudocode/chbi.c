/* ============================================================================
 * chbi.c — 融立德「缠论笔 (CHBI)」逆向伪码
 * ----------------------------------------------------------------------------
 * 来源: TAFLib.dll (32-bit, PE 链接时间 2023-03-15)
 * 定位: 注册表 CHBI(id 0x49C) -> ?CalcProc_ChBi @0x1000f580
 * 证据: tools/re-inventory/chbi/
 *         core_1002c1d0.txt / f_1003db40.txt / f_1003e200.txt
 *         f_1006a040.txt / f_1003eba0.txt / f_1003ef00.txt
 *         f_1003f0d0.txt / f_1003f150.txt / f_1006a720.txt / f_1006a5e0.txt
 *         f_1006b050.txt / f_1003d780.txt / f_1003d8a0.txt
 *         f_1004b1e0.txt / f_1004f430.txt
 *         cond_*.txt (x87_sim.py 由基本块级栈数据流提取的条件表)
 *         wrapper_ChBi_1000f580.txt
 * 批次: CHBI 第一批 (docs/18) + 第二批 (docs/20) + 第三批 (docs/21, 2026-10-16)
 * 置信度: [A]=实测已证(字节级) [B]=高(多路交叉) [C]=待仲裁/推断
 * ----------------------------------------------------------------------------
 * 整体链路:
 *   公式 CHBI(H, L, P)
 *     -> CalcProc_ChBi @0x1000f580          (包装层)
 *          ctx = this[+0xB0] (惰性: new(4) + 0x1002c160 -> W*)
 *          P   = (int) *(double*) param_array[+8]      // 0x1006bc70 = double->int
 *          if (P == 51) { if (!Authorize(0xEA62)) { memset(out,0); return 0; } }
 *          obj  = new(0x30); ctor 0x10001cc0; obj.str = this[+0xC]+4
 *          iface= new(4); iface->vt = 0x1006f708        // 回调/鉴权接口对象
 *          shared_ptr h = 0x1001c110(obj)               // 共享参数对象
 *          0x1002c1d0(ctx, H, L, param_array, iface)
 *     -> 0x1002c1d0  (工作函数)  —— 见下
 *   [状态全部夯进 W(=*ctx); 公式侧只读 W->m[0]/m[5] 等容器]
 *
 * 第三批修正 (docs/21):
 *   - 输出数组 outD 在入口处整表清零 (0x1002c263 fst = ST0 的 0, 不是 H)
 *   - 输出环: outD[elem.bar-1] = ±1 (elem.+0x20, fild int->double),
 *     elem.+0x98==1 时 ×2 (= -2); 空档补 0  [A]
 *   - 分派: 臂后无 return; eba0/ef00 汇于 0x1002c30b; P==51 时只跑一次
 *     (在 a040 之后), 再走 EA62 门  [A]
 * ==========================================================================*/

/* ---------------------------------------------------------------------------
 * 1. 数据结构
 * -------------------------------------------------------------------------*/

/* VectorMember: 16 字节内嵌容器 = (hdr/+0x00, _Myfirst/+0x04, _Mylast/+0x08, _Myend/+0x0C)
 * 注意: 本工程实测 begin 在 +0x04、end 在 +0x08 (与 std::vector 的 _Myfirst@+0 布局不同,
 *       疑为带 vptr 的自研容器包装) —— 证据: 每处计数都写作 (end - begin)/stride */
typedef struct VectorMember {
    void  *hdr;        /* +0x00  语义待确认(§9 #6) */
    void  *begin;      /* +0x04 */
    void  *end;        /* +0x08 */
    void  *cap;        /* +0x0C */
} VectorMember;

/* W —— 缠论分析上下文 (构造器 0x1002c160: new(0xC8) + W 构造) */
typedef struct W {
    VectorMember m[8];   /* +0x00/0x10/0x20/0x30/0x40/0x50/0x60/0x70 */
    /* 本批用到:  m[0] = 0xA0 笔元素向量 ; m[5] = 0x28 笔记录向量 */
    int          cnt88;  /* +0x88  \  三个计数器, 四个同族函数序言统一清零 */
    int          cnt8c;  /* +0x8C  |  (0x1004b1e0 / 0x1004f430 / 0x1003f170) */
    int          cnt90;  /* +0x90  / */
    /* ... 其余见 docs/06 / docs/15 */
} W;

/* A0Elem —— m[0] 元素, 0xA0 字节  [A]
 * 模板来自 0x1003db40 的栈局部 [esp+0x40..0xDF] (逐字段填充后 push_back) */
typedef struct A0Elem {          /* off   type   语义                      */
    int   barIndex;              /* +0x00  int   [A] 该元素对应的 bar 序号 (db40 循环变量 edi) */
    float f04, f08;              /* +0x04  f32   [B] 输入对复制 (+0x04←a/H, +0x08←b/L, x87 fst 序列 [A]) */
    float hi;                    /* +0x0C  f32   [A] 该 bar 高 (H)          */
    float lo;                    /* +0x10  f32   [A] 该 bar 低 (L)          */
    int   fxType;                /* +0x14  int   [A] 分型类型 +1=顶 / -1=底 (0x1003e200 写) */
    float f18;                   /* +0x18  f32   [A] db40 初值 0.0f          */
    int   dir;                   /* +0x1C  int   [A] 方向码 (来自 db40 的 ebx 状态变量) */
    int   biDir;                 /* +0x20  int   [A] 笔端点标志: 顶=+1 / 底=-1
                                  *     (a040/eba0/ef00 三条路径同构戳记; docs/20 §6.4 的
                                  *      "起点/终点"提法仅在日志措辞, 实质是顶/底) */
    int   i24, i28, i2c, i30, i34;/* +0x24  int  [A] db40 逐字段清零 (=0) */
    float g40, g44, g48, g4c;    /* +0x40  f32   [A] g40/g44←首 bar H/L; g48/g4c←当前 bar a/b 复制 */
    float g50, g54, g58, g5c;    /* +0x50  f32   [A] =0 (db40 逐字段清零)    */
    float g64, g68;              /* +0x64  f32   [A] =0                     */
    int   candTop;               /* +0x70  int   [A] 上行元素置 1 (0x1003df9b) */
    int   g84;                   /* +0x84  int   [A] =0                     */
    int   g88, g8c, g90, g94;    /* +0x88  int   [A] =0 (g90/g94 见 db40 清零块) */
    int   candBot;               /* +0x98  int   [A] 下行元素置 1 (0x1003e014; 末条特殊分支也置 1) */
    int   g9c;                   /* +0x9C  int   [A] =0                     */
} A0Elem;                        /* sizeof == 0xA0  [A] */

/* BiRec28 —— 0x28 字节记录, m[5] / ContA / ContB / ContC 四表共用同一模板  [A]
 * 第三批实证 (docs/21 §4/§5): a040 产出 m[5]; eba0 按方向拆入 ContA(W+0x20, 向下笔)
 * / ContB(W+0x30, 向上笔); ef00 全量复制进 ContC(W+0x40)。序号在拆表时重编号 (从 2 起)。
 * 仲裁 #5 (docs/20 §9): docs/16 称 m[2]/m[3] 标志在 +0x18 — 本批实测 dir 在 +0x14、
 * +0x18==0 → 留待 CHDUAN prep (0x10053540) 最终复核。 */
typedef struct BiRec28 {
    int   ord;       /* +0x00  int  [A] 序号 (a040: 1..; eba0/ef00 拆表重编号 从 2 起) */
    int   idxTop;    /* +0x04  int  [A] 顶端点 m0 下标 */
    int   idxBot;    /* +0x08  int  [A] 底端点 m0 下标 */
    float hiTop;     /* +0x0C  f32  [A] 顶 H */
    float loBot;     /* +0x10  f32  [A] 底 L */
    int   dir;       /* +0x14  int  [A] ±1 (唯一"标志位"; 与 m0[idx].fxType 一致) */
    int   i18;       /* +0x18  int  [A] 0 (eba0/ef00 显式清零) */
    int   i1c;       /* +0x1C  int  [A] 0 (a040 复制自 frozen 槽残留; 名义 0) */
    int   flag20;    /* +0x20  int  [A] a040 尾块=1; eba0/ef00 搬运时先清 0 */
    float f24;       /* +0x24  f32  [A] 仅 a040=-1.0f ([0x1006fc50]);
                                  eba0/ef00 的 tmp 不写此槽 (栈垃圾, 不可依赖) */
} BiRec28;           /* sizeof == 0x28  [A] */

/* ---------------------------------------------------------------------------
 * 2. 工作函数 0x1002c1d0  [A]
 *    xref: 全库唯一调用点 = 0x1000f70b (包装层尾部)
 * -------------------------------------------------------------------------*/
void sub_1002c1d0(void *ctx, int count, double *outD, void *src, void *iface)
{
    /* src = { double *H; double *L; double *P; }  —— [A] 由 [esi]/[esi+4]/[esi+8] 用法确证 */
    if (count <= 0) return -1;            /* 0x1002c1e1: 跳到 0x1002c4a2 (mov eax,-1) */
    if (iface == NULL) return -1;         /* 0x1002c1e7 (注意: 无 outD 空检查) */

    float *bufA = new float[count];       /* 0x1006b34a = operator new[] */
    float *bufB = new float[count];
    W *w = *(W **)ctx;                    /* [A] handle[0] = W*  (docs/15) */

    /* --- 2.1 降精度 + 输出数组整表清零 [A 修正: outD 存 0, 不是 H] --- */
    for (int k = 0; k < count; k++) {     /* 0x1002c24d..0x1002c267 */
        bufA[k] = (float)src->H[k];       /* [A] fld qword / fstp dword */
        bufB[k] = (float)src->L[k];
        outD[k] = 0.0;                    /* [A] fst qword 存的是 ST0 残留的 0 (fldz) */
    }

    /* --- 2.2 候选端点生成 (无条件) --- */
    sub_1003db40(w, count, bufA, bufB);   /* 0x1002c281 */

    /* --- 2.3 严格分型标注 (无条件) --- */
    sub_1003e200(w);                      /* 0x1002c288  (参数走 EAX) */

    /* --- 2.4 按 P 分派 [A 修正: 臂后无 return; 全部汇于 0x1002c30b] ---
     *     字节级形态: cmp chain (0x1002c299..0x1002c2b5); 未中者 jne 0x1002c30b,
     *     P==51 也走此 jne → 跳过 0x1002c2ff..0x1002c306 的 eba0/ef00 */
    int P = (int)*(double *)src->P;        /* 0x1006bc70 = double->int */
    if (P==11 || P==12 || P==21 || P==22 || P==31 || P==32) {
        if      (P==11) sub_1003f170(w, 1);    /* 0x1003f170, 8368 insns */
        else if (P==12) sub_1003f170(w, 2);
        else if (P==21) sub_1004b1e0(w, 1);    /* 0x1004b1e0, 4026 insns */
        else if (P==22) sub_1004b1e0(w, 2);
        else if (P==31) sub_1004f430(w, 1);    /* 0x1004f430, 3974 insns */
        else            sub_1004f430(w, 2);
        sub_1003eba0(w);                  /* 0x1002c300  ContA/ContB 拆分 (§7) */
        sub_1003ef00(w);                  /* 0x1002c306  ContC 全量复制 (§8) */
    }

    if (P == 51) {                        /* 0x1002c30b: cmp esi,0x33; jne 0x1002c33a */
        sub_1006a040(w);                  /* 0x1002c311  分型笔记录生成 (§6) */
        sub_1003eba0(w);                  /* 0x1002c317 */
        sub_1003ef00(w);                  /* 0x1002c31d */
        /* 第二道授权门 [A]:
         *   mov ecx,[esp+0x4c](=iface); mov edx,[ecx]; mov eax,[edx+4]
         *   push 0xEA62; call eax; test al,al; je 0x1002c4a2   ; 0x1002c322..0x1002c334
         * 包装层 0x1000f580 已查过一次 (docs/15); 此处对 iface 再查一次 */
        if (!iface->vtbl[1](0xEA62)) return -1;   /* outD 保持全 0 */
    }

    /* --- 2.5 输出环 0x1002c33a..0x1002c466 [A] (第三批新解) ---
     *  遍历 m0 (0xA0 步进):
     *    b = elem.barIndex
     *    空档补齐: while (cur < b-1) outD[cur++] = 0    ; 0x1002c3f3..0x1002c417 rep stosd
     *    v = elem.+0x20 (±1 int)
     *    if (elem.+0x98 == 1) v *= 2                   ; 0x1002c424..0x1002c438
     *    outD[b-1] = (double)v                         ; 0x1002c43c/0x1002c445 fild...
     *    cur = b
     *  产出编码: 顶=+1 / 底=-1; 候选(底,-2) 由 +0x98 旗标翻倍。
     *  未支持 P: eba0/ef00 未跑, m0 的 +0x20 全 0 → 输出全 0 (空状态) */
    {
        int cur = 0;
        for (A0Elem *e = m0_begin(w); e != m0_end(w); e++) {
            int b = e->barIndex;
            while (cur < b - 1) outD[cur++] = 0.0;
            int v = e->biDir;
            if (e->candBot == 1) v *= 2;
            outD[b - 1] = (double)v;
            cur = b;
        }
        /* 释放: free 两个 float 缓冲 (0x1002c474/0x1002c481; 0x1006b344),
         *       iterator 存储条件释放 (0x1002c48d; 0x1006b320) */
    }
    return 0;                             /* 0x1002c496: xor eax,eax */
}

/* ---------------------------------------------------------------------------
 * 2b. 硬编码 P=51 版入口 0x1002c4b0  [A] (第三批)
 *     __usercall: EAX=series(={double*H; double*L; ...}), arg1=ctx(→ W 持有指针),
 *                 arg2=count, arg3=outD, arg4=iface; ret 0x14
 *     无 P 读取; 恒定链: db40 → e200 → a040 → eba0 → ef00 → EA62 门(iface)
 *                → 输出环(同 2.5) → return 0 (拒绝时 -1)
 * -------------------------------------------------------------------------*/
void sub_1002c4b0(/*EAX*/ void *series, void *ctx, int count, double *outD, void *iface);

/* ---------------------------------------------------------------------------
 * 3. 0x1003db40 —— 候选端点生成器  [A]
 *    签名: void __stdcall f(W *self, int n, const float *srcH, const float *srcL)
 *    415 指令 / 92 基本块 / 25 条件 / 0 未知操作数
 *    第三批复核: 主循环共 n 次 (edi = 1..n); 循环底 0x1003e099:
 *      add edi,1; lea edx,[edi-1]; cmp edx,[esp+0x18c](=n); jl 0x1003dc00
 *    → edi 达到 n (最后一根 bar, 无下一根可 peek) → jge 0x1003e00c 特殊分支
 *      (该元素 +0x98=1)。docs/20 §4.2 的 "n-1 次" 更正为 n 次 [A]。
 *    详细状态机 (25 条件) 待第四批逐条落地 — 以下为当前已知骨架 [B]。
 * -------------------------------------------------------------------------*/
void sub_1003db40(W *self, int n, const float *srcH, const float *srcL)
{
    /* 3.1 清空 m[0] (0x1003d8a0 = __move, 把 end 收到 begin) */
    if (m0_size(self)) sub_1003d8a0(self->m[0].begin, self->m[0].end, self->m[0].begin);

    if (n <= 0) return;                    /* 0x1003db9d: 门 */

    float refH = 0, refL = 0;              /* [esp+0x2c] / [esp+0x28] — 每轮末尾被覆写为
                                              (a,b)=当前 bar H/L (0x1003df07/0x1003df0d)，
                                              供下一轮"相邻 bar 比较"用 [A] */
    float hRef = 0;                        /* [esp+0x30] */
    float firstH = 0, firstL = 0;          /* [esp+0x34] / [esp+0x3c] (首 bar 记录) */
    int   i = 1;                           /* edi */
    int   isFirst = 1;                     /* [esp+0x24] */
    int   dir = 0;                         /* ebx: {0, 1, 2, -1, -2} 方向状态机 [A] */
    int   cand = 0;                        /* ebp / [esp+0xe0]: 候选极值索引 */
    int   outIdx = 0;                      /* [esp+0x40] -> elem.barIndex */

    for (; i <= n; i++) {                  /* 0x1003dc16, 共 n 次 [A 修正: docs/20 写 n-1] */
                                           /* 尾底 0x1003e099: add edi,1; lea edx,[edi-1];
                                              cmp edx,n; jl 0x1003dc00 -> edi 达 n (末 bar) */
        float a = srcH[i - 1];             /* [esp+0x14] */
        float b = srcL[i - 1];             /* [esp+0x18] */
        if (isFirst) {                     /* 0x1003dc34 */
            firstH = a; firstL = b; dir = 0; isFirst = 0;
        }

        if (dir > 0) {
            /* ---- 上行分支 0x1003dc52 (条件 1,2,3) ---- */
            /* 落空(严格大于)才继续; 否则 jp/je 跳 0x1003dca3 */
            if (!(refH <= a) && !(refL <= b)) {          /* 条件1 ah,01/jne + 条件2 ah,41/jp */
                if (cand > 0 && srcH[cand] > a) {        /* 条件3 ah,01/jne 落空 = ">" */
                    outIdx = cand + 1; dir = /* 保持 */ 0;
                } else { outIdx = i - 1; cand = i - 2; }
            } else {                                     /* 0x1003dca3 */
                if (a > refH) goto tail2;                /* 条件5 ah,41/je 跳 = 大于 */
                if (b > refL) goto tail2;                /* 条件6 */
                if (cand > 0 && srcH[cand] > a) { outIdx = cand + 1; }
                else { cand = i - 1; outIdx = i; }
            }
tail2:      /* 0x1003dcdb: 收敛判定 */
            if (a > refH) refH = a; else /* 保持 */;    /* 条件7/9 */
            if (b > refL) refL = b; else /* 保持 */;
            dir = 2;
        } else {
            /* ---- 下行分支 0x1003dd54 (条件 8, 镜像) ---- */
            if (/* !(a >= refH) && !(b >= refL) */ true) {
                if (cand > 0 && srcL[cand] > b) { outIdx = cand + 1; }   /* 条件8 ah,41/jp */
                else { outIdx = i - 1; cand = i - 2; }
            } else {
                if (a > refH) goto tail3;
                if (b > refL) goto tail3;
                if (cand > 0 && srcL[cand] > b) { outIdx = cand + 1; }
                else { cand = i - 1; outIdx = i; }
            }
tail3:
            if (a > refH) refH = a;                      /* 条件 9 */
            if (b > refL) refL = b;
            dir = -2;
        }

        /* ---- 3.2 填充 A0 元素模板并 push_back (4 个调用点) ---- */
        A0Elem e; memset(&e, 0, sizeof e);               /* 0x1003de6b..0x1003defe 逐字段清零 [A] */
        e.barIndex = outIdx;                             /* +0x00 */
        e.hi = a;                                        /* +0x0C  [A] */
        e.lo = b;                                        /* +0x10  [A] */
        e.dir = dir;                                     /* +0x1C  [A] */
        if (dir > 0) e.candTop = 1;                      /* +0x70 = 1  [A] 0x1003df9b */
        else         e.candBot = 1;                      /* +0x98 = 1  [A] 0x1003e014 */
        e.g40 = firstH; e.g44 = firstL;                  /* 0x1003dfc1..0x1003dfdc */
        e.g48 = b;      e.g4c = a;                       /* 0x1003dfe3..0x1003dfec */
        push_back_A0(&self->m[0], &e);                   /* 0x1006a5e0(W, &e) */

        /* ---- 3.3 共享尾块: ±0.001 微调 (0x1006fc28 = 0.001 [A]) ---- */
        if (e.g4c != hRef) {                             /* 条件 10 ah,41/jne 落 = ">" */
            if (e.g4c == 0.0f) hRef += 0.001f;           /* 条件 11 ah,44/jnp 跳 = "==" */
            else               hRef -= 0.001f;
        }
        /* 条件 12 ah,05/jp: 另一方向的符号修正 */
    }
}

/* ---------------------------------------------------------------------------
 * 4. 0x1003e200 —— 严格分型标注器  [A]
 *    签名: void __fastcall f(W *self)   (唯一参数走 EAX)
 *    174 指令 / 51 基本块 / 8 条件 / 0 未知操作数
 * -------------------------------------------------------------------------*/
void sub_1003e200(W *self)
{
    int n = m0_size(self);
    if (n <= 1) return;

    A0Elem *it = (A0Elem *)0x1003f0d0(self, 1);   /* m[0].begin() + 1 */
    for (int i = 1; i <= n - 2; i++, it++) {      /* 只处理"内部"元素 */
        A0Elem *cur  = it;
        A0Elem *prev = it - 1;                    /* cur - 0xA0 */
        A0Elem *next = it + 1;                    /* cur + 0xA0 */

        /* 注意 x87 栈序: 载入顺序 (cur, prev, cur, prev) -> ST0 = prev 值 */
        if (prev->hi < cur->hi && prev->lo < cur->lo) {         /* 条件 1,2 (ah,05 jp 落空) */
            if (i >= n - 1) continue;
            if (next->hi < cur->hi && next->lo < cur->lo) {     /* 条件 3,4 */
                cur->fxType = +1;                              /* 0x1003e354  ★ 顶 */
            }
        } else if (cur->hi < prev->hi && cur->lo < prev->lo) {  /* 条件 5,6 (fxch st(3)/fstp st(1) 后) */
            if (i >= n - 1) continue;
            if (next->hi > cur->hi && next->lo > cur->lo) {     /* 条件 7,8 (ah,41 jne 落空 = ">") */
                cur->fxType = -1;                              /* 0x1003e3d7  ★ 底 */
            }
        }
    }
    /* 等价闭式 [A] (由 §1.2 四态真值表可证 '='/'U' 归入不标记侧):
     *   顶(i) <=> H[i] > max(H[i-1],H[i+1]) && L[i] > max(L[i-1],L[i+1])
     *   底(i) <=> H[i] < min(H[i-1],H[i+1]) && L[i] < min(L[i-1],L[i+1])
     */
}

/* ---------------------------------------------------------------------------
 * 5. 0x1004b1e0 / 0x1004f430 —— 镜像孪生的"笔端点定向/收敛器"  [A/B]
 *    签名: void __stdcall f(W *self, int mode)      mode ∈ {1, 2}
 *    4026 / 3974 指令, 各 80 条件, 条件形状序列逐位一致 79/80 = 98.8%
 * -------------------------------------------------------------------------*/
void sub_1004b1e0(W *self, int mode)   /* mode==1 -> 顶向 ; mode==2 -> 底向  [B] */
{
    /* 5.1 序言 (与 0x1004f430 / 0x1003f170 逐条同构) [A] */
    self->cnt88 = self->cnt8c = self->cnt90 = 0;
    int n0 = m0_size(self);            /* (end-begin)/0xA0 */
    int n5 = m5_size(self);            /* (end-begin)/0x28 */
    if (n5) shrink_m5(self);           /* 非空先收缩 */

    /* 5.2 主体: 以 db40 生成的候选元素为输入做收敛 */
    int local98 = 3;                                     /* [esp+0x98]，尾部也用 */
    for (A0Elem *ip = m0_begin(self); ip != m0_end(self); ip++) {
        /* 元素访问一律经 0x1006a830 = vector<E>::const_iterator::operator* (断言版) */
        float hi = deref(ip)->hi, lo = deref(ip)->lo;
        float histH = LOCH(0x30), histL = LOCH(0xf0);    /* 历史极值栈槽 */
        float sentinel = *(float *)0x1006fc50;           /* = -1.0f  [A] 哨兵 */

        /* --- 条件族 1: 极值比较 (35 条 ST1 族中的主体) --- */
        if (hi > histH && lo > histL) { /* ... */ }
        /* --- 条件族 2: 哨兵检查 (45 条 mem 族) ---
         *   fucom / fucomp / fucompp  +  test ah,0x44 + jnp  => "是否恰等于 -1.0f"
         *   (mem 操作数 = [0x1006fc50] / [esp+0x1c] / [esp+0x30] / [esp+0xf0]) */
        if (lo == sentinel) { /* 视为"未设置" */ }
        /* ... 成立则 0x100697a0/0x100699c0 (b1e0) 或 0x10069ba0/0x10069e10 (f430) 插入元素 ... */
    }

    /* 5.3 尾部: 笔端点方向标注 (0x1004f1e1..0x1004f399 / f430 同构)  [A] */
    for (BiRec28 *e = m5_begin(self); e != m5_end(self); e++) {   /* += 0x28 */
        if (e->dir == 1 || e->dir == -1) {
            A0Elem *pA = (A0Elem *)0x1003f0d0(self, e->idxTop);    /* m[0].begin() + idx */
            pA->biDir = +1;                                        /* 0x1004f2d5 / 0x1004f343 */
            A0Elem *pB = (A0Elem *)0x1003f0d0(self, e->idxBot);
            pB->biDir = -1;                                        /* 0x1004f381 */
            /* 第三批补注 [A]: 与 a040/eba0/ef00 三处同构 —— +0x04 端(顶)=+1,
             *   +0x08 端(底)=-1; docs/20 待仲裁 #4 的"两分支动作等价"即该映射 */
        } else {
            e->flag20 = ((X - e->idxBot) > local98) ? 1 : 0;        /* 0x1004f26f / 0x1004f283 */
        }
    }
}

/* 0x1004f430 与 sub_1004b1e0 为同一算法的镜像实例:
 *   - 序言同构, 条件形状 79/80 逐位一致 (差异仅在末位 0x41/jp vs 0x41/jnp)
 *   - 调用画像对称 (0x1006a830: 296 vs 298 ; 0x1003f0d0: 58 vs 57)
 *   - 专用 insert 家族不同: b1e0 用 0x100697a0/0x100699c0, f430 用 0x10069ba0/0x10069e10
 *   - 仅 b1e0 额外调用 0x10069540 (读 +0x14 == -1) 3 次
 *   => 复用同一伪码, mode 由调用方 (0x1002c1d0 的 P 分派) 决定  [B] */

/* ---------------------------------------------------------------------------
 * 6. 0x1006a040 —— 分型笔记录生成器 (P=51 专用)  [A]
 *    356 指令; 输入 = m[0] (db40/e200 产物); 输出 = m[5] (0x28 记录) + m[0] 端点戳
 *    字节级复核 (docs/21 §4):
 *      - 序言 n=m0.size(); n<=5 return; 清 m5 (→ W+0x50 对象)
 *      - lea esi,[ebx-1] (0x1006a113) 仅在循环前执行一次 (循环回跳 0x1006a116)
 *        → esi==1 是常量比较 (此前误读为动态比较, 已修正)
 *      - 端点共享 (借用): 向上笔借上一条 push 的 +0x08/+0x10 (底),
 *        向下笔借 +0x04/+0x0C (顶) —— "bi K 与 bi K-1 共享端点"
 *      - 记录 +0x24 = -1.0f ([0x1006fc50])  [A]
 * -------------------------------------------------------------------------*/
void sub_1006a040(W *self)
{
    int n = m0_size(self);
    if (n <= 5) return;                        /* 0x1006a05f */
    clear_m5(self);                            /* 0x1006a07e: W+0x50 对象清空 */

    A0Elem *frozen = NULL;                     /* 首个标记元素: 冻结 (pending), 不立即 push */
    int recNo = 0;                             /* [esp+0x14] (首条 = 1, 先自增后用) */

    for (int k = 2; k <= n - 2; k++) {         /* 扫描标记窗口 [B] */
        A0Elem *e = &m0[k];
        if (e->fxType == 0) continue;
        if (!frozen) { frozen = e; continue; } /* 首标记: 冻结 */

        /* 每个后续标记: 产出"顶/底"端点记录对 (dir 由 frozen 分型类型决定):
         *   向上笔: push(prev底, frozen顶) + push(frozen, cur)
         *   向下笔: 同构镜像 —— 两条
         * 端点复用: 后 push 借前 push 的栈槽 (端点共享, 见上) */
        BiRec28 tmp;
        tmp.ord    = ++recNo;
        tmp.idxTop = ...; tmp.idxBot = ...;    /* [B] 逐 push 字段来源表待第四批 */
        tmp.hiTop  = ...; tmp.loBot  = ...;
        tmp.dir    = frozen->fxType;           /* ±1 */
        tmp.i18 = 0; tmp.i1c = 0; tmp.flag20 = 0;
        tmp.f24    = -1.0f;                    /* [A] [0x1006fc50] */
        push_back_28(self, W+0x50, &tmp);      /* 0x1006a720 */
        frozen = e;
    }
    /* 尾块 [A]: #rec == #标记 - 1 (0x1006a364 校验)
     *   for each rec: m0[rec.idxTop].biDir = +1; m0[rec.idxBot].biDir = -1;
     *   for each rec: rec.flag20 = 1;
     *   pending 无 current 时 flush 为单条记录 (0x1006a331 附近特判) [B] */
}

/* ---------------------------------------------------------------------------
 * 7. 0x1003eba0 —— 按方向拆表 (ContA/ContB) + m[0] 端点戳  [A]
 *    (第三批全文解码; P∈{11..32} 臂后 0x1002c300 / P=51 链 0x1002c317 共用)
 * -------------------------------------------------------------------------*/
void sub_1003eba0(W *self)
{
    clear_28(W+0x20 /*ContA: 向下笔*/);        /* 序言: W+0x24/0x28 */
    clear_28(W+0x30 /*ContB: 向上笔*/);        /* W+0x34/0x38 */

    int counter = 1;
    for (BiRec28 *r = m5_begin(self); r != m5_end(self); r++) {   /* 步进 0x28 */
        r->flag20 = 0;                         /* 先清笔端点标志 */
        BiRec28 tmp = *r;                      /* 复制 (含 i1c; i18/flag20 = 0) */
        tmp.ord = ++counter;                   /* 重编号: 首条 = 2 */
        if (r->dir == +1) push_back_28(self, W+0x30, &tmp);   /* 0x1006a720 */
        if (r->dir == -1) push_back_28(self, W+0x20, &tmp);
        A0Elem *pt = (A0Elem *)0x1003f0d0(self, r->idxTop);
        pt->biDir = +1;                        /* m0[顶].+0x20 = +1 */
        A0Elem *pb = (A0Elem *)0x1003f0d0(self, r->idxBot);
        pb->biDir = -1;                        /* m0[底].+0x20 = -1 */
        /* tmp.f24 未写 (栈垃圾) — 下游不可依赖 [A] */
    }
}

/* ---------------------------------------------------------------------------
 * 8. 0x1003ef00 —— 全量复制到 ContC + m[0] 端点戳  [A]
 *    (第三批全文解码; 与 eba0 成对调用, 无 dir 分支)
 * -------------------------------------------------------------------------*/
void sub_1003ef00(W *self)
{
    clear_28(W+0x40 /*ContC: 全量*/);          /* 序言: W+0x44/0x48 */

    int counter = 1;
    for (BiRec28 *r = m5_begin(self); r != m5_end(self); r++) {
        r->flag20 = 0;
        BiRec28 tmp = *r;
        tmp.ord = ++counter;                   /* 首条 = 2 */
        tmp.i18 = 0; tmp.i1c = 0; tmp.flag20 = 0;
        push_back_28(self, W+0x40, &tmp);      /* 0x1006a720 */
        A0Elem *pt = (A0Elem *)0x1003f0d0(self, r->idxTop);
        pt->biDir = +1;
        A0Elem *pb = (A0Elem *)0x1003f0d0(self, r->idxBot);
        pb->biDir = -1;
    }
}

/* ---------------------------------------------------------------------------
 * 9. 待办 (第四批+)
 * ---------------------------------------------------------------------------
 *  [ ] db40 状态机逐条落地 (25 条件); 重点: [esp+0x30] 与 cand([esp+0xe0]) 的
 *      互斥消费; 末条特殊分支 0x1003e00c 与 0x1003e024 尾块 (0.001 修正路径)
 *  [ ] a040 逐 push 字段来源表 (顶/底 idx 与 H/L 的四种组合) — 供 chbi.py 移植
 *  [ ] 仲裁 #4 收尾: b1e0/f430 尾部 ±1 分支等价 ↔ 顶=+1/底=-1 映射 (§5.3 已补注)
 *  [ ] 仲裁 #5 收尾: CHDUAN prep (0x10053540) 对 ContA/ContB 的读取偏移复核 (+0x14 vs +0x18)
 *  [ ] A0Elem 剩余 [C]: g88/g8c; W+0x00 (VectorMember.hdr) 语义
 *  [ ] 动态验证 (frida): dump m5 (W+0x50) 记录表 + CHBI 输出序列, 与 chbi.py 对拍
 *  [ ] 条件表落盘复现: x87_sim.py 逐函数跑 (见 docs/20 §8)
 * -------------------------------------------------------------------------*/
