/* ============================================================================
 * chbi.c — 融立德「缠论笔 (CHBI)」逆向伪码
 * ----------------------------------------------------------------------------
 * 来源: TAFLib.dll (32-bit, PE 链接时间 2023-03-15)
 * 定位: 注册表 CHBI(id 0x49C) -> ?CalcProc_ChBi @0x1000f580
 * 证据: tools/re-inventory/chbi/
 *         core_1002c1d0.txt / f_1003db40.txt / f_1003e200.txt
 *         f_1004b1e0.txt / f_1004f430.txt
 *         cond_*.txt (x87_sim.py 由基本块级栈数据流提取的条件表)
 *         wrapper_ChBi_1000f580.txt
 * 批次: CHBI 第一批 (docs/18) + 第二批 (docs/20, 2026-10-16)
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
    int   barIndex;              /* +0x00  int   [A] 该元素对应的 bar 序号  */
    float f04, f08;              /* +0x04  f32   [C] 待定                   */
    float hi;                    /* +0x0C  f32   [A] 该 bar 高 (H)          */
    float lo;                    /* +0x10  f32   [A] 该 bar 低 (L)          */
    int   fxType;                /* +0x14  int   [A] 分型类型 +1=顶 / -1=底 (0x1003e200 写) */
    float f18;                   /* +0x18  f32   [C] 待定                   */
    int   dir;                   /* +0x1C  int   [A] 方向码 (来自 db40 的 ebx 状态变量) */
    int   biDir;                 /* +0x20  int   [A] 笔方向端点 +1=起点 / -1=终点 (大函数尾部写) */
    int   i24, i28, i2c, i30, i34;/* +0x24  int  [C] 待定 (i24 与 CHDUAN 标记同址) */
    float g40, g44, g48, g4c;    /* +0x40  f32   [C] 待定 (g40/g44 后写首 bar 的 H/L) */
    float g50, g54, g58, g5c;    /* +0x50  f32   [C] 待定 */
    float g64, g68;              /* +0x64  f32   [C] 待定 */
    int   candTop;               /* +0x70  int   [A] 顶向候选标志 (置 1)     */
    int   g84;                   /* +0x84  int   [C] 待定                   */
    int   g88, g8c, g90, g94;    /* +0x88  int   [C] 待定                   */
    int   candBot;               /* +0x98  int   [A] 底向候选标志 (置 1)     */
    int   g9c;                   /* +0x9C  int   [C] 待定                   */
} A0Elem;                        /* sizeof == 0xA0  [A] */

/* BiRec28 —— m[5] 元素, 0x28 字节  [A]
 * 注意: 字段标志位在 +0x14; docs/16 §2.2 记载 m[2]/m[3] 的同类元素标志在 +0x18
 *       -> 同尺寸不同结构, 登记待仲裁 (docs/20 §9 #5) */
typedef struct BiRec28 {
    int   idxA;      /* +0x04  int  [A] 起点 bar 索引 */
    int   idxB;      /* +0x08  int  [A] 终点 bar 索引 */
    int   i0c, i10;  /* +0x0C  int  [C] 待定 */
    int   fxType;    /* +0x14  int  [A] 分型类型 +1/-1 (由 0x1003e200 写入 m[0] 后同步) */
    int   i18;       /* +0x18  int  [C] 待定 */
    int   flag20;    /* +0x20  int  [A] {0,1} (尾部队计数比较后写) */
} BiRec28;           /* sizeof == 0x28  [A] */

/* ---------------------------------------------------------------------------
 * 2. 工作函数 0x1002c1d0  [A]
 *    xref: 全库唯一调用点 = 0x1000f70b (包装层尾部)
 * -------------------------------------------------------------------------*/
void sub_1002c1d0(void *ctx, int count, double *outD, void *src, void *iface)
{
    /* src = { double *H; double *L; double *P; }  —— [A] 由 [esi]/[esi+4]/[esi+8] 用法确证 */
    if (count <= 0) return;
    if (outD == NULL) return;

    float *bufA = new float[count];       /* 0x1006b34a = operator new[] */
    float *bufB = new float[count];
    W *w = *(W **)ctx;                    /* [A] handle[0] = W*  (docs/15) */

    /* --- 2.1 降精度: double -> float, 并保留 double 到 outD --- */
    for (int k = 0; k < count; k++) {     /* 0x1002c24d..0x1002c267 */
        bufA[k] = (float)src->H[k];       /* [A] fld qword / fstp dword */
        bufB[k] = (float)src->L[k];
        outD[k] = src->H[k];              /* [A] fst qword (原精度) */
    }

    /* --- 2.2 候选端点生成 (无条件) --- */
    sub_1003db40(w, count, bufA, bufB);   /* 0x1002c281 */

    /* --- 2.3 严格分型标注 (无条件) --- */
    sub_1003e200(w);                      /* 0x1002c288  (参数走 EAX) */

    /* --- 2.4 按 P 分派 (顶/底由 mode 奇偶选择) --- */
    int P = (int)*(double *)src->P;        /* 0x1006bc70 = double->int */
    switch (P) {
    case 11: sub_1003f170(w, 1); break;    /* 0x1003f170, 8368 insns — 第三批 */
    case 12: sub_1003f170(w, 2); break;
    case 21: sub_1004b1e0(w, 1); break;    /* 0x1004b1e0, 4026 insns (本批) */
    case 22: sub_1004b1e0(w, 2); break;
    case 31: sub_1004f430(w, 1); break;    /* 0x1004f430, 3974 insns (本批) */
    case 32: sub_1004f430(w, 2); break;
    default: goto afterDispatch;           /* 0x1002c30b */
    }
    sub_1003eba0(w);                       /* 0x1002c300  m[2] 预处理 (与 CHDUAN 共用) */
    sub_1003ef00(w);                       /* 0x1002c306  方向标注 */
    return;                                /* 0x1002c30b 之后为 P==51 专用路径 */

afterDispatch:
    if (P == 51) {                         /* 0x1002c30b */
        sub_1006a040(w);                   /* 0x1002c311  分型笔专用处理 (356 insns) */
        sub_1003eba0(w);
        sub_1003ef00(w);
        /* 第二道授权门 [A]:
         *   mov ecx,[esp+0x4c](=iface); mov edx,[ecx]; mov eax,[edx+4]
         *   push 0xEA62; call eax                  ; 0x1002c322..0x1002c330
         * 包装层 0x1000f580 已查过一次 (docs/15); 此处对 iface 再查一次 (docs/20 §3) */
        if (!iface->vtbl[1](0xEA62)) return;
        ...
    }
}

/* ---------------------------------------------------------------------------
 * 3. 0x1003db40 —— 候选端点生成器  [A]
 *    签名: void __stdcall f(W *self, int n, const float *srcH, const float *srcL)
 *    415 指令 / 92 基本块 / 25 条件 / 0 未知操作数
 * -------------------------------------------------------------------------*/
void sub_1003db40(W *self, int n, const float *srcH, const float *srcL)
{
    /* 3.1 清空 m[0] (0x1003d8a0 = __move, 把 end 收到 begin) */
    if (m0_size(self)) sub_1003d8a0(self->m[0].begin, self->m[0].end, self->m[0].begin);

    if (n <= 0) return;                    /* 0x1003db9d: 门 */

    float refH = 0, refL = 0;              /* [esp+0x2c] / [esp+0x28]  (0x1003dbb4..) */
    float hRef = 0;                        /* [esp+0x30] */
    float firstH = 0, firstL = 0;          /* [esp+0x34] / [esp+0x3c] (首 bar 记录) */
    int   i = 1;                           /* edi */
    int   isFirst = 1;                     /* [esp+0x24] */
    int   dir = 0;                         /* ebx: {0, 1, 2, -1, -2} 方向状态机 [A] */
    int   cand = 0;                        /* ebp / [esp+0xe0]: 候选极值索引 */
    int   outIdx = 0;                      /* [esp+0x40] -> elem.barIndex */

    for (; i < n; i++) {                   /* 0x1003dc16, n-1 次 */
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
        if (e->fxType == 1 || e->fxType == -1) {
            A0Elem *pA = (A0Elem *)0x1003f0d0(self, e->idxA);      /* m[0].begin() + idxA */
            pA->biDir = +1;                                        /* 0x1004f2d5 / 0x1004f343 */
            A0Elem *pB = (A0Elem *)0x1003f0d0(self, e->idxB);      /* m[0].begin() + idxB */
            pB->biDir = -1;                                        /* 0x1004f381 */
            /* [C] 待仲裁(docs/20 §9 #4): fxType==1 与 ==-1 两分支动作观测上等价,
             *      仅临时出参槽不同 ([esp+0x14C] vs [esp+0x164]) */
        } else {
            e->flag20 = ((X - e->idxB) > local98) ? 1 : 0;          /* 0x1004f26f / 0x1004f283 */
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
 * 6. 待办 (第三批+)
 * ---------------------------------------------------------------------------
 *  [ ] 0x1003f170 (P=11/12, 8368 指令, 同族最大) 与 0x1006a040 (P=51) 解剖
 *  [ ] 仲裁 #4: 大函数尾部 fxType==±1 两分支等价性
 *  [ ] 仲裁 #5: m[5] 元素 (+0x14 标志) vs docs/16 m[2]/m[3] (+0x18 标志) 偏移复核
 *  [ ] A0Elem 中标记为 [C] 的 f32/int 字段 (f04/f08/f18/g40..g9c) 找消费者
 *  [ ] W+0x00 (VectorMember.hdr) 语义确认
 *  [ ] 动态验证 (frida): 断 0x1003e354 / 0x1003e3d7 (fxType 写点) 与
 *      0x1004f2d5 / 0x1004f381 (biDir 写点), 用 600000 日线核对 m[0] 序列
 *  [ ] 条件表落盘复现: x87_sim.py 逐函数跑 (见 docs/20 §8)
 * -------------------------------------------------------------------------*/
