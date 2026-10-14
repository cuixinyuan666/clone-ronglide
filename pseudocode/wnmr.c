/*
 * clone-ronglide — 「无脑买入线段」核心算法伪码还原
 * 目标二进制: TAFLib.dll (32-bit PE, ImageBase 0x10000000)
 *
 * 本文件是把四份分析报告合并为可读 C 伪码，便于理解与复刻。
 * 变量名与结构体字段均来自反汇编证据（见 docs/ 目录）。
 *
 * 注意：这是【伪码】—— 用于表达逻辑，不保证可直接编译运行。
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================
 * 1. 数据结构
 * ============================================================ */

/* 级别对象（笔/线段端点），步长 0xA0 = 160 字节
 * 证据: 遍历循环 add ebp,0A0h; 魔数 0x66666667+sar6 = ÷160 */
typedef struct LevelObj {          /* size = 0xA0 */
    int32_t  index;                /* +0x00  自身序号 */
    int32_t  idx_prev;             /* +0x04  索引A: 前一顶点  ★卖出组取此 */
    int32_t  idx_next;             /* +0x08  索引B: 后一顶点  ★买入组取此 */
    float    low;                  /* +0x0C  LOW  (卖出组价格源) */
    float    high;                 /* +0x10  HIGH (买入组价格源) */
    int32_t  level_type;           /* +0x14  分型选择器: 1=取后继底, -1=取前驱顶 */
    uint8_t  _pad0[0x20 - 0x18];
    int32_t  direction;            /* +0x20  方向: 1=上涨, -1=下跌, 0=未定 */
    uint8_t  _pad1[0x88 - 0x24];
    int32_t  fenxing;              /* +0x88  分型: 1=顶, -1=底 */
    int32_t  signal_flag;          /* +0x8C  信号标志: 0/1/-1 */
    int32_t  status;               /* +0x90  ★状态码: 1..6 */
    float    price;                /* +0x94  ★该点实际价格 */
    int32_t  special;              /* +0x98  特殊标志 */
} LevelObj;


/* ============================================================
 * 1b. x87 浮点判定规则（第五批补全）
 *      fnstsw ax  →  AH = {..., C3(6), C2(2), C0(0)}
 * ============================================================
 *
 *  掩码        分支    次数   语义
 *  test ah,5   jp      49    ST0 == ST1     （C0=0 && C2=0）
 *  test ah,5   jnp     10    ST0 != ST1 / 不可比
 *  test ah,41h jne     39    ST0 >  ST1     （C0=0 && C3=0）
 *  test ah,41h je/jp   26    ST0 == ST1
 *  test ah,1   jne     12    ST0 <  ST1     （C0=1）
 *  test ah,1   je       7    ST0 >= ST1
 *
 *  合计 147 次 —— 引擎主体是「区间高低点大小比较」(41h 最多)，判等(5)为辅助。
 */

/* 状态码语义（对应公式 WNMR_线段 中的 VAR5） */
enum {
    ST_STRUCT_UP   = 1,   /* 上涨结构起点 */
    ST_BUY         = 2,   /* 买入价  → 告警 '无脑买入B' */
    ST_STOPLOSS    = 3,   /* 止损价 */
    ST_STRUCT_DOWN = 4,   /* 下跌结构起点 */
    ST_SELL        = 5,   /* 卖出价 */
    ST_TAKEPROFIT  = 6,   /* 止盈价 */
};

/* ============================================================
 * 1c. 容器与迭代器（第六批还原）
 *     级别对象存放在 MSVC 安全 STL 的 std::vector<LevelObj> 中
 * ============================================================ */

/* std::vector<LevelObj> —— 16 字节
 * 证据: sub_1003f0d0 用 [ebx+4]/[ebx+8]；
 *       sub_1006a4e0 写 [edi+4]/[edi+8]/[edi+0Ch] */
typedef struct VectorLevelObj {
    void*      _Myproxy;   /* +0x00  _Container_proxy*（分配器代理） */
    LevelObj*  _Myfirst;   /* +0x04  首元素指针 */
    LevelObj*  _Mylast;    /* +0x08  末元素后一位置（迭代终点） */
    LevelObj*  _Myend;     /* +0x0C  已分配容量末尾 */
} VectorLevelObj;

/* MSVC 受检迭代器 _Vector_iterator<LevelObj> —— 8 字节
 * 普通 STL 迭代器仅 4 字节，多出的 _Mycont 用于越界校验 */
typedef struct CheckedIter {
    VectorLevelObj* _Mycont;   /* +0x00  所属容器 */
    LevelObj*       _Myptr;    /* +0x04  当前元素 */
} CheckedIter;

/* sub_1003f0d0(vec[ebx], out[esi], n[栈]) -> out = vec.begin() + n
 * n 原样使用，无 ±1 调整；越界则夹到 end */
CheckedIter* vec_begin_plus_n(VectorLevelObj* v, CheckedIter* out, int n)
{
    out->_Mycont = v;
    out->_Myptr  = v->_Myfirst;
    for (int i = 0; ; i++) {
        if (out->_Myptr == v->_Mylast) break;   /* 到末尾 */
        if (i == n)                    break;   /* 推进 n 次 */
        out->_Myptr += 1;                       /* +0xA0 字节 */
    }
    return out;
}

/* sub_1003d720(it[esi], out[edi]) —— 后置自增 it++
 * sub_1003d750 完全对称，步进 -0xA0，边界改查 _Myfirst */
CheckedIter* iter_postinc(CheckedIter* it, CheckedIter* out)
{
    *out = *it;                             /* 后置：先拷贝旧值 */
    it->_Myptr += 1;                        /* +0xA0 */
    return out;
}

/* sub_1003f150(src[ecx]) -> vector<LevelObj>（按值，深拷贝快照）
 *   转调 sub_1006a4e0 = vector 拷贝构造：
 *     1) count = (src->_Mylast - src->_Myfirst) / 0xA0
 *     2) _Allocate(count)      → 堆分配 count*160
 *     3) _Uninitialized_copy   → 逐元素拷贝（rep movsd ×0x28）
 *   调用方用完必须 operator delete(snapshot._Myfirst)（0x1006b320） */
VectorLevelObj VectorCopy(VectorLevelObj* src);

/* ============================================================
 * 1d. 输入 bar（0x28 字节）与「迭代器窗口」（第十/十一批还原）
 *
 *  容器 = 上下文类 W（含 8 个 16 字节内嵌 vector 记录）：
 *    W->m[0]  记录 +0x00，数据 +0x04/+0x08  →  vector<0xA0>  级别对象
 *    W->m[4]  记录 +0x40，数据 +0x44/+0x48  →  vector<0x28>  输入 bar
 *    W->m[5]  记录 +0x50，数据 +0x54/+0x58  →  vector<0x28>
 *  sub_10056190 的参数就是 W。
 * ============================================================ */

typedef struct Bar28 {          /* 0x28 字节，POD，经 rep movsd 整体拷贝 */
    int32_t idx00;              /* +0x00  ★ 1 基序号（= 计数器 + 1） */
    int32_t f04;                /* +0x04  另一索引 */
    int32_t idx08;              /* +0x08  ★ 0 基索引 → W->m[0] 的下标 */
    float   low;                /* +0x0C  = 级别对象 +0x0C */
    float   high;               /* +0x10  = 级别对象 +0x10 */
    uint8_t _pad[0x28 - 0x14];  /* +0x14 .. 语义未定 */
} Bar28;

/* 迭代器窗口：9 个受检迭代器，指向 W->m[4] 中连续 9 个 bar
 * 证据：0x100567ae..0x10056804（lea ebx,[esp+0x18] + add ebx,8 + add esi,0x28）
 *      窗口从 W->m[4]._Myfirst + 0x28 起（跳过 bar[0]） */
#define BLOCK_N 9
static void build_block(CheckedIter* block /* = &frame[0x18] */,
                        VectorMember* m4   /* = &W->m[4] */)
{
    Bar28* p = (Bar28*)m4->_Myfirst + 1;        /* 跳过 bar[0] */
    int    i = 0;
    while (p != (Bar28*)m4->_Mylast && i != BLOCK_N - 1) {
        block[i]._Mycont = m4;
        block[i]._Myptr  = (LevelObj*)p;
        p += 1;                                  /* +0x28 */
        i += 1;
        /* block += 1;  (+8) */
    }
}

/* ============================================================
 * 1e. 索引基数定论（第十一批）
 * ============================================================
 *  构造侧（sub_1003e410 等，栈上临时 bar 基址 [esp+0x38]）：
 *    temp+0x00 = [esp+0x10] + 1        →  1, 2, 3, ...      【1 基】
 *    temp+0x08 = [esp+0x14]            →  0 基下标
 *        空 vector   → 0
 *        正常路径    → i-1（i 为 begin()+i 的 0 基元素下标）
 *        无前驱      → N（元素个数，哨兵）
 *  消费侧（sub_1003f0d0）：result = W->m[0].begin() + n，n 原样使用
 *
 *  ∴ +0x00 为 1 基，+0x08 为 0 基 —— 两侧基数一致，无 off-by-one。
 */

/* ============================================================
 * 2. WNMRNEW 封装层  —— sub_1003a7c0
 *    int __thiscall(void* this, int count, double* out, void* ctx)
 * ============================================================ */

int WNMRNEW(void* this_obj, int count, double* out, void* ctx)
{
    if (count <= 0 || ctx == NULL)
        return -1;

    LevelObj* list = *(LevelObj**)this_obj;

    /* 2.1 双缓冲初始化: out 清零并镜像到临时 float 数组 */
    float* temp = (float*)malloc(count * sizeof(float));
    for (int i = 0; i < count; i++) {
        out[i]  = 0.0;
        temp[i] = (float)out[i];
    }

    /* 2.2 授权门禁（功能码 0xEA63） */
    if (!Authorize(ctx, 0xEA63)) {
        free(temp);
        return -1;
    }

    /* 2.3 三级流水线 */
    MarkSignalFlag(list, count, temp);   /* sub_10060aa0 */
    MergeByFlag(list);                   /* sub_100616b0 */
    MainEngine(list);                    /* sub_10056190 */

    /* 2.4 生成容器快照（第六批更正：sub_1003f150 是深拷贝，非"取首元素"）
     *     std::vector<LevelObj> snapshot = *list;   ← 触发堆分配 O(n)
     *     sub_1003f150(src) 转调 sub_1006a4e0 = vector 拷贝构造
     *     遍历 snapshot._Myfirst .. snapshot._Mylast                  */
    VectorLevelObj snapshot = VectorCopy(list);   /* sub_1003f150 / sub_1006a4e0 */

    for (LevelObj* o = snapshot._Myfirst; o != snapshot._Mylast; ++o) {
        int k = o->index - 1;            /* +0x00 为 1 基 → 减 1 */
        out[k] = (double)o->status;      /* ★ 状态码 +0x90 → VAR5 */
    }

    OperatorDelete(snapshot._Myfirst);   /* 0x1006b320：释放快照 */
    free(temp);
    return 1;
}

/* ============================================================
 * 3. 信号打标  —— sub_10060aa0
 *    依据分型序列 arr[] 设置 obj->signal_flag
 * ============================================================ */

void MarkSignalFlag(LevelObj* list, int n, float* arr)
{
    /* 3.1 清零所有 signal_flag */
    for (LevelObj* o = list; o != end(list); o++)
        o->signal_flag = 0;

    /* 3.2 逐元素判定 */
    for (int i = 0; i < n; i++) {
        float v = arr[i];

        if (v == 1.0f) {                 /* fld1 / fcomp */
            /* 回查 index == i-1 的级别对象 */
            for (LevelObj* o = list; o != end(list); o++) {
                if (o->index == i - 1) {
                    if (arr[o->index] == 1.0f)
                        o->signal_flag =  1;   /* 连续同向 → +1 */
                    else
                        o->signal_flag = -1;
                    break;
                }
            }
        }
        else if (v == -1.0f) {           /* 常量 0x1006FC50 = -1.0 */
            /* 不打标 */
        }
    }
}

/* ============================================================
 * 4. 极值搜索（唯一的"数学"部分）
 * ============================================================ */

/* sub_10056010: argmax —— best < arr[k] 时【严格】更新 → 最大值【首次】位置 */
int ArgMax(const float* arr, int n)
{
    float best = arr[0];
    int   idx  = 1;
    for (int k = 1; k < n; k++) {
        if (!(best >= arr[k])) {         /* 即 best < arr[k] */
            best = arr[k];
            idx  = k + 1;
        }
    }
    return idx;
}

/* sub_100560d0: argmin —— best >= arr[k] 时【非严格】更新 → 最小值【最后】位置 */
int ArgMin(const float* arr, int n)
{
    float best = arr[0];
    int   idx  = 1;
    for (int k = 1; k < n; k++) {
        if (best >= arr[k]) {
            best = arr[k];
            idx  = k + 1;
        }
    }
    return idx;
}

/* ============================================================
 * 5. 主引擎（结构标注）  —— sub_10056190
 *    8173 条指令；145 次 fcompp；无 fadd/fsub/fmul/fdiv
 *
 *    ★ 第五批修正：本函数是「同一算法模板的 4 次内联展开」，
 *      共 24 处状态码写入点（4 组 × 卖4/5/6 + 买1/2/3）。
 *      4 组仅【临时迭代器槽位】与【数据容器】不同，代码完全一致。
 * ============================================================ */

void MainEngine(LevelObj* list)
{
    for (LevelObj* o = list; o != end(list); o++) {
        LevelObj* prev = o - 1;          /* lea ebx,[esi-0A0h] */

        /* ---- 触发门禁 ---- */

        /* 条件1: 相邻区间【不重叠】 —— 三种浮点比较组合 */
        /*   买入方向: prev->high < o->low      (test ah,1  + jne) */
        /*   卖出方向: prev->low  > o->high     (test ah,41h + jne) */
        int gap_up   = (prev->high <  o->low);    /* 低端不重叠 */
        int gap_down = (prev->low  >  o->high);   /* 高端不重叠 */

        /* 条件2: 该点方向未标记 */
        if (o->direction == 1 || o->direction == -1)
            continue;                    /* 已处理 → 跳过 */

        /* ---- 标注（对称两组，各 3 码）---- */

        if (gap_up) {
            /* 买入组: 取「后一顶点」(+0x08)，全用 HIGH (+0x10) */
            LevelObj* b = LookupByIndex(list, o->idx_next);
            b->status = ST_STRUCT_UP;    /* 1 */
            b->price  = b->high;
            b->status = ST_BUY;          /* 2 */  b->price = b->high;
            b->status = ST_STOPLOSS;     /* 3 */  b->price = b->high;
        }

        if (gap_down) {
            /* 卖出组: 取「前一顶点」(+0x04)，全用 LOW (+0x0C) */
            LevelObj* s = LookupByIndex(list, prev->idx_prev);
            s->status = ST_STRUCT_DOWN;  /* 4 */
            s->price  = s->low;
            s->status = ST_SELL;         /* 5 */  s->price = s->low;
            s->status = ST_TAKEPROFIT;   /* 6 */  s->price = s->low;
        }
    }
}

/* ============================================================
 * 5b. 4 组算法实例对照（第五批）
 * ============================================================
 *  实例   卖出段(4/5/6)                        买入段(1/2/3)
 *  ①    10057c20 / 10057c69 / 10057cf0       1005a1fa / 1005a243 / 1005a2ca
 *  ②    10058336 / 1005837f / 10058406       1005a85c / 1005a8a5 / 1005a92c
 *  ③    1005b737 / 1005b780 / 1005b807       1005bcd4 / 1005bd1d / 1005bda4
 *  ④    1005c47a / 1005c4c3 / 1005c54a       1005cae3 / 1005cb2c / 1005cbb3
 *
 *  分型标志写入: 0x10056710 → +0x88 = -1 (底); 0x10056760 → +0x88 = +1 (顶)
 *  由 +0x14 level_type 选择: ==1 取 +0x08; ==-1 取 +0x04
 */

/* ============================================================
 * 6. WNMRPRINEW  —— sub_1003a960
 *    int __stdcall(objList[eax], ctx[edx], count[ecx], out[[esp+34h]])
 *    注意: ret 4 (只有 1 个栈参数)
 * ============================================================ */

int WNMRPRINEW(LevelObj* objList, void* ctx, int count, double* out)
{
    if (ctx == NULL)
        return -1;

    if (count > 0)
        memset(out, 0, count * sizeof(double));

    if (!Authorize(ctx, 0xEA63))
        return -1;

    /* 同样先取快照（sub_1003f150），遍历后释放 */
    VectorLevelObj snapshot = VectorCopy(objList);      /* sub_1003f150 */

    for (LevelObj* o = snapshot._Myfirst; o != snapshot._Mylast; ++o) {
        int k = o->index - 1;
        out[k] = (double)o->price;       /* ★ +0x94 → VAR6 */
    }

    OperatorDelete(snapshot._Myfirst);   /* 0x1006b320 */
    return 1;
}

/* ============================================================
 * 7. 上游: CHBI  → 决定 +0x0C/+0x10/+0x20 的写入
 *    CalcProc_ChBi @ 0x1000f580 → sub_1002C1D0 → sub_1003DB40/…
 * ============================================================ */

/*
 * 输入: double[] 价格序列（步长 8 字节），降精度为 float 副本
 * P 参数映射（来自 cmp esi,xxh）:
 *   0x0B(11) → sub_1003F170(edi,1)   老笔
 *   0x0C(12) → sub_1003F170(edi,2)   新笔
 *   0x15(21) → sub_1004B1E0(edi,1)
 *   0x16(22) → sub_1004B1E0(edi,2)
 *   0x1F(31) → sub_1004F430(edi,1)
 *   0x20(32) → sub_1004F430(edi,2)
 *   0x33(51) → sub_1006A040(edi)     分型笔
 */

void CalcChBi(double* price_series, int n, int P, double* result)
{
    if (!Authorize(ctx, 0xEA62))      /* 注意 CHBI 授权码是 0xEA62 */
        return;

    LevelObj* obj = AllocLevelObj();

    /* 填基础字段 */
    obj->index = 1;
    obj->aux   = 0;
    memset(&obj->idx_prev, 0, 4);
    strlen_copy(&obj->field_14, ctx->field_0C + 4);

    /* 按 P 分发到不同分型算法 */
    switch (P) {
        case 11: BuildBi_v1(obj, 1); break;
        case 12: BuildBi_v1(obj, 2); break;
        case 51: BuildFenxingBi(obj); break;
        /* ... */
    }

    /* 产出级别对象序列 */
}

/*
 * 方向标注 —— sub_1003ef00
 * 关键证据:
 *   0x1003efe2: fld [edi+0Ch]            ; 读 LOW
 *   0x1003f01a: mov [ebx+20h],1          ; 目标对象方向 = +1 (上涨)
 *   0x1003f039: fld [edi+10h]            ; 读 HIGH
 *   0x1003f073: mov [ebx+20h],0FFFFFFFFh ; 目标对象方向 = -1 (下跌)
 */
void MarkDirection(LevelObj* src, LevelObj* table)
{
    /* 第一段: 上涨 */
    float low_val = src->low;                         /* +0x0C */
    LevelObj* t1 = LookupByIndex(table, src->idx_prev); /* +0x04 */
    t1->direction = 1;

    /* 第二段: 下跌 */
    float high_val = src->high;                       /* +0x10 */
    LevelObj* t2 = LookupByIndex(table, src->idx_next); /* +0x08 */
    t2->direction = -1;
}

/* ============================================================
 * 8. 完整信号链路（对照公式 WNMR_线段）
 * ============================================================
 *
 *   double[] 价格序列
 *        ↓ CalcChBi (P=11/12/51)
 *   笔端点对象: +0x0C(LOW) +0x10(HIGH) +0x20(方向)
 *        ↓ CHBI → ±1
 *   CHDUAN → 线段特征序列分型 (±1)
 *        ↓ WNMRNEW
 *   ┌ MarkSignalFlag  → +0x8C
 *   ├ MergeByFlag     → 保留 8C==1
 *   ├ MainEngine      → +0x90(状态1-6) +0x94(价格)
 *   └ 输出 VAR5 = [1,2,3,4,5,6] 序列
 *        ↓ WNMRPRINEW
 *   VAR6 = [价格序列]
 *
 *   公式消费:
 *     VAR5=2 → ' 买入价: ' + DRAWICON(L,1)
 *     VAR5=3 → ' 止损价：'
 *     VAR5=5 → ' 卖出价: ' + DRAWICON(H,2)
 *     VAR5=6 → ' 止赢价：'
 *     SELECT(COUNT(VAR5=2, M) >= 1)     ; 选中条件
 *     ALERT (COUNT(VAR5=2, M) >= 1, '无脑买入B')
 */
