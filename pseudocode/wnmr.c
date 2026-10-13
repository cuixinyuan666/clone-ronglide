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
#include <string.h>

/* ============================================================
 * 1. 数据结构
 * ============================================================ */

/* 级别对象（笔/线段端点），步长 0xA0 = 160 字节
 * 证据: 遍历循环 add ebp,0A0h; 魔数 0x66666667+sar6 = ÷160 */
typedef struct LevelObj {          /* size = 0xA0 */
    int32_t  index;                /* +0x00  自身序号 */
    int32_t  idx_prev;             /* +0x04  索引A: 前一顶点 */
    int32_t  idx_next;             /* +0x08  索引B: 后一顶点 */
    float    low;                  /* +0x0C  LOW  (卖出组价格源) */
    float    high;                 /* +0x10  HIGH (买入组价格源) */
    int32_t  aux_idx;              /* +0x14  辅助索引 */
    uint8_t  _pad0[0x20 - 0x18];
    int32_t  direction;            /* +0x20  方向: 1=上涨, -1=下跌, 0=未定 */
    uint8_t  _pad1[0x88 - 0x24];
    int32_t  fenxing;              /* +0x88  分型: 1=顶, -1=底 */
    int32_t  signal_flag;          /* +0x8C  信号标志: 0/1/-1 */
    int32_t  status;               /* +0x90  ★状态码: 1..6 */
    float    price;                /* +0x94  ★该点实际价格 */
    int32_t  special;              /* +0x98  特殊标志 */
} LevelObj;

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
    LevelObj* it = GetFirst(list);       /* sub_1003f150 */

    /* 2.4 提取状态码 +0x90 写入 out[] */
    for (LevelObj* o = it; o != GetEnd(list); o += 1 /*0xA0*/) {
        int k = o->index - 1;
        out[k] = (double)o->status;      /* ★ 状态码 → VAR5 */
    }

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
 * ============================================================ */

void MainEngine(LevelObj* list)
{
    for (LevelObj* o = list; o != end(list); o++) {
        LevelObj* prev = o - 1;          /* lea ebx,[esi-0A0h] */

        /* ---- 触发门禁 ---- */

        /* 条件1: 相邻区间价格不相等 (fcompp + test ah,5 + jnp) */
        int not_equal = (o->low != prev->high);   /* 买入方向判定 */

        /* 条件2: 该点方向未标记 */
        if (o->direction == 1 || o->direction == -1)
            continue;                    /* 已处理 → 跳过 */

        if (!not_equal)
            continue;

        /* ---- 标注（对称两组）---- */

        /* 买入组: 全用 HIGH (+0x10) */
        o->status = ST_BUY;              /* 状态 2 */
        o->price  = o->high;
        /* 止损同理取同区间 HIGH → ST_STOPLOSS(3) */

        /* 卖出组: 全用 LOW (+0x0C) */
        if (o->high != prev->low) {
            o->status = ST_SELL;         /* 状态 5 */
            o->price  = o->low;
            /* 止盈同理取同区间 LOW → ST_TAKEPROFIT(6) */
        }
    }
}

/* ============================================================
 * 6. WNMRPRINEW  —— sub_1003a960
 *    int __stdcall(objList /*eax*/, ctx /*edx*/, count /*ecx*/, out /*[esp+34h]*/)
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

    LevelObj* first = GetFirst(objList);

    for (LevelObj* o = first; o != end(objList); o++) {
        int k = o->index - 1;
        out[k] = (double)o->price;       /* ★ +0x94 → VAR6 */
    }
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
