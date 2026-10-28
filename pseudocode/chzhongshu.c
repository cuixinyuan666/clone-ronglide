/* ChZhongShu 族第二批伪码（静态反汇编；原生数组对拍待做）
 * 证据：tools/re-inventory/chzhongshu/chlib_worker_*.txt
 *
 * m0 记录步长 0xA0；+0 为 1 基序号，+0x28 为类别/状态，
 * G 读 +0x50 float，D 读 +0x54 float。
 */

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t serial;       /* +0x00; output index = serial - 1 */
    uint8_t  _pad04[0x24];
    int32_t  kind;         /* +0x28; eligible values are 1..4 */
    uint8_t  _pad2c[0x24];
    float    high_value;   /* +0x50 */
    float    low_value;    /* +0x54 */
    uint8_t  _tail58[0x48];
} M0Record;

/* Common behavior of 0x1002cd00 (field=+0x50) and 0x1002cee0 (field=+0x54).
 * records is the deep snapshot returned through 0x1003f150.
 */
static int chzhongshu_extreme_series(
    size_t count,
    const M0Record *records,
    size_t record_count,
    double *out,
    int use_low)
{
    if (!records)
        return -1;

    for (size_t i = 0; i < count; ++i)
        out[i] = 0.0;

    size_t cursor = 0;
    double held = 0.0;
    for (size_t r = 0; r < record_count; ++r) {
        const M0Record *rec = &records[r];
        size_t index = rec->serial - 1; /* valid input is expected to be ordered */

        while (cursor < index && cursor < count)
            out[cursor++] = held;

        float candidate = use_low ? rec->low_value : rec->high_value;
        if (rec->kind >= 1 && rec->kind <= 4 && candidate > 0.0f)
            held = (double)candidate;

        if (cursor < count)
            out[cursor++] = held;
    }
    return 0;
}

/* 0x1002ca30 writes the category stream to out[serial-1]. It also calls
 * 0x10061920 with state->field0 and trunc(**input_holder) before snapshotting.
 * That helper's mutations are not modeled here; the function is intentionally
 * left as a contract sketch until its 4292-instruction body is resolved.
 */
static int chzhongshu_kind_series(
    size_t count,
    const M0Record *records,
    size_t record_count,
    double *out)
{
    if (!records)
        return -1;

    for (size_t i = 0; i < count; ++i)
        out[i] = 0.0;

    size_t cursor = 0;
    for (size_t r = 0; r < record_count; ++r) {
        size_t index = records[r].serial - 1;
        while (cursor < index && cursor < count)
            ++cursor; /* out was pre-zeroed; skipped positions stay zero */
        if (cursor < count)
            out[cursor++] = (double)records[r].kind;
    }
    return 0;
}
