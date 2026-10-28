# -*- coding: utf-8 -*-
r"""
函数级反汇编工具（InvalidByte 续扫模式）

capstone 线性 disasm 遇到无效字节会静默停止; 本工具在停止点跳 1 字节续扫,
直到函数边界: 连续 int3(0xCC)/nop 填充 或 撞到下一个函数的序.prologue。

用法: python disasm_func.py <start_va_hex> [-o out.txt] [--max 0x8000] [--dll <path>] [--fix-esp]
输出格式与 core_*.txt 一致: "地址  助记符  操作数"
默认 DLL = 缠中说禅\TAFLib.dll; 需要分析 chlib.dll 等其它模块时用 --dll 指定。

--fix-esp: 自动识别 push; call malloc/new; mov [esp+X],reg 序列并输出修正后的槽位表
           规则: add esp,4 之前的 [esp+X] 真实槽位 = X - 4 * (push 条数)
"""
import sys
import re

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_INS_INT3, X86_INS_NOP

DLL = r"D:\a_ronglide\缠中说禅\TAFLib.dll"

# 已知的 malloc/new 入口地址
MALLOC_TARGETS = {
    0x1006b34a,  # malloc
    0x1006b344,  # free
    0x1006b320,  # free
    0x1006b1c0,  # copy_a0
    0x1006b1f0,  # copy_28
    0x1006a4e0,  # iter_begin
    0x1003f0d0,  # iter_at
    0x1006bc70,  # ftol
    0x1006a680,  # operator->
    0x1006a6a0,
    0x1006a830,
    0x1006a860,
    0x1006a8e0,
    0x1006aa90,
    0x1006ad60,
    0x1006a930,  # grow
    0x1006a9e0,
    0x1003d720,  # iter_post_increment
}


def parse_esp_offset(op_str):
    """从操作数字符串解析 [esp+0xXX] 或 [esp+XX] 的偏移量"""
    # 匹配 [esp+0x44] [esp+0x14] 等格式
    m = re.search(r'\[esp\s*\+\s*(0x[0-9a-fA-F]+|\d+)\]', op_str)
    if m:
        val = m.group(1)
        return int(val, 16) if val.startswith('0x') else int(val)
    # 匹配 [esp-0xXX] 格式
    m = re.search(r'\[esp\s*-\s*(0x[0-9a-fA-F]+|\d+)\]', op_str)
    if m:
        val = m.group(1)
        return -int(val, 16) if val.startswith('0x') else -int(val)
    return None


def is_push_insn(insn):
    """判断是否为 push 指令"""
    return insn.mnemonic == 'push'


def is_call_malloc(insn):
    """判断是否为 call malloc/new 类函数"""
    if insn.mnemonic != 'call':
        return False
    # 解析 call 目标地址
    m = re.search(r'0x([0-9a-fA-F]+)', insn.op_str)
    if m:
        target = int(m.group(1), 16)
        return target in MALLOC_TARGETS
    return False


def is_mov_esp_store(insn):
    """判断是否为 mov [esp+X], reg 存储返回值"""
    if insn.mnemonic != 'mov':
        return False
    # 检查目的操作数是否为 [esp+X]
    # capstone 输出格式: "mov dword ptr [esp + 0x44], eax"
    return '[esp' in insn.op_str and ']' in insn.op_str.split(',')[0]


def find_matching_add_esp4(insns, start_idx):
    """从 start_idx 开始向后查找匹配的 add esp, 4"""
    for i in range(start_idx, len(insns)):
        ins = insns[i]
        if ins.mnemonic == 'add' and 'esp' in ins.op_str and ('4' in ins.op_str or '0x4' in ins.op_str):
            return i
    return None


def fix_esp_slots(insns):
    """
    扫描指令序列，找出 push; call malloc; mov [esp+X] 序列，
    计算修正后的槽位。
    返回: 列表 (mov_insn_idx, original_offset, corrected_offset, push_count, call_target)
    """
    results = []
    i = 0
    while i < len(insns) - 2:
        # 寻找 push
        if not is_push_insn(insns[i]):
            i += 1
            continue

        # 统计连续的 push 数量
        push_count = 0
        j = i
        while j < len(insns) and is_push_insn(insns[j]):
            push_count += 1
            j += 1

        # 下一条应该是 call
        if j >= len(insns) or not is_call_malloc(insns[j]):
            i += 1
            continue

        call_insn = insns[j]
        call_target = None
        m = re.search(r'0x([0-9a-fA-F]+)', call_insn.op_str)
        if m:
            call_target = int(m.group(1), 16)

        # 找 call 后的 add esp, 4 位置
        add_esp_idx = find_matching_add_esp4(insns, j + 1)

        # 在 call 和 add esp,4 之间找 mov [esp+X], reg
        search_end = add_esp_idx if add_esp_idx is not None else min(j + 10, len(insns))
        for k in range(j + 1, search_end):
            if k >= len(insns):
                break
            ins = insns[k]
            if is_mov_esp_store(ins):
                offset = parse_esp_offset(ins.op_str)
                if offset is not None:
                    # 修正：push 已让 esp 减 4，在 add esp,4 之前真实槽位 = X - 4*push_count
                    corrected = offset - 4 * push_count
                    results.append({
                        'mov_addr': ins.address,
                        'mov_insn': "%08x  %-8s %s" % (ins.address, ins.mnemonic, ins.op_str),
                        'original_offset': offset,
                        'corrected_offset': corrected,
                        'push_count': push_count,
                        'call_target': call_target,
                        'call_addr': call_insn.address,
                        'add_esp_addr': insns[add_esp_idx].address if add_esp_idx else None,
                    })
        i = j + 1

    return results


def main():
    import argparse
    parser = argparse.ArgumentParser(description="函数级反汇编工具")
    parser.add_argument("start_va", help="起始虚拟地址 (hex)")
    parser.add_argument("-o", "--output", help="输出文件")
    parser.add_argument("--max", type=lambda x: int(x, 16), default=0x8000, help="最大长度 (hex)")
    parser.add_argument("--dll", default=DLL, help="目标 DLL 路径")
    parser.add_argument("--fix-esp", action="store_true", help="自动修正 push;call;mov [esp+X] 槽位")
    args = parser.parse_args()

    start = int(args.start_va, 16)
    out = args.output
    max_len = args.max
    dll = args.dll
    fix_esp = args.fix_esp

    pe = pefile.PE(dll, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    sec = next(s for s in pe.sections if b".text" in s.Name)

    def va2off(va):
        return va - base - sec.VirtualAddress + sec.PointerToRawData

    md = Cs(CS_ARCH_X86, CS_MODE_32)

    # 存储指令对象用于后续分析
    insn_objects = []
    lines = []
    va = start
    end_va = None
    bad_skips = 0
    while va < start + max_len:
        code = pe.__data__[va2off(va): va2off(va) + 0x1000]
        got = list(md.disasm(code, va))
        if not got:
            bad_skips += 1
            va += 1
            continue
        stop = False
        for ins in got:
            # 边界: int3 填充 或 连续3条nop(对齐填充) 视为函数结束
            if ins.mnemonic == "int3":
                stop = True
                break
            line = "%08x  %-8s %s" % (ins.address, ins.mnemonic, ins.op_str)
            lines.append(line)
            insn_objects.append(ins)
        va = got[-1].address + got[-1].size
        if stop:
            end_va = va
            break
        if not got or got[-1].address + got[-1].size < va + len(code):
            bad_skips += 1
            va += 1

    text = "\n".join(lines)
    print(text)
    sys.stderr.write("\n[info] end≈%s  insns=%d  resync_skips=%d\n"
                     % (hex(end_va) if end_va else "?", len(lines), bad_skips))

    # --fix-esp 分析
    if fix_esp:
        fixes = fix_esp_slots(insn_objects)
        if fixes:
            sys.stderr.write("\n[fix-esp] 发现 %d 处 push;call;mov [esp+X] 序列:\n" % len(fixes))
            sys.stderr.write("%-12s  %-12s  %-12s  %-6s  %-10s  %s\n"
                             % ("MOV_ADDR", "ORIG_OFF", "CORR_OFF", "PUSH#", "CALL_TARGET", "MOV_INSN"))
            for f in fixes:
                call_str = "0x%08x" % f['call_target'] if f['call_target'] else "?"
                sys.stderr.write("%-12s  0x%-10x  0x%-10x  %-6d  %-10s  %s\n"
                                 % (hex(f['mov_addr']), f['original_offset'], f['corrected_offset'],
                                    f['push_count'], call_str, f['mov_insn']))

            # 汇总表：按 call_target 分组
            sys.stderr.write("\n[fix-esp] 按 call 目标汇总:\n")
            by_target = {}
            for f in fixes:
                t = f['call_target'] or 0
                by_target.setdefault(t, []).append(f)
            for t, lst in by_target.items():
                tstr = "0x%08x" % t if t else "unknown"
                sys.stderr.write("  %s: %d 处\n" % (tstr, len(lst)))
                for f in lst:
                    sys.stderr.write("    %s: [esp+0x%x] -> [esp+0x%x] (push#=%d)\n"
                                     % (hex(f['mov_addr']), f['original_offset'], f['corrected_offset'], f['push_count']))

    if out:
        with open(out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        sys.stderr.write("[info] written %s\n" % out)


if __name__ == "__main__":
    main()
