#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""别名感知写入分析：
   跟踪 lea reg,[esp+D] -> 该 reg 的帧偏移，并据此解析 mov [reg+off],X 的写入目标。
   另跟踪 mov reg,[esp+D] 的指针载入（一级解引用不展开，仅记录来源）。
"""
import sys, os
from collections import defaultdict
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import trace_fixed as tf
from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_OP_IMM, X86_REG_ESP

START, END, FRET = 0x10056190, 0x1005cc00, 4

def reg_name(ins, rid):
    try:
        return ins.reg_name(rid)
    except Exception:
        return str(rid)

def analyze():
    rows, exits = tf.trace(START, END, FRET)
    # 需要完整 insn 对象 -> 重新解码（仅目标函数）
    md = tf.md
    lo = START - tf.TSTART
    hi = END - tf.TSTART
    seq = list(md.disasm(tf.code[lo:hi], START))
    seq = [i for i in seq if i.id != 0]

    frame_writes = defaultdict(list)   # frame_offset -> [(va, text)]
    lea_sites = defaultdict(list)      # frame_offset -> [(va, reg)]

    regmap = {}      # regname -> frame_offset (经 lea 建立)
    def kill(ins):
        # 任何写寄存器的指令都使映射失效
        for op in ins.operands:
            if op.type == X86_OP_REG and op.access & 2:   # write
                regmap.pop(reg_name(ins, op.reg), None)

    prev_was_branch = True
    for ins in seq:
        mn, ops = ins.mnemonic, ins.op_str
        # 分支/调用后清空映射（跨基本块不可靠）
        if prev_was_branch:
            regmap.clear()
        # 1) lea reg,[esp+D]
        if mn == 'lea' and len(ins.operands) == 2 \
                and ins.operands[0].type == X86_OP_REG \
                and ins.operands[1].type == X86_OP_MEM \
                and ins.operands[1].mem.base == X86_REG_ESP:
            d = ins.operands[1].mem.disp
            rn = reg_name(ins, ins.operands[0].reg)
            regmap[rn] = d            # 相对 esp；帧偏移 = d + delta
            lea_sites[d].append((ins.address, rn))
        # 2) mov [reg+off], X   —— 经别名写入
        elif mn in ('mov','add','sub','or','and','xor') and ins.operands \
                and ins.operands[0].type == X86_OP_MEM \
                and ins.operands[0].mem.base != 0 \
                and ins.operands[0].mem.base != X86_REG_ESP:
            rn = reg_name(ins, ins.operands[0].mem.base)
            if rn in regmap:
                fo = regmap[rn] + ins.operands[0].mem.disp
                frame_writes[fo].append((ins.address, mn + ' ' + ops))
        kill(ins)
        prev_was_branch = (mn.startswith('j') or mn in ('call','ret','int3'))
    return frame_writes, lea_sites

if __name__ == '__main__':
    fw, ls = analyze()
    print("=== 经别名（lea + [reg+off]）可解析的写入，按帧偏移 ===")
    for fo in sorted(fw):
        print("  [E%+d]  %d 处: %s" % (fo, len(fw[fo]),
              ' '.join('0x%x' % v for v, _ in fw[fo][:8])))
    print()
    for key in (-1016, -1012, -1000, -996, -976, -972, -1064, -1060):
        print("  [E%+d] 别名写入: %s" % (key, [hex(v) for v, _ in fw.get(key, [])]))
