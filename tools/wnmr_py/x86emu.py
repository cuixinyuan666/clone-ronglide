"""x86emu.py - minimal 32-bit x86/x87 interpreter for the CHBI P=51 evidence set.

Executes disassembly listings exported from TAFLib.dll (tools/re-inventory/chbi/*.txt)
so the faithful CHBI 0x1002c4b0 / 0x1002c1d0 pipeline can be run offline.

Not a general emulator: only the instruction subset present in the evidence files
is implemented, with hooks for library helpers that were not exported.
"""
import re
import struct
import sys

MASK32 = 0xFFFFFFFF
PAGE_SIZE = 0x1000
SENTINEL = 0x0000DEAD

# hooks (addresses that are dispatched to Python instead of code)
HOOK_ASSERT = 0xDEADF194      # value stored at 0x1006f194 (invalid-parameter trap)
HOOK_MALLOC = 0x1006B34A      # void* malloc(size_t) cdecl
HOOK_FREE1 = 0x1006B344       # no-op deallocator (cdecl)
HOOK_FREE2 = 0x1006B320       # no-op deallocator (cdecl)
HOOK_FTOL = 0x1006BC70        # int _ftol(void): ST0 -> eax (truncate), pop
HOOK_ITER_BEGIN = 0x1006A4E0  # iterator begin: ecx=container, esi=slot -> {c,begin,end}
HOOK_CPY_A0 = 0x1006B1C0      # copy 0xA0 bytes ebx->eax (push_back m0 slow-path copy)
HOOK_CPY_28 = 0x1006B1F0      # copy 0x28 bytes ebx->eax (push_back rec slow-path copy)
HOOK_AUTH = 0xEA62C001        # iface vtbl[1] gate for formula 0xea62 (thiscall, arg on stack)
HOOK_ITER_AT = 0x1003F0D0      # iterator-at-n: ebx=container, esi=slot, [esp+4]=n, ret 4

R32N = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
R32 = {n: i for i, n in enumerate(R32N)}
R8N = {"al": ("eax", 0), "cl": ("ecx", 0), "dl": ("edx", 0), "bl": ("ebx", 0),
       "ah": ("eax", 8), "ch": ("ecx", 8), "dh": ("edx", 8), "bh": ("ebx", 8)}
R16N = {"ax": "eax", "cx": "ecx", "dx": "edx", "bx": "ebx",
        "sp": "esp", "bp": "ebp", "si": "esi", "di": "edi"}


class EmuError(Exception):
    pass


class Halt(EmuError):
    def __init__(self, eax):
        super().__init__("halt eax=0x%08x" % (eax & MASK32))
        self.eax = eax & MASK32


class AssertHit(EmuError):
    def __init__(self, caller_pc):
        super().__init__("invalid-parameter trap, caller pc=0x%08x" % caller_pc)
        self.caller_pc = caller_pc


class UnknownCall(EmuError):
    def __init__(self, target, caller_pc):
        super().__init__("call to unknown target 0x%08x from 0x%08x" % (target, caller_pc))
        self.target = target
        self.caller_pc = caller_pc


class UnknownInsn(EmuError):
    pass


class Memory:
    """Sparse paged memory. Unwritten bytes read as zero."""

    def __init__(self):
        self.pages = {}

    def rd_bytes(self, addr, n):
        addr &= MASK32
        out = bytearray(n)
        pos = 0
        while n > 0:
            p = addr >> 12
            off = addr & 0xFFF
            chunk = min(n, PAGE_SIZE - off)
            pg = self.pages.get(p)
            if pg is not None:
                out[pos:pos + chunk] = pg[off:off + chunk]
            addr += chunk
            n -= chunk
            pos += chunk
        return bytes(out)

    def wr_bytes(self, addr, data):
        addr &= MASK32
        pos = 0
        n = len(data)
        while n > 0:
            p = addr >> 12
            off = addr & 0xFFF
            chunk = min(n, PAGE_SIZE - off)
            pg = self.pages.get(p)
            if pg is None:
                pg = bytearray(PAGE_SIZE)
                self.pages[p] = pg
            pg[off:off + chunk] = data[pos:pos + chunk]
            addr += chunk
            n -= chunk
            pos += chunk

    def rd32(self, addr):
        addr &= MASK32
        pg = self.pages.get(addr >> 12)
        if pg is None:
            return 0
        off = addr & 0xFFF
        if off < PAGE_SIZE - 3:
            return pg[off] | (pg[off + 1] << 8) | (pg[off + 2] << 16) | (pg[off + 3] << 24)
        return int.from_bytes(self.rd_bytes(addr, 4), "little")

    def wr32(self, addr, val):
        addr &= MASK32
        p = addr >> 12
        pg = self.pages.get(p)
        if pg is None:
            pg = bytearray(PAGE_SIZE)
            self.pages[p] = pg
        off = addr & 0xFFF
        if off < PAGE_SIZE - 3:
            pg[off] = val & 0xFF
            pg[off + 1] = (val >> 8) & 0xFF
            pg[off + 2] = (val >> 16) & 0xFF
            pg[off + 3] = (val >> 24) & 0xFF
        else:
            self.wr_bytes(addr, (val & MASK32).to_bytes(4, "little"))

    def copy(self, dest, src, n):
        self.wr_bytes(dest, self.rd_bytes(src, n))


def _parse_mem(s):
    size = None
    t = s.strip()
    m = re.match(r"^(byte|word|dword|qword)\s+ptr\s+(.*)$", t)
    if m:
        size = {"byte": 1, "word": 2, "dword": 4, "qword": 8}[m.group(1)]
        t = m.group(2).strip()
    if "[" not in t or "]" not in t:
        raise UnknownInsn("bad memory operand: %r" % s)
    inner = t[t.index("[") + 1:t.rindex("]")].replace(" ", "")
    base = index = None
    scale = 1
    disp = 0
    for term in inner.replace("-", "+-").split("+"):
        if not term:
            continue
        if "*" in term:
            reg, sc = term.split("*", 1)
            if reg not in R32:
                raise UnknownInsn("bad index reg: %r" % term)
            index = R32[reg]
            scale = int(sc, 0)
        elif term in R32:
            if base is None:
                base = R32[term]
            else:
                index = R32[term]
        else:
            disp += int(term, 0)
    return ("m", base, index, scale, disp & MASK32, size)


def _parse_operand(s):
    s = s.strip()
    if not s:
        return None
    if s.startswith("st(") and s.endswith(")"):
        return ("st", int(s[3:-1]))
    if s == "st":
        return ("st", 0)
    if "[" in s:
        return _parse_mem(s)
    if s in R32:
        return ("r", R32[s])
    if s in R8N:
        return ("r8", s)
    if s in R16N:
        return ("r16", s)
    return ("i", int(s, 0))

LINE_RE = re.compile(r"^([0-9a-f]{8})\s+([a-z][a-z0-9]*)\s*(.*?)\s*$")

JCC = {
    "ja": lambda e: (not e.CF) and (not e.ZF),
    "jae": lambda e: not e.CF,
    "jb": lambda e: e.CF,
    "jbe": lambda e: e.CF or e.ZF,
    "je": lambda e: e.ZF,
    "jz": lambda e: e.ZF,
    "jne": lambda e: not e.ZF,
    "jnz": lambda e: not e.ZF,
    "jg": lambda e: (not e.ZF) and (e.SF == e.OF),
    "jge": lambda e: e.SF == e.OF,
    "jl": lambda e: e.SF != e.OF,
    "jle": lambda e: e.ZF or (e.SF != e.OF),
    "jp": lambda e: e.PF,
    "jnp": lambda e: not e.PF,
    "js": lambda e: e.SF,
    "jns": lambda e: not e.SF,
}

# decoded instruction kinds
MOV = "mov"; ADD = "add"; SUB = "sub"; CMP = "cmp"; AND = "and"; OR = "or"
XOR = "xor"; TEST = "test"; NEG = "neg"; IMUL1 = "imul1"; IMUL = "imul"
MUL = "mul"; LEA = "lea"; PUSH = "push"; POP = "pop"; CALL = "call"
RET = "ret"; JMP = "jmp"; SETO = "seto"; SHL = "shl"; SHR = "shr"; SAR = "sar"
NOP = "nop"; INT3 = "int3"; REP_MOVSD = "rep_movsd"; REP_STOSD = "rep_stosd"
FLD = "fld"; FST = "fst"; FSTP = "fstp"; FADD = "fadd"; FSUB = "fsub"
FSUBR = "fsubr"; FCOM = "fcom"; FCOMP = "fcomp"; FCOMPP = "fcompp"
FUCOMP = "fucomp"; FXCH = "fxch"; FNSTSW = "fnstsw"; FLDZ = "fldz"; FILD = "fild"
FLD1 = "fld1"; FUCOMPP = "fucompp"; SETNE = "setne"


class Emu:
    def __init__(self):
        self.mem = Memory()
        self.r = [0, 0, 0, 0, 0, 0, 0, 0]  # eax ecx edx ebx esp ebp esi edi
        self.CF = self.ZF = self.SF = self.OF = self.PF = False
        self.st = []          # x87 stack, top at end
        self.xc0 = self.xc1 = self.xc2 = self.xc3 = 0
        self.code = {}        # addr -> (mnemonic, operand-text)
        self.next_addr = {}   # addr -> fall-through addr (next line in same file)
        self.dec = {}         # addr -> decoded tuple
        self.pc = 0
        self.heap = 0x60000000
        self.hooks = {}
        self.steps = 0
        self.auth_ok = 1      # EA62 gate return value
        self.assert_count = 0
        self.malloc_log = []
        self._install_hooks()

    # ---- memory helpers -------------------------------------------------
    def rd8(self, a):
        pg = self.mem.pages.get((a & MASK32) >> 12)
        return 0 if pg is None else pg[(a & MASK32) & 0xFFF]

    def wr8(self, a, v):
        self.mem.wr_bytes(a & MASK32, bytes((v & 0xFF,)))

    def rd16(self, a):
        return int.from_bytes(self.mem.rd_bytes(a & MASK32, 2), "little")

    def wr16(self, a, v):
        self.mem.wr_bytes(a & MASK32, (v & 0xFFFF).to_bytes(2, "little"))

    def rd32(self, a):
        return self.mem.rd32(a)

    def wr32(self, a, v):
        self.mem.wr32(a, v & MASK32)

    def read_bytes(self, a, n):
        return self.mem.rd_bytes(a, n)

    def write_bytes(self, a, data):
        self.mem.wr_bytes(a, data)

    # ---- allocator ------------------------------------------------------
    def alloc(self, n):
        n = (int(n) + 15) & ~15
        p = self.heap
        self.heap += n
        self.malloc_log.append((p, n))
        return p

    # ---- code loading ---------------------------------------------------
    def load_dis_file(self, path):
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            prev = None
            count = 0
            for raw in fh:
                line = raw.strip()
                if not line:
                    continue
                m = LINE_RE.match(line)
                if not m:
                    raise UnknownInsn("cannot parse line in %s: %r" % (path, line))
                addr = int(m.group(1), 16)
                self.code[addr] = (m.group(2), m.group(3))
                if prev is not None:
                    self.next_addr[prev] = addr
                prev = addr
                count += 1
            if prev is not None:
                self.next_addr[prev] = None
            return count

    def load_evidence_dir(self, dirpath, names):
        total = 0
        for name in names:
            total += self.load_dis_file(dirpath + "/" + name)
        return total

    # ---- decode ---------------------------------------------------------
    def decode(self, pc):
        d = self.dec.get(pc)
        if d is not None:
            return d
        e = self.code.get(pc)
        if e is None:
            raise UnknownInsn("no instruction at 0x%08x" % pc)
        d = parse_insn(e[0], e[1])
        self.dec[pc] = d
        return d

    # ---- operand access -------------------------------------------------
    def eff_addr(self, op):
        _, base, index, scale, disp, _sz = op
        a = disp
        if base is not None:
            a += self.r[base]
        if index is not None:
            a += self.r[index] * scale
        return a & MASK32

    def op_size(self, op):
        if op[0] == "r8":
            return 1
        if op[0] == "r16":
            return 2
        if op[0] == "m":
            return op[5] if op[5] is not None else 4
        return 4

    def read_op(self, op):
        t = op[0]
        if t == "r":
            return self.r[op[1]]
        if t == "r8":
            reg, shift = R8N[op[1]]
            return (self.r[R32[reg]] >> shift) & 0xFF
        if t == "r16":
            return self.r[R32[R16N[op[1]]]] & 0xFFFF
        if t == "i":
            return op[1] & MASK32
        if t == "st":
            return None
        if t == "m":
            sz = op[5] if op[5] is not None else 4
            a = self.eff_addr(op)
            if sz == 1:
                return self.rd8(a)
            if sz == 2:
                return self.rd16(a)
            if sz == 4:
                return self.rd32(a)
            if sz == 8:
                return int.from_bytes(self.mem.rd_bytes(a, 8), "little")
            raise UnknownInsn("unsupported mem size %d" % sz)
        raise UnknownInsn("bad operand %r" % (op,))

    def write_op(self, op, val):
        t = op[0]
        if t == "r":
            self.r[op[1]] = val & MASK32
            return
        if t == "r8":
            reg, shift = R8N[op[1]]
            code = R32[reg]
            self.r[code] = (self.r[code] & ~(0xFF << shift)) | ((val & 0xFF) << shift)
            return
        if t == "r16":
            code = R32[R16N[op[1]]]
            self.r[code] = (self.r[code] & 0xFFFF0000) | (val & 0xFFFF)
            return
        if t == "m":
            sz = op[5] if op[5] is not None else 4
            a = self.eff_addr(op)
            if sz == 1:
                self.wr8(a, val)
            elif sz == 2:
                self.wr16(a, val)
            elif sz == 4:
                self.wr32(a, val)
            elif sz == 8:
                self.mem.wr_bytes(a, (val & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little"))
            else:
                raise UnknownInsn("unsupported mem size %d" % sz)
            return
        raise UnknownInsn("cannot write %r" % (op,))

    # ---- flags ----------------------------------------------------------
    def flags_logic(self, res):
        self.CF = False
        self.OF = False
        self.ZF = (res & MASK32) == 0
        self.SF = bool(res & 0x80000000)
        self.PF = bin(res & 0xFF).count("1") % 2 == 0

    def flags_add(self, a, b, res):
        self.CF = res > MASK32
        self.ZF = (res & MASK32) == 0
        self.SF = bool(res & 0x80000000)
        self.OF = ((a ^ res) & (b ^ res) & 0x80000000) != 0
        self.PF = bin(res & 0xFF).count("1") % 2 == 0

    def flags_sub(self, a, b, res):
        self.CF = a < b
        self.ZF = (res & MASK32) == 0
        self.SF = bool(res & 0x80000000)
        self.OF = ((a ^ b) & (a ^ res) & 0x80000000) != 0
        self.PF = bin(res & 0xFF).count("1") % 2 == 0

    # ---- stack ----------------------------------------------------------
    def push(self, v):
        self.r[4] = (self.r[4] - 4) & MASK32
        self.wr32(self.r[4], v)

    def pop(self):
        v = self.rd32(self.r[4])
        self.r[4] = (self.r[4] + 4) & MASK32
        return v

    # ---- x87 ------------------------------------------------------------
    def f_read(self, op):
        t = op[0]
        if t == "st":
            return self.st[-1 - op[1]]
        if t == "m":
            sz = op[5]
            a = self.eff_addr(op)
            if sz == 4:
                return struct.unpack("<f", self.mem.rd_bytes(a, 4))[0]
            if sz == 8:
                return struct.unpack("<d", self.mem.rd_bytes(a, 8))[0]
            raise UnknownInsn("x87 mem load size %r" % sz)
        raise UnknownInsn("x87 bad operand %r" % (op,))

    def f_write(self, op, val):
        t = op[0]
        if t == "m":
            sz = op[5]
            a = self.eff_addr(op)
            if sz == 4:
                self.mem.wr_bytes(a, struct.pack("<f", val))
            elif sz == 8:
                self.mem.wr_bytes(a, struct.pack("<d", val))
            else:
                raise UnknownInsn("x87 mem store size %r" % sz)
            return
        raise UnknownInsn("x87 bad store %r" % (op,))

    def f_cmp(self, b):
        a = self.st[-1]
        if a != a or b != b:  # NaN -> unordered
            self.xc3, self.xc2, self.xc0 = 1, 1, 1
        elif a > b:
            self.xc3, self.xc2, self.xc0 = 0, 0, 0
        elif a < b:
            self.xc3, self.xc2, self.xc0 = 0, 0, 1
        else:
            self.xc3, self.xc2, self.xc0 = 1, 0, 0
        self.xc1 = 0

    def f_status_word(self):
        return (self.xc0 << 8) | (self.xc1 << 9) | (self.xc2 << 10) | (self.xc3 << 14)

    # ---- hooks ----------------------------------------------------------
    def _install_hooks(self):
        self.hooks[HOOK_ASSERT] = h_assert
        self.hooks[HOOK_MALLOC] = h_malloc
        self.hooks[HOOK_FREE1] = h_free
        self.hooks[HOOK_FREE2] = h_free
        self.hooks[HOOK_FTOL] = h_ftol
        self.hooks[HOOK_ITER_BEGIN] = h_iter_begin
        self.hooks[HOOK_CPY_A0] = h_copy_a0
        self.hooks[HOOK_CPY_28] = h_copy_28
        self.hooks[HOOK_AUTH] = h_auth
        self.hooks[HOOK_ITER_AT] = h_iter_at

FPU_KINDS = frozenset((FLD, FST, FSTP, FADD, FSUB, FSUBR, FCOM, FCOMP,
                       FCOMPP, FUCOMP, FUCOMPP, FXCH, FNSTSW, FLDZ, FLD1, FILD))


def parse_insn(mn, ops):
    ops = ops.strip()
    if mn == "rep":
        if ops.startswith("stosd"):
            return (REP_STOSD,)
        if ops.startswith("movsd"):
            return (REP_MOVSD,)
        raise UnknownInsn("unsupported rep form: %r" % ops)
    if mn == "nop":
        return (NOP,)
    if mn == "int3":
        return (INT3,)
    if mn == "fldz":
        return (FLDZ,)
    if mn == "fld1":
        return (FLD1,)
    if mn == "fcompp":
        return (FCOMPP,)
    if mn == "fucompp":
        return (FUCOMPP,)
    if mn == "setne":
        return (SETNE, _parse_operand(ops))
    if mn == "ret":
        return (RET, None) if not ops else (RET, int(ops, 0) & MASK32)
    if mn == "fnstsw":
        return (FNSTSW, _parse_operand(ops))
    if mn in JCC:
        return (mn, _parse_operand(ops)[1] & MASK32)
    if mn == "jmp":
        return (JMP, _parse_operand(ops))
    if mn == "fxch":
        return (FXCH, _parse_operand(ops) if ops else ("st", 1))
    if mn in ("mov", "add", "sub", "cmp", "and", "or", "xor", "test"):
        parts = [p.strip() for p in ops.split(",")]
        if len(parts) != 2:
            raise UnknownInsn("%s with %d operands: %r" % (mn, len(parts), ops))
        return (mn, _parse_operand(parts[0]), _parse_operand(parts[1]))
    if mn == "lea":
        parts = [p.strip() for p in ops.split(",")]
        return (LEA, _parse_operand(parts[0]), _parse_operand(parts[1]))
    if mn in ("push", "pop", "neg", "seto", "mul", "call"):
        return (mn, _parse_operand(ops))
    if mn == "imul":
        parts = [p.strip() for p in ops.split(",") if p.strip()]
        if len(parts) == 1:
            return (IMUL1, _parse_operand(parts[0]))
        if len(parts) == 2:
            return (IMUL, _parse_operand(parts[0]), _parse_operand(parts[1]), None)
        if len(parts) == 3:
            return (IMUL, _parse_operand(parts[0]), _parse_operand(parts[1]),
                    _parse_operand(parts[2]))
        raise UnknownInsn("imul with %d operands" % len(parts))
    if mn in ("shl", "shr", "sar", "sal"):
        parts = [p.strip() for p in ops.split(",")]
        kind = SHL if mn == "sal" else mn
        return (kind, _parse_operand(parts[0]), _parse_operand(parts[1]))
    if mn in ("fld", "fst", "fstp", "fild", "fcom", "fcomp", "fucomp"):
        return (mn, _parse_operand(ops))
    if mn in ("fadd", "fsub", "fsubr"):
        parts = [p.strip() for p in ops.split(",") if p.strip()]
        if len(parts) == 2:
            return (mn, _parse_operand(parts[0]), _parse_operand(parts[1]))
        return (mn, _parse_operand(parts[0]), None)
    raise UnknownInsn("unsupported mnemonic %r (ops=%r)" % (mn, ops))


def _sx32(v):
    v &= MASK32
    return v - (1 << 32) if v & 0x80000000 else v


class Runner:
    pass


def run(emu, max_steps=500000000):
    r = emu.r
    while True:
        emu.steps += 1
        if emu.steps > max_steps:
            raise EmuError("step limit %d exceeded at 0x%08x" % (max_steps, emu.pc))
        ins = emu.decode(emu.pc)
        if ins[0] in FPU_KINDS:
            exec_fpu(emu, ins)
        else:
            exec_int(emu, ins)


def exec_int(emu, ins):
    kind = ins[0]
    pc = emu.pc
    nxt = emu.next_addr.get(pc)
    r = emu.r
    mem = emu.mem

    if kind == MOV:
        val = emu.read_op(ins[2])
        emu.write_op(ins[1], val)
        emu.pc = nxt

    elif kind == ADD:
        a = emu.read_op(ins[1])
        b = emu.read_op(ins[2])
        res = a + b
        emu.write_op(ins[1], res)
        emu.flags_add(a, b, res)
        emu.pc = nxt

    elif kind == SUB:
        a = emu.read_op(ins[1])
        b = emu.read_op(ins[2])
        res = a - b
        emu.write_op(ins[1], res)
        emu.flags_sub(a, b, res)
        emu.pc = nxt

    elif kind == CMP:
        a = emu.read_op(ins[1])
        b = emu.read_op(ins[2])
        emu.flags_sub(a, b, a - b)
        emu.pc = nxt

    elif kind in (AND, OR, XOR, TEST):
        a = emu.read_op(ins[1])
        b = emu.read_op(ins[2])
        if kind == AND or kind == TEST:
            res = a & b
        elif kind == OR:
            res = a | b
        else:
            res = a ^ b
        if kind != TEST:
            emu.write_op(ins[1], res)
        emu.flags_logic(res & MASK32)
        emu.pc = nxt

    elif kind == NEG:
        a = emu.read_op(ins[1])
        res = 0 - a
        emu.write_op(ins[1], res)
        emu.flags_sub(0, a, res)
        emu.pc = nxt

    elif kind == IMUL1:
        src = _sx32(emu.read_op(ins[1]))
        prod = _sx32(r[0]) * src
        r[2] = (prod >> 32) & MASK32
        r[0] = prod & MASK32
        ovf = prod != _sx32(r[0])
        emu.CF = emu.OF = ovf
        emu.pc = nxt

    elif kind == IMUL:
        a = _sx32(emu.read_op(ins[2]))
        b = _sx32(emu.read_op(ins[3]))
        prod = a * b
        emu.write_op(ins[1], prod)
        ovf = prod != _sx32(prod)
        emu.CF = emu.OF = ovf
        emu.pc = nxt

    elif kind == MUL:
        src = emu.read_op(ins[1]) & MASK32
        prod = (r[0] & MASK32) * src
        r[2] = (prod >> 32) & MASK32
        r[0] = prod & MASK32
        emu.CF = emu.OF = (r[2] != 0)
        emu.pc = nxt

    elif kind == LEA:
        emu.write_op(ins[1], emu.eff_addr(ins[2]))
        emu.pc = nxt

    elif kind == PUSH:
        emu.push(emu.read_op(ins[1]))
        emu.pc = nxt

    elif kind == POP:
        emu.write_op(ins[1], emu.pop())
        emu.pc = nxt

    elif kind == SETO:
        emu.write_op(ins[1], 1 if emu.OF else 0)
        emu.pc = nxt

    elif kind == SETNE:
        emu.write_op(ins[1], 0 if emu.ZF else 1)
        emu.pc = nxt

    elif kind in (SHL, SHR, SAR):
        a = emu.read_op(ins[1]) & MASK32
        c = emu.read_op(ins[2]) & 0xFF
        if c:
            if kind == SHL:
                shifted = (a << c) & 0xFFFFFFFFFFFFFFFF
                emu.CF = bool((shifted >> 32) & 1)
                res = shifted & MASK32
            elif kind == SHR:
                emu.CF = bool((a >> (c - 1)) & 1)
                res = a >> c
            else:
                s = _sx32(a)
                emu.CF = bool((s >> (c - 1)) & 1)
                res = s >> c
            emu.ZF = (res & MASK32) == 0
            emu.SF = bool(res & 0x80000000)
            emu.PF = bin(res & 0xFF).count("1") % 2 == 0
            emu.write_op(ins[1], res)
        emu.pc = nxt

    elif kind == CALL:
        op = ins[1]
        t = op[0]
        if t == "i":
            target = op[1] & MASK32
        elif t == "r":
            target = r[op[1]]
        elif t == "m":
            target = emu.rd32(emu.eff_addr(op))
        else:
            raise UnknownInsn("bad call operand %r" % (op,))
        hk = emu.hooks.get(target)
        if hk is not None:
            emu.push(nxt)
            emu.pc = target
            hk(emu)
        elif target in emu.code:
            emu.push(nxt)
            emu.pc = target
        else:
            raise UnknownCall(target, pc)

    elif kind == RET:
        addr = emu.pop()
        if ins[1] is not None:
            r[4] = (r[4] + ins[1]) & MASK32
        if addr == SENTINEL:
            raise Halt(r[0])
        emu.pc = addr

    elif kind == JMP:
        emu.pc = emu.read_op(ins[1])

    elif kind in JCC:
        if JCC[kind](emu):
            emu.pc = ins[1]
        else:
            emu.pc = nxt

    elif kind == NOP:
        emu.pc = nxt

    elif kind == INT3:
        raise EmuError("int3 executed at 0x%08x" % pc)

    elif kind == REP_MOVSD:
        ecx = r[1]
        esi = r[6]
        edi = r[7]
        while ecx:
            emu.wr32(edi, emu.rd32(esi))
            esi = (esi + 4) & MASK32
            edi = (edi + 4) & MASK32
            ecx -= 1
        r[1] = ecx
        r[6] = esi
        r[7] = edi
        emu.pc = nxt

    elif kind == REP_STOSD:
        ecx = r[1]
        edi = r[7]
        val = r[0]
        while ecx:
            emu.wr32(edi, val)
            edi = (edi + 4) & MASK32
            ecx -= 1
        r[1] = ecx
        r[7] = edi
        emu.pc = nxt

    else:
        raise UnknownInsn("unhandled kind %r at 0x%08x" % (kind, pc))

def exec_fpu(emu, ins):
    kind = ins[0]
    pc = emu.pc
    nxt = emu.next_addr.get(pc)
    st = emu.st

    if kind == FLD:
        st.append(emu.f_read(ins[1]))
    elif kind == FILD:
        op = ins[1]
        sz = op[5]
        a = emu.eff_addr(op)
        raw = int.from_bytes(emu.mem.rd_bytes(a, sz), "little")
        if sz == 4 and raw & 0x80000000:
            raw -= 1 << 32
        elif sz == 2 and raw & 0x8000:
            raw -= 1 << 16
        st.append(float(raw))
    elif kind == FLDZ:
        st.append(0.0)
    elif kind == FLD1:
        st.append(1.0)
    elif kind == FST:
        v = st[-1]
        if ins[1][0] == "st":
            st[-1 - ins[1][1]] = v
        else:
            emu.f_write(ins[1], v)
    elif kind == FSTP:
        v = st[-1]
        if ins[1][0] == "st":
            i = ins[1][1]
            if i:
                st[-1 - i] = v
            st.pop()
        else:
            emu.f_write(ins[1], v)
            st.pop()
    elif kind == FADD:
        if ins[2] is not None:
            st[-1 - ins[1][1]] = st[-1 - ins[1][1]] + st[-1 - ins[2][1]]
        else:
            op = ins[1]
            v = st[-1 - op[1]] if op[0] == "st" else emu.f_read(op)
            st[-1] = st[-1] + v
    elif kind == FSUB:
        if ins[2] is not None:
            st[-1 - ins[1][1]] = st[-1 - ins[1][1]] - st[-1 - ins[2][1]]
        else:
            op = ins[1]
            v = st[-1 - op[1]] if op[0] == "st" else emu.f_read(op)
            st[-1] = st[-1] - v
    elif kind == FSUBR:
        if ins[2] is not None:
            st[-1 - ins[1][1]] = st[-1 - ins[2][1]] - st[-1 - ins[1][1]]
        else:
            op = ins[1]
            v = st[-1 - op[1]] if op[0] == "st" else emu.f_read(op)
            st[-1] = v - st[-1]
    elif kind == FCOM:
        emu.f_cmp(emu.f_read(ins[1]))
    elif kind == FCOMP:
        emu.f_cmp(emu.f_read(ins[1]))
        st.pop()
    elif kind == FUCOMP:
        emu.f_cmp(emu.f_read(ins[1]))
        st.pop()
    elif kind == FCOMPP:
        emu.f_cmp(st[-2])
        st.pop()
        st.pop()
    elif kind == FUCOMPP:
        emu.f_cmp(st[-2])
        st.pop()
        st.pop()
    elif kind == FXCH:
        i = ins[1][1]
        if i:
            st[-1], st[-1 - i] = st[-1 - i], st[-1]
    elif kind == FNSTSW:
        emu.write_op(ins[1], emu.f_status_word())
    else:
        raise UnknownInsn("unhandled fpu kind %r at 0x%08x" % (kind, pc))
    emu.pc = nxt


# ---- library hooks -------------------------------------------------------

def h_assert(emu):
    emu.assert_count += 1
    caller = emu.rd32(emu.r[4])
    raise AssertHit(caller)


def h_malloc(emu):
    ret = emu.pop()
    n = emu.rd32(emu.r[4])
    emu.r[0] = emu.alloc(n)
    emu.pc = ret


def h_free(emu):
    emu.pc = emu.pop()


def h_ftol(emu):
    ret = emu.pop()
    v = emu.st.pop()
    emu.r[0] = int(v) & MASK32
    emu.pc = ret


def h_iter_begin(emu):
    ret = emu.pop()
    emu.r[4] = (emu.r[4] + 4) & MASK32
    c = emu.r[1]
    slot = emu.r[6]
    emu.wr32(slot, c)
    emu.wr32(slot + 4, emu.rd32(c + 4))
    emu.wr32(slot + 8, emu.rd32(c + 8))
    emu.r[0] = slot
    emu.pc = ret


def h_iter_at(emu):
    ret = emu.pop()
    k = emu.rd32(emu.r[4])
    emu.r[4] = (emu.r[4] + 4) & MASK32
    c = emu.r[3]
    slot = emu.r[6]
    begin = emu.rd32(c + 4)
    end = emu.rd32(c + 8)
    if end < begin:
        raise EmuError("container begin/end corrupt at 0x%08x" % c)
    cur = begin + k * 0xA0
    if cur > end:
        cur = end
    emu.wr32(slot, c)
    emu.wr32(slot + 4, cur)
    emu.r[0] = slot
    emu.pc = ret


def h_copy_a0(emu):
    ret = emu.pop()
    emu.mem.copy(emu.r[0], emu.r[3], 0xA0)
    emu.pc = ret


def h_copy_28(emu):
    ret = emu.pop()
    emu.mem.copy(emu.r[0], emu.r[3], 0x28)
    emu.pc = ret


def h_auth(emu):
    ret = emu.pop()
    emu.r[4] = (emu.r[4] + 4) & MASK32
    emu.r[0] = emu.auth_ok
    emu.pc = ret


CODE_FILES = [
    "f_1003db40.txt", "f_1003e200.txt", "f_1003eba0.txt", "f_1003ef00.txt",
    "f_1006a040.txt", "core_1002c1d0.txt", "f_1003d780.txt", "f_1003d8a0.txt",
    "f_1003f0d0.txt", "f_1003f150.txt", "f_1006b050.txt",
    "f_1006a5e0.txt", "f_1006a720.txt",
]


def make_emu(evidence_dir):
    import os
    emu = Emu()
    for name in CODE_FILES:
        emu.load_dis_file(os.path.join(evidence_dir, name))
    emu.mem.wr_bytes(0x1006F194, HOOK_ASSERT.to_bytes(4, "little"))
    emu.mem.wr_bytes(0x1006FC28, struct.pack("<d", 0.001))
    emu.mem.wr_bytes(0x1006FC50, struct.pack("<f", -1.0))
    return emu


if __name__ == "__main__":
    import os
    ev = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "re-inventory", "chbi")
    emu = make_emu(ev)
    print("x86emu: loaded %d instructions from %d files" % (len(emu.code), len(CODE_FILES)))
    print("entry points: c1d0=%s c4b0=%s db40=%s" % (
        0x1002C1D0 in emu.code, 0x1002C4B0 in emu.code, 0x1003DB40 in emu.code))
