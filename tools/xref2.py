import pefile, capstone, os, struct

APP = r'D:\a_ronglide\缠中说禅'
TARGET = os.path.join(APP, 'rquo.dll')
pe = pefile.PE(TARGET, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
data = open(TARGET, 'rb').read()
secs = [(s.Name.rstrip(b'\x00').decode(), base + s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData) for s in pe.sections]

def va2off(va):
    for name, sva, raw, size in secs:
        if sva <= va < sva + size:
            return raw + (va - sva)
    return None

# target string VAs
targets = {}
for va, label in [
    (0x1009be4f, 'SymTable.rs'), (0x1009be3f, 'SymTable.tmp'), (0x1009be03, 'SecTable.rs'),
    (0x1009be9b, 'StaMem.tmp'), (0x1009beaf, 'StaMem.rs'), (0x1009bee3, 'ActMem.tmp'),
    (0x1009bef7, 'ActMem.rs'), (0x1009bf0b, 'ActMemI.tmp'), (0x1009bf23, 'ActMemI.rs'),
    (0x1009beb2, 'Mem.rs'), (0x1009be9e, 'Mem.tmp'), (0x1009bf26, 'MemI.rs'), (0x1009bf0e, 'MemI.tmp'),
    (0x1009bf77, 'latelydays.bin'), (0x1009b8e0, 'stock.xdr'),
]:
    targets[va] = label

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

name, sva, raw, size = [s for s in secs if s[0] == '.text'][0]
code = data[raw:raw + size]
hits = []
for insn in md.disasm(code, sva):
    for op in insn.operands:
        if op.type == capstone.x86.X86_OP_IMM and op.imm in targets:
            hits.append((insn.address, insn.mnemonic, insn.op_str, targets[op.imm]))

print('hits:', len(hits))
for addr, mn, ops, label in hits:
    print(f'  {hex(addr)} {mn} {ops}   ; {label}')
