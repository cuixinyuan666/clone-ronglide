import collections
import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_MEM
for p in (r"D:/a_ronglide/clone-ronglide/ronglide-app/TAFLib.dll",):
    pe = pefile.PE(p); base = pe.OPTIONAL_HEADER.ImageBase
    s = next(x for x in pe.sections if b".text" in x.Name)
    raw = open(p,"rb").read()
    tstart = base + s.VirtualAddress
    tdata = raw[s.PointerToRawData: s.PointerToRawData + s.SizeOfRawData]
    md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail=True
    insns=[]; off=0; n=len(tdata)
    while off<n:
        got=False
        for ins in md.disasm(tdata[off:off+16], tstart+off):
            insns.append(ins); off+=ins.size; got=True; break
        if not got: off+=1
    cnt=collections.Counter(); idxc=collections.Counter()
    for ins in insns:
        if ins.mnemonic not in ("call","jmp"): continue
        if not ins.operands: continue
        op=ins.operands[0]
        if op.type!=X86_OP_MEM: continue
        if op.mem.index: idxc[(ins.mnemonic, op.mem.disp)]+=1
        else: cnt[op.mem.disp]+=1
    print("== %s  非索引 mem-call 位移分布 (前25)"%p)
    for d,c in cnt.most_common(25): print("   disp=0x%-8x n=%d"%(d,c))
    print("   索引形态:", idxc.most_common(10))
