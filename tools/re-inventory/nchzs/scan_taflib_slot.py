# 扫 TAFLib.dll 中所有 call/jmp [reg+disp] 虚表调用，重点 disp==0x10
import collections
import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_MEM
p = r"D:/a_ronglide/clone-ronglide/ronglide-app/TAFLib.dll"
pe = pefile.PE(p); base = pe.OPTIONAL_HEADER.ImageBase
s = next(x for x in pe.sections if b".text" in x.Name)
raw = open(p,"rb").read()
tstart = base + s.VirtualAddress
tdata = raw[s.PointerToRawData: s.PointerToRawData + s.SizeOfRawData]
md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail=True
insns=[]; off=0; n=len(tdata); covered=0
while off<n:
    got=False
    for ins in md.disasm(tdata[off:off+16], tstart+off):
        insns.append(ins); off+=ins.size; covered+=ins.size; got=True; break
    if not got: off+=1
print("TAFLib .text size=%d covered=%d (%.1f%%) insns=%d"%(n,covered,100.0*covered/n,len(insns)))
cnt=collections.Counter(); hits={}
for k,ins in enumerate(insns):
    if ins.mnemonic not in ("call","jmp"): continue
    if not ins.operands: continue
    op=ins.operands[0]
    if op.type!=X86_OP_MEM: continue
    d=op.mem.disp
    cnt[d]+=1
    if d==0x10: hits.setdefault(d,[]).append(k)
print("disp==0x10 hits:", len(hits.get(0x10,[])))
for k in hits.get(0x10,[])[:20]:
    print("---- @0x%08x"%insns[k].address)
    for j in range(max(0,k-10), min(len(insns),k+3)):
        pre=" >>" if j==k else "   "
        print("%s %08x  %-8s %s"%(pre,insns[j].address,insns[j].mnemonic,insns[j].op_str))
