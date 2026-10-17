import collections, sys
import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_MEM
p = r"D:/a_ronglide/clone-ronglide/ronglide-app/chlib.dll"
pe = pefile.PE(p); base = pe.OPTIONAL_HEADER.ImageBase
s = next(x for x in pe.sections if b".text" in x.Name)
raw = open(p,"rb").read()
tstart = base + s.VirtualAddress
tdata = raw[s.PointerToRawData: s.PointerToRawData + s.SizeOfRawData]
md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True
cnt = collections.Counter(); samples = {}
covered = 0; total = len(tdata); gaps = 0
off = 0
while off < total:
    got = False
    for ins in md.disasm(tdata[off:off+16], tstart+off):
        off += ins.size; got = True; covered += ins.size
        if ins.mnemonic in ("call","jmp") and ins.operands and ins.operands[0].type == X86_OP_MEM:
            m = ins.operands[0].mem
            key = (ins.mnemonic, m.disp, m.index!=0)
            cnt[key] += 1
            samples.setdefault(key, []).append(ins.address)
        break
    if not got:
        off += 1; gaps += 1
print("text size=%d covered=%d (%.1f%%) resync_bytes=%d" % (total, covered, 100.0*covered/total, gaps))
for k,v in sorted(cnt.items(), key=lambda x:-x[1])[:20]:
    print("%-5s disp=0x%-6x indexed=%-5s  n=%-4d  eg=%s" % (k[0], k[1], k[2], v, [hex(a) for a in samples[k][:4]]))
