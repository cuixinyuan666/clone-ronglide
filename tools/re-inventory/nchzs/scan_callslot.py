# 字节级验证: 是否存在 call/jmp dword ptr [reg + 0x10]  (FF /2 mod=01 rm=reg disp8=0x10)
p = r"D:/a_ronglide/clone-ronglide/ronglide-app/chlib.dll"
pe = __import__("pefile").PE(p); base = pe.OPTIONAL_HEADER.ImageBase
s = next(x for x in pe.sections if b".text" in x.Name)
raw = open(p,"rb").read()
tstart = base + s.VirtualAddress
d = raw[s.PointerToRawData: s.PointerToRawData + s.SizeOfRawData]
hits = []
for i in range(len(d)-2):
    if d[i] != 0xFF: continue
    m = d[i+1]
    if (m & 0xC7) != 0x40:      # mod=01, reg=000 => /0 inc, /2 call, /4 jmp: reg bits vary
        continue
    reg = (m >> 3) & 7
    if reg not in (2,4): continue
    if d[i+2] != 0x10: continue
    hits.append((tstart+i, m))
print("byte-level [reg+0x10] call/jmp hits:", len(hits))
for a,m in hits[:10]: print("  0x%08x modrm=0x%02x" % (a,m))
# 同时统计 disp 为 0x10 的所有 FF /2 /4 形态(含 SIB)
cnt = {}
for i in range(len(d)-2):
    if d[i] != 0xFF: continue
    m = d[i+1]; reg = (m>>3)&7
    if reg not in (2,4): continue
    if (m>>6) == 1: disp = d[i+2]
    elif (m>>6) == 2: disp = None
    else: disp = 0
    cnt[disp] = cnt.get(disp,0)+1
print("call/jmp mem disp histogram (mod=00/01 only):", sorted(cnt.items(), key=lambda x: (x[0] is None, x[0] or 0))[:12])
