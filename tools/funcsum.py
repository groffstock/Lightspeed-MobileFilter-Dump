#!/usr/bin/env python3
# Function summarizer: bound functions via LC_FUNCTION_STARTS, then for each report
# referenced string literals + imported-symbol calls. Also builds a string-xref index
# to locate stripped pure-Swift functions by the strings they touch.
import struct, sys, json, re
import capstone
d = open("MobileFilter","rb").read()
binds = {int(k):v for k,v in json.load(open(sys.argv[1])).items()} if sys.argv[1].endswith(".json") else {}

segs=[]; sects={}
off=32; ncmds=struct.unpack_from("<I",d,16)[0]; fstarts_off=fstarts_sz=0; textbase=0
for _ in range(ncmds):
    cmd,sz=struct.unpack_from("<II",d,off)
    if cmd==0x19:
        vmaddr,vmsize,fileoff,filesize=struct.unpack_from("<QQQQ",d,off+24); segs.append((vmaddr,vmsize,fileoff))
        nm=d[off+8:off+24].split(b'\0')[0]
        if nm==b"__TEXT": textbase=vmaddr
        nsects=struct.unpack_from("<I",d,off+64)[0]; so=off+72
        for s in range(nsects):
            sn=d[so:so+16].split(b'\0')[0].decode(); sg=d[so+16:so+32].split(b'\0')[0].decode()
            a,size=struct.unpack_from("<QQ",d,so+32); sects[(sg,sn)]=(a,size); so+=80
    if cmd==0x26:  # LC_FUNCTION_STARTS
        fstarts_off,fstarts_sz=struct.unpack_from("<II",d,off+8)
    off+=sz
def voff(vm):
    for a,s,f in segs:
        if a<=vm<a+s: return f+(vm-a)
    return None
def cstr(vm):
    fo=voff(vm)
    if fo is None: return ""
    e=d.find(b"\x00",fo); return d[fo:e].decode("utf-8","replace") if e>=0 else ""

# decode ULEB128 function starts (deltas from textbase)
def func_starts():
    res=[]; p=fstarts_off; end=fstarts_off+fstarts_sz; addr=textbase
    while p<end:
        shift=0; val=0
        while True:
            b=d[p]; p+=1; val|=(b&0x7f)<<shift
            if not (b&0x80): break
            shift+=7
        if val==0 and res: break
        addr+=val; res.append(addr)
    return res
FS=func_starts()
import bisect
def func_end(start):
    i=bisect.bisect_right(FS,start)
    return FS[i] if i<len(FS) else start+0x2000

md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN); md.detail=True
A=capstone.arm64

def summarize(start, verbose=False):
    end=func_end(start); fo=voff(start)
    code=d[fo:fo+(end-start)]
    regpage={}; strings=[]; imports=[]; subs=[]
    for insn in md.disasm(code,start):
        m=insn.mnemonic
        if m=="adrp" and insn.operands[1].type==A.ARM64_OP_IMM:
            regpage[insn.operands[0].reg]=insn.operands[1].imm
        elif m=="add" and len(insn.operands)==3 and insn.operands[1].reg in regpage and insn.operands[2].type==A.ARM64_OP_IMM:
            addr=regpage[insn.operands[1].reg]+insn.operands[2].imm; regpage[insn.operands[0].reg]=addr
            s=cstr(addr)
            if s and s.isprintable() and len(s)>=3: strings.append(s)
        elif m=="ldr" and insn.operands[1].type==A.ARM64_OP_MEM:
            mem=insn.operands[1].mem
            if mem.base in regpage:
                slot=regpage[mem.base]+mem.disp
                if slot in binds: imports.append(binds[slot])
        elif m=="bl" and insn.operands[0].type==A.ARM64_OP_IMM:
            t=insn.operands[0].imm
            if t in binds: imports.append(binds[t])
            else: subs.append(t)
    return dict(start=start,end=end,strings=strings,imports=imports,subs=subs)

def show(start):
    s=summarize(start)
    print(f"\n=== sub_{start:x}  ({(s['end']-start)} bytes) ===")
    seen=set()
    if s['strings']:
        print(" strings:")
        for x in s['strings']:
            if x not in seen: print(f'   "{x[:80]}"'); seen.add(x)
    imp=[]
    for x in s['imports']:
        if x not in imp: imp.append(x)
    if imp:
        print(" imported calls:")
        for x in imp: print(f"   {x}")

if __name__=="__main__":
    args=[a for a in sys.argv[1:] if not a.endswith(".json")]
    if args and args[0]=="index":
        # build string-xref index, print functions whose strings match regex args[1]
        pat=re.compile(args[1],re.I)
        for f in FS:
            s=summarize(f)
            hits=[x for x in s['strings'] if pat.search(x)]
            if hits:
                print(f"sub_{f:x}: "+" | ".join(sorted(set(hits))[:6]))
    else:
        for a in args:
            show(int(a,16))
