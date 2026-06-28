#!/usr/bin/env python3
# Decision-point tracer: disassemble one function and emit, in address order, the
# "interesting" lines only — string-literal loads, comparisons, conditional branches,
# returns, and calls to named imports/subs — so an if/else precedence ladder can be
# reconstructed from a huge Swift function.
import struct, sys, json, bisect
import capstone
d = open("MobileFilter","rb").read()
binds = {int(k):v for k,v in json.load(open(sys.argv[1])).items()} if sys.argv[1].endswith(".json") else {}
START = int(sys.argv[2],16)

segs=[]; off=32; ncmds=struct.unpack_from("<I",d,16)[0]; fstarts_off=fstarts_sz=textbase=0
for _ in range(ncmds):
    cmd,sz=struct.unpack_from("<II",d,off)
    if cmd==0x19:
        vmaddr,vmsize,fileoff,filesize=struct.unpack_from("<QQQQ",d,off+24); segs.append((vmaddr,vmsize,fileoff))
        if d[off+8:off+24].split(b'\0')[0]==b"__TEXT": textbase=vmaddr
    if cmd==0x26: fstarts_off,fstarts_sz=struct.unpack_from("<II",d,off+8)
    off+=sz
def voff(vm):
    for a,s,f in segs:
        if a<=vm<a+s: return f+(vm-a)
    return None
def cstr(vm):
    fo=voff(vm)
    if fo is None: return ""
    e=d.find(b"\x00",fo); return d[fo:e].decode("utf-8","replace") if e>=0 else ""
def fstarts():
    res=[]; p=fstarts_off; end=fstarts_off+fstarts_sz; a=textbase
    while p<end:
        sh=0; v=0
        while True:
            b=d[p]; p+=1; v|=(b&0x7f)<<sh
            if not(b&0x80): break
            sh+=7
        if v==0 and res: break
        a+=v; res.append(a)
    return res
FS=fstarts()
END=FS[bisect.bisect_right(FS,START)] if bisect.bisect_right(FS,START)<len(FS) else START+0x20000

md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN); md.detail=True
A=capstone.arm64
fo=voff(START); code=d[fo:fo+(END-START)]
regpage={}
COND={"b.eq","b.ne","b.lt","b.le","b.gt","b.ge","b.hi","b.lo","b.hs","b.ls","b.mi","b.pl","cbz","cbnz","tbz","tbnz"}
# collect branch targets to label join points
insns=list(md.disasm(code,START))
targets=set()
for insn in insns:
    if insn.mnemonic in COND or insn.mnemonic=="b":
        if insn.operands and insn.operands[-1].type==A.ARM64_OP_IMM:
            targets.add(insn.operands[-1].imm)
depth=0
for insn in insns:
    a=insn.address; m=insn.mnemonic; ops=insn.op_str; line=None
    if a in targets: print(f"            .L{a:x}:")
    if m=="adrp" and insn.operands[1].type==A.ARM64_OP_IMM:
        regpage[insn.operands[0].reg]=insn.operands[1].imm
    elif m=="add" and len(insn.operands)==3 and insn.operands[1].reg in regpage and insn.operands[2].type==A.ARM64_OP_IMM:
        addr=regpage[insn.operands[1].reg]+insn.operands[2].imm; regpage[insn.operands[0].reg]=addr
        s=cstr(addr)
        if s and s.isprintable() and len(s)>=3:
            line=f'  {a:#x}  str  "{s[:90]}"'
    elif m=="bl" and insn.operands[0].type==A.ARM64_OP_IMM:
        t=insn.operands[0].imm
        if t in binds and not binds[t].startswith("_$s"):  # named imports / ObjC only
            line=f"  {a:#x}  call {binds[t]}"
    elif m in COND:
        line=f"  {a:#x}  {m:<5} {ops}   -> .L{insn.operands[-1].imm:x}"
    elif m=="b" and insn.operands and insn.operands[0].type==A.ARM64_OP_IMM:
        line=f"  {a:#x}  b     -> .L{insn.operands[0].imm:x}"
    elif m in ("cmp","cmn","tst"):
        line=f"  {a:#x}  {m:<5} {ops}"
    elif m=="ret":
        line=f"  {a:#x}  ret"
    if line: print(line)
