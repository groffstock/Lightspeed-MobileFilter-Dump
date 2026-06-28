#!/usr/bin/env python3
# Resolve ObjC class+selector -> IMP, disassemble arm64, annotate string/sel/symbol refs.
import struct, sys, json, re
import capstone
PATH = "MobileFilter"
d = open(PATH, "rb").read()
BINDS = sys.argv[-1] if sys.argv[-1].endswith(".json") else None
binds = {int(k): v for k, v in json.load(open(BINDS)).items()} if BINDS else {}

# ---- seg/section map ----
segs = []
off = 32; ncmds = struct.unpack_from("<I", d, 16)[0]
sects = {}
for _ in range(ncmds):
    cmd, sz = struct.unpack_from("<II", d, off)
    if cmd == 0x19:
        vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", d, off + 24)
        segs.append((vmaddr, vmsize, fileoff))
        nsects = struct.unpack_from("<I", d, off + 64)[0]; so = off + 72
        for s in range(nsects):
            sn = d[so:so+16].split(b'\0')[0].decode(); sg = d[so+16:so+32].split(b'\0')[0].decode()
            a, size = struct.unpack_from("<QQ", d, so+32)
            sects[(sg, sn)] = (a, size); so += 80
    off += sz
def voff(vm):
    for a, s, f in segs:
        if a <= vm < a + s: return f + (vm - a)
    return None
def cstr(vm):
    fo = voff(vm)
    if fo is None: return ""
    e = d.find(b"\x00", fo); return d[fo:e].decode("utf-8","replace") if e>=0 else ""
def u32(fo): return struct.unpack_from("<I", d, fo)[0] if fo is not None and fo+4<=len(d) else 0
def s32(fo): return struct.unpack_from("<i", d, fo)[0]
def ptr(vm):
    if not vm: return 0
    fo = voff(vm)
    if fo is None or fo+8>len(d): return 0
    raw = struct.unpack_from("<Q", d, fo)[0]
    if (raw>>63)&1: return 0
    return (raw & 0xFFFFFFFFF) | (((raw>>36)&0xFF)<<56)

# ---- find IMP for class+selector via objc metadata ----
def class_methods(target_class):
    cl_a, cl_sz = sects[("__DATA_CONST","__objc_classlist")]
    for i in range(cl_sz//8):
        cvm = ptr(cl_a + i*8)
        data = ptr(cvm+32) & ~7
        name = cstr(ptr(data+24))
        # demangle _TtC..
        dn = name
        if name.startswith("_TtC"):
            s=name[4:]; parts=[]
            while s and s[0].isdigit():
                j=0
                while j<len(s) and s[j].isdigit(): j+=1
                ln=int(s[:j]); parts.append(s[j:j+ln]); s=s[j+ln:]
            dn=".".join(parts) if parts else name
        if target_class not in (name, dn) and not dn.endswith("."+target_class): continue
        out=[]
        for is_inst, cls_vm in ((False, ptr(cvm+0)), (True, cvm)):  # metaclass then class
            data2 = ptr(cls_vm+32) & ~7
            ml = ptr(data2+32)
            if not ml: continue
            mfo = voff(ml)
            if mfo is None: continue
            entsize = u32(mfo); count = u32(mfo+4); small = bool(entsize&0x80000000); esz=entsize&0xFFFF
            for k in range(count):
                evm = ml + 8 + k*esz
                if small:
                    sel = cstr(ptr(evm + s32(voff(evm))))
                    imp = (evm+8) + s32(voff(evm)+8)
                else:
                    sel = cstr(ptr(evm)); imp = ptr(evm+16)
                out.append((('+' if not is_inst else '-'), sel, imp))
        return dn, out
    return None, []

# ---- disassembler with annotations ----
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
md.detail = True
selref_a, selref_sz = sects.get(("__DATA","__objc_selrefs"),(0,0))
classref_a, classref_sz = sects.get(("__DATA","__objc_classrefs"),(0,0))

def annotate(insn, adrp_reg):
    txt=""
    m=insn.mnemonic
    # track adrp/add page for string refs
    if m=="bl":
        tgt=insn.operands[0].imm
        if tgt in binds: txt=f"  ; {binds[tgt]}"
        else:
            sym=symbolmap.get(tgt)
            txt=f"  ; {sym}" if sym else f"  ; sub_{tgt:x}"
    # adr/adrp+add string detection handled by caller via resolved addr
    return txt

# symbol map from symtab for bl targets
symbolmap={}
for cmd_off in []: pass
off=32
for _ in range(ncmds):
    cmd,sz=struct.unpack_from("<II",d,off)
    if cmd==0x02:  # LC_SYMTAB
        symoff,nsyms,stroff,strsize=struct.unpack_from("<IIII",d,off+8)
        for i in range(nsyms):
            so=symoff+i*16
            strx,typ,sect,desc=struct.unpack_from("<IBBH",d,so); val=struct.unpack_from("<Q",d,so+8)[0]
            if val and (typ & 0x0e)==0x0e:  # N_SECT
                nm=cstr_str=d[stroff+strx:d.find(b"\0",stroff+strx)].decode("utf-8","replace")
                symbolmap[val]=nm
    off+=sz

def disasm_func(name, imp, maxins=400, stop_on_tailcall=True):
    print(f"\n===== {name}  @ {imp:#x} (file {voff(imp):#x}) =====")
    fo=voff(imp); code=d[fo:fo+maxins*4]
    regpage={}; gotreg={}  # reg -> resolved string addr / GOT symbol
    for insn in md.disasm(code, imp):
        ann=""
        m=insn.mnemonic; ops=insn.op_str
        if m=="adrp" and insn.operands[1].type==capstone.arm64.ARM64_OP_IMM:
            regpage[insn.operands[0].reg]=insn.operands[1].imm; gotreg.pop(insn.operands[0].reg,None)
        elif m=="add" and len(insn.operands)==3 and insn.operands[1].reg in regpage and insn.operands[2].type==capstone.arm64.ARM64_OP_IMM:
            addr=regpage[insn.operands[1].reg]+insn.operands[2].imm
            regpage[insn.operands[0].reg]=addr
            s=cstr(addr)
            if s and s.isprintable() and len(s)>=2: ann=f'  ; "{s[:64]}"'
        elif m=="ldr" and insn.operands[1].type==capstone.arm64.ARM64_OP_MEM:
            mem=insn.operands[1].mem
            if mem.base in regpage:
                slot=regpage[mem.base]+mem.disp
                if slot in binds:
                    gotreg[insn.operands[0].reg]=binds[slot]; ann=f"  ; &{binds[slot]}"
        elif m=="bl":
            tgt=insn.operands[0].imm
            if tgt in binds: ann=f"  ; -> {binds[tgt]}"
            elif tgt in symbolmap: ann=f"  ; -> {symbolmap[tgt]}"
            else: ann=f"  ; -> sub_{tgt:x}"
        elif m=="blr" and insn.operands[0].reg in gotreg:
            ann=f"  ; -> {gotreg[insn.operands[0].reg]}"
        print(f"  {insn.address:#010x}  {m:<7} {ops}{ann}")
        if m=="ret": break
        if m=="b" and stop_on_tailcall and insn.operands and insn.operands[0].type==capstone.arm64.ARM64_OP_IMM:
            t=insn.operands[0].imm
            if t < imp or t > imp+maxins*4:
                print(f"  ; --- tail-call to {('->'+binds[t]) if t in binds else f'sub_{t:x}'}, stop ---"); break

if __name__=="__main__":
    if sys.argv[1].startswith("0x"):
        disasm_func(f"sub_{sys.argv[1]}", int(sys.argv[1],16), maxins=int(sys.argv[2]) if len(sys.argv)>2 and sys.argv[2].isdigit() else 300)
        sys.exit()
    target=sys.argv[1]; sel=sys.argv[2] if len(sys.argv)>2 and not sys.argv[2].endswith('.json') else None
    dn, methods = class_methods(target)
    if dn is None:
        print(f"class {target} not found"); sys.exit()
    print(f"// {dn}: {len(methods)} methods")
    for pm, s, imp in methods:
        print(f"  {pm} {s}   IMP={imp:#x}")
    if sel:
        for pm, s, imp in methods:
            if s==sel or s.split(':')[0]==sel:
                disasm_func(f"{dn} {pm}{s}", imp); break
