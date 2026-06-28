#!/usr/bin/env python3
# Self-contained ObjC + Swift metadata class-dump for arm64 Mach-O with
# DYLD_CHAINED_PTR_64 fixups.  No external deps beyond stdlib.
import struct, sys, re

import json, os
PATH = sys.argv[1] if len(sys.argv) > 1 else "MobileFilter"
OUT  = sys.argv[2] if len(sys.argv) > 2 else None
BINDS = sys.argv[3] if len(sys.argv) > 3 else None
d = open(PATH, "rb").read()
binds = {}
if BINDS and os.path.exists(BINDS):
    binds = {int(k): v for k, v in json.load(open(BINDS)).items()}

def demangle_class(n):
    """Light Swift class-name demangle: _TtC<modlen><mod><len><name> -> mod.Name."""
    if not n.startswith("_Tt"): return n
    s = n[3:]
    if s[:1] in ("C", "V", "O"):  # class / struct / enum
        s = s[1:]; parts = []
        while s and s[0].isdigit():
            j = 0
            while j < len(s) and s[j].isdigit(): j += 1
            ln = int(s[:j]); parts.append(s[j:j+ln]); s = s[j+ln:]
        if parts: return ".".join(parts)
    return n

def ext_name(sym):
    return sym.replace("_OBJC_CLASS_$_", "").replace("_OBJC_METACLASS_$_", "")

# ---- segment / section map (VM <-> file offset) -------------------------------
segs = []  # (vmaddr, vmsize, fileoff)
ncmds = struct.unpack_from("<I", d, 16)[0]
off = 32
for _ in range(ncmds):
    cmd, sz = struct.unpack_from("<II", d, off)
    if cmd == 0x19:  # LC_SEGMENT_64
        vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", d, off + 24)
        segs.append((vmaddr, vmsize, fileoff))
    off += sz

def voff(vm):
    for vmaddr, vmsize, fileoff in segs:
        if vmaddr <= vm < vmaddr + vmsize:
            return fileoff + (vm - vmaddr)
    return None

# ---- chained-pointer (PTR_64) decode ------------------------------------------
def ptr(vm):
    """Resolve a pointer slot located at VM address `vm` -> (target_vm, is_bind)."""
    if not vm: return (0, False)
    fo = voff(vm)
    if fo is None or fo + 8 > len(d): return (0, False)
    raw = struct.unpack_from("<Q", d, fo)[0]
    bind = (raw >> 63) & 1
    if bind:
        return (raw & 0xFFFFFF, True)          # bind ordinal (external)
    target = raw & 0xFFFFFFFFF                  # 36-bit target
    high8 = (raw >> 36) & 0xFF
    return (target | (high8 << 56), False)

def cstr(vm):
    fo = voff(vm)
    if fo is None: return ""
    e = d.find(b"\x00", fo)
    if e < 0: return ""
    return d[fo:e].decode("utf-8", "replace")

def u32(fo):
    if fo is None or fo < 0 or fo + 4 > len(d): return 0
    return struct.unpack_from("<I", d, fo)[0]
def s32(fo): return struct.unpack_from("<i", d, fo)[0]

# ---- ObjC type-encoding decoder ----------------------------------------------
_ENC = {'c':'char','i':'int','s':'short','l':'long','q':'long long','C':'unsigned char',
        'I':'unsigned int','S':'unsigned short','L':'unsigned long','Q':'unsigned long long',
        'f':'float','d':'double','B':'BOOL','v':'void','*':'char *','@':'id','#':'Class',
        ':':'SEL','?':'void *'}
def decode_type(enc):
    enc = enc.lstrip('rnNoRV')  # qualifiers
    if not enc: return 'void'
    c = enc[0]
    if c == '@':
        m = re.match(r'@"([^"]*)"', enc)
        return (m.group(1)+' *') if m and m.group(1) and not m.group(1).startswith('<') else 'id'
    if c == '^': return decode_type(enc[1:]).rstrip('*').rstrip()+' *'
    if c in '{[(': return 'struct' if c=='{' else 'void *'
    return _ENC.get(c, enc)

def parse_method_types(types):
    """ObjC method type string -> (ret_type, [arg_types]) skipping self/_cmd."""
    toks = re.findall(r'[rnNoRV]*[A-Za-z@#:*?^]("[^"]*")?[0-9]*|[{\[(].*?[}\])][0-9]*', types)
    parts = re.findall(r'([rnNoRV]*(?:@"[^"]*"|\^?[A-Za-z@#:*?]|\{[^}]*\}|\[[^\]]*\])[0-9]*)', types)
    clean = [re.sub(r'[0-9]+$', '', p) for p in parts]
    if not clean: return ('id', [])
    ret = decode_type(clean[0])
    args = [decode_type(a) for a in clean[3:]]  # skip ret, self(@0), _cmd(:8)
    return (ret, args)

def fmt_selector(sel, types, is_inst):
    ret, args = parse_method_types(types) if types else ('id', [])
    pre = '-' if is_inst else '+'
    parts = sel.split(':')
    if ':' not in sel:
        return f"{pre} ({ret}){sel};"
    out = []
    for i, key in enumerate(parts[:-1]):
        a = args[i] if i < len(args) else 'id'
        out.append(f"{key}:({a})arg{i}")
    return f"{pre} ({ret}){' '.join(out)};"

# ---- read a method_list_t at VM -----------------------------------------------
def read_method_list(vm, is_inst):
    if not vm: return []
    fo = voff(vm)
    if fo is None: return []
    entsize = u32(fo); count = u32(fo + 4)
    if count > 5000 or (entsize & 0xFFFF) == 0: return []
    small = bool(entsize & 0x80000000)
    esz = entsize & 0xFFFF
    res = []
    base = fo + 8
    for i in range(count):
        e = base + i * esz
        evm = vm + 8 + i * esz
        if small:
            name_rel = s32(e); types_rel = s32(e + 4)
            # name field -> selref slot holding ptr to selector string
            selref_vm = evm + name_rel
            sel_ptr, _ = ptr(selref_vm)
            sel = cstr(sel_ptr)
            types = cstr((evm + 4) + types_rel)
        else:
            name_ptr, _ = ptr(evm)
            types_ptr, _ = ptr(evm + 8)
            sel = cstr(name_ptr); types = cstr(types_ptr)
        res.append((sel, types, is_inst))
    return res

# ---- read ivar / property lists ----------------------------------------------
def read_ivars(vm):
    if not vm: return []
    fo = voff(vm)
    if fo is None: return []
    entsize = u32(fo) & 0xFFFF; count = u32(fo + 4)
    if count > 5000 or entsize == 0: return []
    out = []
    for i in range(count):
        e = fo + 8 + i * entsize; evm = vm + 8 + i * entsize
        name_ptr, _ = ptr(evm + 8)
        type_ptr, _ = ptr(evm + 16)
        out.append((cstr(name_ptr), decode_type(cstr(type_ptr))))
    return out

def read_props(vm):
    if not vm: return []
    fo = voff(vm)
    if fo is None: return []
    entsize = u32(fo) & 0xFFFF; count = u32(fo + 4)
    if count > 5000 or entsize == 0: return []
    out = []
    for i in range(count):
        evm = vm + 8 + i * entsize
        n, _ = ptr(evm); a, _ = ptr(evm + 8)
        out.append((cstr(n), cstr(a)))
    return out

# ---- walk a class -------------------------------------------------------------
def class_ro(class_vm):
    fo = voff(class_vm)
    if fo is None: return None
    isa, _ = ptr(class_vm + 0)
    sup, _ = ptr(class_vm + 8)
    data_raw, _ = ptr(class_vm + 32)
    ro_vm = data_raw & ~7
    rfo = voff(ro_vm)
    if rfo is None: return None
    name_ptr, _ = ptr(ro_vm + 24)
    methods_ptr, _ = ptr(ro_vm + 32)
    protos_ptr, _ = ptr(ro_vm + 40)
    ivars_ptr, _ = ptr(ro_vm + 48)
    props_ptr, _ = ptr(ro_vm + 64)
    return dict(name=cstr(name_ptr), isa=isa, sup=sup,
                methods=methods_ptr, ivars=ivars_ptr, props=props_ptr, protos=protos_ptr)

def sec(name):
    for vmaddr, vmsize, fileoff in []: pass
# locate __objc_classlist via section table
def find_section(segn, secn):
    off = 32; ncmds = struct.unpack_from("<I", d, 16)[0]
    for _ in range(ncmds):
        cmd, sz = struct.unpack_from("<II", d, off)
        if cmd == 0x19:
            nsects = struct.unpack_from("<I", d, off + 64)[0]
            so = off + 72
            for s in range(nsects):
                sn = d[so:so+16].split(b'\0')[0].decode()
                sg = d[so+16:so+32].split(b'\0')[0].decode()
                addr, size = struct.unpack_from("<QQ", d, so+32)
                if sg == segn and sn == secn:
                    return addr, size
                so += 80
        off += sz
    return None, None

cl_addr, cl_size = find_section("__DATA_CONST", "__objc_classlist")
out_lines = []
def emit(s=""): out_lines.append(s)

classes = []
for i in range(cl_size // 8):
    cvm, _ = ptr(cl_addr + i * 8)
    ro = class_ro(cvm)
    if ro: classes.append((cvm, ro))

emit(f"// ObjC class-dump of {PATH} — {len(classes)} classes\n")
for cvm, ro in sorted(classes, key=lambda x: demangle_class(x[1]['name'])):
    # superclass: external binds win, else internal class_ro name
    if (cvm + 8) in binds:
        supname = ext_name(binds[cvm + 8])
    else:
        sup_ro = class_ro(ro['sup']) if ro['sup'] else None
        supname = sup_ro['name'] if sup_ro else ''
    supname = demangle_class(supname)
    cname = demangle_class(ro['name'])
    emit(f"@interface {cname}" + (f" : {supname}" if supname else "") + " {")
    for n, t in read_ivars(ro['ivars']):
        if t == 'void' or not t:
            emit(f"    id {n};  // Swift-typed ivar")
        else:
            emit(f"    {t} {n};")
    emit("}")
    for n, a in read_props(ro['props']):
        emit(f"@property {n};")
    # class (+) methods live on the metaclass (isa)
    meta = class_ro(ro['isa']) if ro['isa'] else None
    if meta:
        for sel, types, _ in read_method_list(meta['methods'], False):
            emit(fmt_selector(sel, types, False))
    for sel, types, _ in read_method_list(ro['methods'], True):
        emit(fmt_selector(sel, types, True))
    emit("@end\n")

text = "\n".join(out_lines)
if OUT:
    open(OUT, "w", encoding="utf-8").write(text)
    print(f"wrote {OUT} ({len(out_lines)} lines, {len(classes)} classes)")
else:
    print(text[:6000])
