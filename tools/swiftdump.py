#!/usr/bin/env python3
# Swift reflection dump from __swift5_fieldmd -> type name + stored fields (name: type).
import struct, sys, re
PATH = sys.argv[1] if len(sys.argv) > 1 else "MobileFilter"
OUT  = sys.argv[2] if len(sys.argv) > 2 else None
d = open(PATH, "rb").read()

# section table
def find_section(segn, secn):
    off = 32; ncmds = struct.unpack_from("<I", d, 16)[0]
    for _ in range(ncmds):
        cmd, sz = struct.unpack_from("<II", d, off)
        if cmd == 0x19:
            nsects = struct.unpack_from("<I", d, off + 64)[0]; so = off + 72
            for s in range(nsects):
                sn = d[so:so+16].split(b'\0')[0].decode(); sg = d[so+16:so+32].split(b'\0')[0].decode()
                addr, size = struct.unpack_from("<QQ", d, so+32); fo = struct.unpack_from("<I", d, so+48)[0]
                if sg == segn and sn == secn: return addr, size, fo
                so += 80
        off += sz
    return None
segs = []
off = 32; ncmds = struct.unpack_from("<I", d, 16)[0]
for _ in range(ncmds):
    cmd, sz = struct.unpack_from("<II", d, off)
    if cmd == 0x19:
        vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", d, off + 24); segs.append((vmaddr, vmsize, fileoff))
    off += sz
def voff(vm):
    for a, s, f in segs:
        if a <= vm < a + s: return f + (vm - a)
    return None
def cstr_at_off(fo):
    if fo is None or fo < 0 or fo >= len(d): return ""
    e = d.find(b"\x00", fo); return d[fo:e].decode("utf-8", "replace") if e >= 0 else ""

def s32off(fo): return struct.unpack_from("<i", d, fo)[0]

def nominal_name(desc_fo):
    """Read the Name field of a nominal/context type descriptor at file offset desc_fo."""
    # TypeContextDescriptor: Flags(u32@0) Parent(rel@4) Name(rel@8)
    if desc_fo is None or desc_fo + 12 > len(d) or desc_fo < 0: return None
    name_fo = (desc_fo + 8) + s32off(desc_fo + 8)
    return cstr_at_off(name_fo)

def resolve_symbolic_name(fo):
    """If the mangled name at fo begins with a symbolic reference to a nominal
    type descriptor, return that type's name; else None."""
    if fo is None or fo >= len(d): return None
    c = d[fo]
    if c == 0x01:                       # direct relative ptr to descriptor
        return nominal_name((fo + 1) + s32off(fo + 1))
    if c == 0x02:                       # indirect (rel ptr to a ptr) — skip
        return None
    return None

# Swift "symbolic reference" aware mangled-name reader: stops at NUL, skips control bytes
def read_swift_mangled(fo):
    if fo is None: return ""
    out = bytearray(); i = fo
    while i < len(d):
        c = d[i]
        if c == 0x00: break
        if c == 0x01 or c == 0x02:        # symbolic ref to context descriptor (4-byte rel ptr follows)
            out += b"{ref}"; i += 5; continue
        if 0x03 <= c <= 0x1F:             # other symbolic refs
            out += b"{ref}"; i += 5; continue
        out.append(c); i += 1
    return bytes(out).decode("utf-8", "replace")

# Very small Swift type demangler for the common standard-library manglings
_STD = {"Si":"Int","Su":"UInt","Sf":"Float","Sd":"Double","SS":"String","Sb":"Bool",
        "Si8":"Int8","s5UInt8V":"UInt8","ypG":"Any","yp":"Any","SQ":"Optional","Sg":"?"}
def demangle_type(m):
    if not m: return "?"
    m = m.replace("{ref}", "T")             # symbolic ref placeholder -> opaque T
    if m in _STD: return _STD[m]
    # Sq/Sg suffix => Optional
    opt = m.endswith("Sg")
    base = m[:-2] if opt else m
    r = _STD.get(base, None)
    if r is None:
        mm = re.search(r'(\d+)([A-Za-z_][A-Za-z0-9_]*)$', base)
        r = mm.group(2) if mm else base
    return r + ("?" if opt else "")

fm = find_section("__TEXT", "__swift5_fieldmd")
if not fm:
    print("no __swift5_fieldmd"); sys.exit()
addr, size, base_fo = fm
lines = []
def emit(s=""): lines.append(s)

KIND = {0:"struct",1:"class",2:"enum",3:"optional",4:"protocol",
        5:"class-proto",6:"obj-proto",7:"enum?",17:"struct",18:"enum"}
fo = base_fo; end = base_fo + size; ntypes = 0
while fo + 16 <= end:
    mtn_rel = struct.unpack_from("<i", d, fo)[0]
    superc  = struct.unpack_from("<i", d, fo + 4)[0]
    kind    = struct.unpack_from("<H", d, fo + 8)[0]
    frs     = struct.unpack_from("<H", d, fo + 10)[0]
    nfields = struct.unpack_from("<I", d, fo + 12)[0]
    if frs == 0 or nfields > 4000:
        fo += 16; continue
    type_name = "?"
    if mtn_rel:
        nm = resolve_symbolic_name(fo + mtn_rel)
        type_name = nm if nm else demangle_type(read_swift_mangled(fo + mtn_rel))
    recs = []
    rfo = fo + 16
    for i in range(nfields):
        if rfo + 12 > end: break
        flags  = struct.unpack_from("<I", d, rfo)[0]
        tn_rel = struct.unpack_from("<i", d, rfo + 4)[0]
        fn_rel = struct.unpack_from("<i", d, rfo + 8)[0]
        fname = cstr_at_off((rfo + 8) + fn_rel) if fn_rel else ""
        ftype = "?"
        if tn_rel:
            nm = resolve_symbolic_name((rfo + 4) + tn_rel)
            ftype = nm if nm else demangle_type(read_swift_mangled((rfo + 4) + tn_rel))
        recs.append((fname, ftype, flags))
        rfo += frs
    ntypes += 1
    knd = KIND.get(kind, f"kind{kind}")
    emit(f"{knd} {type_name} {{")
    for fname, ftype, flags in recs:
        kw = "let" if (flags & 0x2) == 0 else "var"
        emit(f"    {kw} {fname}: {ftype}")
    emit("}\n")
    fo = rfo

hdr = f"// Swift reflection (__swift5_fieldmd) — {ntypes} types with stored fields\n"
text = hdr + "\n".join(lines)
if OUT:
    open(OUT, "w", encoding="utf-8").write(text); print(f"wrote {OUT} ({ntypes} types)")
else:
    print(text[:4000])
