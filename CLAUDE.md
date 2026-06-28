# CLAUDE.md

Guidance for working on this project: inspecting and (if needed) decrypting the iOS Mach-O
binary `MobileFilter`.

## TL;DR — current state

**The binary is already decrypted.** Do not waste time trying to "decrypt" it.

- `LC_ENCRYPTION_INFO_64` is present with `cryptoff=0x4000`, `cryptsize=0x2e4000`, but
  **`cryptid=0`** — FairPlay is marked off.
- The `__TEXT` crypt region is plaintext ARM64: entropy ≈ **6.6 bits/byte** (encrypted data
  is ~7.99), and it begins with a normal prologue (`ff c3 01 d1` = `SUB SP, SP, #...`).

If a binary were still encrypted you would instead see `cryptid=1` and a crypt region with
entropy ≈ 8.0 / unreadable code. See "How to decrypt" below for that case.

## The binary

`MobileFilter` — ~3.7 MB, single thin Mach-O (not a fat/universal binary).

| Property        | Value                                                        |
|-----------------|-------------------------------------------------------------|
| Magic           | `cffaedfe` (`MH_MAGIC_64`, little-endian)                   |
| CPU             | arm64 (`cputype 0x0100000c`)                                 |
| File type       | `MH_EXECUTE` (2)                                             |
| Platform        | iOS (platform 2), min OS **14.0**                            |
| Load commands   | 54                                                          |
| Segments        | `__PAGEZERO`, `__TEXT`, `__DATA_CONST`, `__DATA`, `__LINKEDIT` |
| Flags           | `NOUNDEFS DYLDLINK TWOLEVEL BINDS_TO_WEAK PIE HAS_TLV_DESCRIPTORS` |

It is a **Swift + Objective-C** app using **NetworkExtension** (the name + framework set
points to a content/traffic filter). Notable linked frameworks: NetworkExtension, Network,
CFNetwork, Security, CryptoKit, CoreLocation, UIKit, Foundation, and a large `libswift*` set.

## Environment constraints (read this)

This project lives on **Windows** (`win32`, PowerShell). The usual Apple toolchain
(`otool`, `lldb`, `dyldinfo`, `nm`, `codesign`) is **not available**, and on-device
decryption tools (`frida-ios-dump`, `dumpdecrypted`, `bagbak`) require a **jailbroken iOS
device** that this host does not have.

Use **cross-platform Python** for inspection:

- Prefer **`LIEF`** (`pip install lief`) or **`machofile` / `macholib`** for parsing.
- A hand-rolled `struct`-based parser also works fine (see snippet below) and needs no deps.
- `capstone` (`pip install capstone`) for ARM64 disassembly.
- For decompilation, load into **Ghidra**, **IDA**, or **Hopper** — all run on Windows.

## How to verify encryption state

```python
import struct
d = open("MobileFilter", "rb").read()
ncmds = struct.unpack_from("<I", d, 16)[0]
off = 32
for _ in range(ncmds):
    cmd, sz = struct.unpack_from("<II", d, off)
    if cmd in (0x21, 0x2C):  # LC_ENCRYPTION_INFO / _64
        cryptoff, cryptsize, cryptid = struct.unpack_from("<III", d, off + 8)
        print(f"cryptoff={cryptoff:#x} cryptsize={cryptsize:#x} cryptid={cryptid}")
    off += sz
```

Then confirm with entropy — encrypted ⇒ ≈8.0, plaintext code ⇒ ≈6–7:

```python
import math, collections
r = d[cryptoff:cryptoff + cryptsize]
c = collections.Counter(r); n = len(r)
print("entropy", -sum(v/n * math.log2(v/n) for v in c.values()))
```

## How to decrypt (only if `cryptid == 1`)

FairPlay encryption **cannot be removed statically/offline** — the decryption key is fused to
Apple hardware. The real options:

1. **Dump from a jailbroken device** (the standard route): `frida-ios-dump`, `bagbak`, or
   `dumpdecrypted`. These read the decrypted pages out of memory after `dyld` maps the binary,
   then rewrite the Mach-O with `cryptid=0`.
2. **flexdecrypt / `Clutch`** on-device.
3. Source the decrypted IPA from an archive that already stripped FairPlay.

After any dump, sanity-check the result with the verification snippet above (`cryptid` should
be 0 and entropy should drop).

## Working agreements

- This binary is **already plaintext** — jump straight to static analysis (header/load-command
  parsing, string extraction, Swift/ObjC class dumping, ARM64 disassembly). No dump step needed.
- Treat the binary as **read-only reference**; do not modify `MobileFilter` in place. Write any
  patched/derived output to a new filename.
- All offsets above are **file offsets**, not VM addresses — convert via the segment/section
  tables when correlating with a disassembler.
- Keep analysis scripts and intermediate output out of the repo root; use the scratchpad.
