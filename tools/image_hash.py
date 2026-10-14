#!/usr/bin/env python3
"""
Writes the BLAKE2b-256 of the kernel's .text || .rodata sections into the
ELF's .integrity section (KernelImageHash in include/integrity.h). The key
hart recomputes it at boot and before arming the runtime integrity monitor.

This is a corruption check (storage, transfer, memory faults), not a
signature: whoever can rewrite the image can rewrite this hash too.

Usage: image_hash.py <kernel.elf>
"""
import hashlib
import os
import struct
import subprocess
import sys
import tempfile

MAGIC = 0x48474D49  # "IMGH"
FMT = "<IIQQ32s"     # magic, version, text_len, rodata_len, hash (64 bytes total with padding)
SIZE = 64


def section_bytes(elf, name):
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name
    try:
        subprocess.run(["llvm-objcopy", "-O", "binary", f"--only-section={name}", elf, path], check=True)
        with open(path, "rb") as f:
            return f.read()
    finally:
        os.unlink(path)


def section_size(elf, name):
    out = subprocess.run(["llvm-objdump", "-h", elf], capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 3 and p[1] == name:
            return int(p[2], 16)
    return None


def main():
    elf = sys.argv[1]
    text = section_bytes(elf, ".text")
    rodata = section_bytes(elf, ".rodata")
    digest = hashlib.blake2b(text + rodata, digest_size=32).digest()
    blob = struct.pack(FMT, MAGIC, 1, len(text), len(rodata), digest).ljust(SIZE, b"\0")
    if section_size(elf, ".integrity") != SIZE:
        print(f"image_hash: FAILED: .integrity must be {SIZE} bytes", file=sys.stderr)
        sys.exit(1)
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(blob)
        path = f.name
    try:
        subprocess.run(["llvm-objcopy", f"--update-section=.integrity={path}", elf], check=True)
    finally:
        os.unlink(path)
    print(f"image_hash: .text {len(text)} B + .rodata {len(rodata)} B -> blake2b-256 {digest.hex()[:16]}...")


if __name__ == "__main__":
    main()
