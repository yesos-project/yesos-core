#!/usr/bin/env python3
"""
Build-time check: the kernel image contains no floating-point instructions.

YesOS keeps all of its arithmetic in integers (fixed point where fractions
are needed). This disassembles every executable section of the linked ELF and
fails on any F/D instruction, compressed forms (c.fld, c.fsd, ...) included.
The only exception is resetting the FP status register (`fscsr zero` /
`csrw fcsr`) at boot, which is a CSR write, not arithmetic. Vector loads and
stores share the FP major opcodes but disassemble as v*, so they are not
affected.

Usage: check_no_fp.py <kernel.elf>     (exit 1 on violation)
"""
import re
import subprocess
import sys

FP_RE = re.compile(r"^(c\.)?f(?!ence)[a-z0-9.]+$")
ALLOWED = {"fscsr", "fsflags", "fsrm"}          # writes of the FP status/control CSR
LINE_RE = re.compile(r"^\s*([0-9a-f]+):\s+(\S+)(?:\s+(.*))?$")
FUNC_RE = re.compile(r"^[0-9a-f]+ <(.+)>:$")


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    elf = sys.argv[1]
    out = subprocess.run(["llvm-objdump", "-d", "--no-show-raw-insn", elf],
                         capture_output=True, text=True, check=True).stdout
    func = "?"
    bad = []
    for line in out.splitlines():
        m = FUNC_RE.match(line)
        if m:
            func = m.group(1)
            continue
        m = LINE_RE.match(line)
        if not m:
            continue
        mnem, args = m.group(2), (m.group(3) or "")
        if FP_RE.match(mnem) and mnem not in ALLOWED:
            bad.append(f"0x{m.group(1)} <{func}>: {mnem} {args}".rstrip())
    if bad:
        print(f"check_no_fp: {elf}: {len(bad)} floating-point instruction(s); the kernel must be integer-only:")
        for b in bad[:20]:
            print("  " + b)
        if len(bad) > 20:
            print(f"  ... and {len(bad) - 20} more")
        return 1
    print(f"check_no_fp: {elf}: no floating-point instructions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
