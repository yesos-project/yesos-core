#!/usr/bin/env python3
"""
Build-time check: the kernel image contains no symbol starting with any of
the given prefixes (local symbols included). core.mk forbids the symbols of
every optional core module that was not selected (font_ g_font_ without
"gfx", ledit_ without "lineedit"); a product adds its own with
FORBIDDEN_SYMBOLS, e.g. NAS and Security forbid the Desktop drivers
(hda_ audio_ display_ input_ terminal_ wav_ desktop_
surf_ files_) so that none of them can be linked in
by mistake.

Usage: check_symbols.py <kernel.elf> <prefix>...     (exit 1 on violation)
"""
import subprocess
import sys


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    elf, prefixes = sys.argv[1], sys.argv[2:]
    if not prefixes:
        return 0
    out = subprocess.run(["llvm-nm", elf], capture_output=True, text=True, check=True).stdout
    bad = []
    for line in out.splitlines():
        name = line.split()[-1]
        if any(name.startswith(p) for p in prefixes):
            bad.append(name)
    if bad:
        print(f"check_symbols: {elf}: {len(bad)} forbidden symbol(s): " + ", ".join(sorted(bad)[:20]),
              file=sys.stderr)
        return 1
    print(f"check_symbols: {elf}: none of {' '.join(prefixes)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
