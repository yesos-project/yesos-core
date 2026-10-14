#!/usr/bin/env python3
"""
Build-time check: no code reachable from the key hart's service loop may use
vector instructions, because the vault key lives in vector registers.

Walks the static call graph of the linked ELF from `keyhart_loop_entry`
(direct calls, tail jumps and auipc+jalr far calls). Only the dedicated
primitives in kernel/keyhart_vkey.S may contain vector instructions.
Indirect calls cannot be followed statically and make the check fail.

Usage: check_keyhart_vector.py <kernel.elf>     (exit 1 on violation)
"""
import re
import subprocess
import sys

import os
ROOT = os.environ.get("KEYHART_CHECK_ROOT", "keyhart_loop_entry")
ALLOWED_VECTOR = {"kh_vk_load", "kh_vk_clear", "kh_vk_clear_sub", "kh_vk_hchacha", "kh_vk_chacha_xor",
                  "kh_vk_chacha_to_slot", "kh_vk_chacha_from_slot", "kh_vk_count"}
VECTOR_RE = re.compile(r"^(v[a-z0-9]+\.[a-z0-9.]+|vset[i]?vl[i]?|vl[0-9a-z]+\.v|vs[0-9a-z]+\.v)$")


def functions(elf):
    out = subprocess.run(["llvm-nm", "-S", "--defined-only", elf], capture_output=True, text=True, check=True).stdout
    funcs = []
    for line in out.splitlines():
        p = line.split()
        if len(p) == 4 and p[2] in "tT" and int(p[1], 16) > 0:
            funcs.append((int(p[0], 16), int(p[0], 16) + int(p[1], 16), p[3]))
    # asm labels without size: give them the range up to the next symbol
    out = subprocess.run(["llvm-nm", "-n", "--defined-only", elf], capture_output=True, text=True, check=True).stdout
    syms = [(int(l.split()[0], 16), l.split()[2]) for l in out.splitlines()
            if len(l.split()) == 3 and l.split()[1] in "tT" and not l.split()[2].startswith(".L")]
    sized = {f[2] for f in funcs}
    for i, (addr, name) in enumerate(syms):
        if name not in sized and i + 1 < len(syms):
            funcs.append((addr, syms[i + 1][0], name))
    funcs.sort()
    return funcs


def owner(funcs, addr):
    lo, hi = 0, len(funcs) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        s, e, n = funcs[mid]
        if addr < s:
            hi = mid - 1
        elif addr >= e:
            lo = mid + 1
        else:
            return funcs[mid]
    return None


def main():
    elf = sys.argv[1]
    funcs = functions(elf)
    by_name = {}
    for f in funcs:
        by_name.setdefault(f[2], f)
    dis = subprocess.run(["llvm-objdump", "-d", "--no-show-raw-insn", "-M", "no-aliases", elf],
                         capture_output=True, text=True, check=True).stdout
    insns = {}
    for line in dis.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\s+(\S+)\s*(.*)$", line)
        if m:
            insns[int(m.group(1), 16)] = (m.group(2), m.group(3))
    addrs = sorted(insns)

    def body(f):
        import bisect
        i = bisect.bisect_left(addrs, f[0])
        while i < len(addrs) and addrs[i] < f[1]:
            yield addrs[i], insns[addrs[i]]
            i += 1

    if ROOT not in by_name:
        print(f"check_keyhart_vector: {ROOT} not found", file=sys.stderr)
        sys.exit(2)
    seen, todo, problems = set(), [by_name[ROOT]], []
    while todo:
        f = todo.pop()
        if f[2] in seen:
            continue
        seen.add(f[2])
        auipc = {}
        for addr, (mn, ops) in body(f):
            if VECTOR_RE.match(mn) and f[2] not in ALLOWED_VECTOR:
                problems.append(f"{f[2]} uses vector instruction '{mn}' at 0x{addr:x}")
            targets = []
            if mn == "jal":
                m = re.search(r"0x([0-9a-f]+)", ops)
                if m:
                    targets.append(int(m.group(1), 16))
            elif mn == "auipc":
                m = re.match(r"(\w+),\s*(-?0x[0-9a-f]+|-?\d+)", ops)
                if m:
                    auipc[m.group(1)] = addr + (int(m.group(2), 0) << 12)
            elif mn == "jalr":
                m = re.match(r"(\w+),\s*(-?0x[0-9a-f]+|-?\d+)\((\w+)\)", ops)
                if m:
                    rd, off, rs1 = m.group(1), int(m.group(2), 0), m.group(3)
                    if rs1 in auipc:
                        targets.append(auipc[rs1] + off)
                    elif not (rd == "zero" and rs1 == "ra" and off == 0):   # plain ret
                        problems.append(f"{f[2]}: indirect jump/call at 0x{addr:x} ({ops})")
            for t in targets:
                g = owner(funcs, t)
                if g and g[2] != f[2]:
                    todo.append(g)
    print(f"check_keyhart_vector: {len(seen)} functions reachable from {ROOT}")
    if problems:
        for p in problems:
            print("  VIOLATION:", p)
        sys.exit(1)
    print("check_keyhart_vector: OK - no vector instruction outside kernel/keyhart_vkey.S")


if __name__ == "__main__":
    main()
