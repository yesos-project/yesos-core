#!/usr/bin/env python3
"""
YesOS 2.0 - Build-time PMP prover.

Reads the policy boundaries from a linked kernel ELF, generates the PMP
register layout (independently of kernel/pmp.c), and uses the Z3 SMT solver to
prove, for EVERY physical address and access type, that the RISC-V PMP
semantics of that layout in Machine mode equal the policy. It also proves the
security invariants directly on the hardware model. On success it writes a
certificate into the ELF's .pmp_proof section; the kernel refuses to boot if
its own layout differs from the certificate.

Hardware model (RISC-V Privileged Spec, "Physical Memory Protection"):
  - entries are checked in order; the lowest-numbered match decides;
  - TOR i matches pmpaddr[i-1]<<2 <= a < pmpaddr[i]<<2 (pmpaddr[-1] = 0);
  - NAPOT matches when ((a>>2) | t) == (pmpaddr | t), t = pmpaddr ^ (pmpaddr+1);
  - in M-mode a matching entry restricts access only if its L bit is set;
  - in M-mode an address matched by no entry is ALLOWED.

Usage: pmp_prover.py <kernel.elf> [--no-patch] [--self-test]
Exit status: 0 proven (and patched), 1 disproven/invalid, 2 tool error.
"""

import os
import struct
import subprocess
import sys
import tempfile

try:
    import z3
except ImportError:
    print("pmp_prover: z3 not available (python -m pip install z3-solver)", file=sys.stderr)
    sys.exit(2)

PA_BITS = 56
MAX_ENTRIES = 16
R, W, X = 1, 2, 4
A_TOR, A_NAPOT, L = 0x08, 0x18, 0x80
PROOF_MAGIC = 0x56504D50
PROOF_VERSION = 3
PROOF_CELLS = 5
CELL_SLOTS = 8
PROOF_FMT = f"<IIII16Q16BII{PROOF_CELLS * CELL_SLOTS}Q{PROOF_CELLS * CELL_SLOTS}BII16Q16B32s"
SYMBOLS = ["_kernel_start", "_text_end", "_rodata_end", "_jit_start", "_jit_end", "_ram_end",
           "_pmp_null_end", "_pmp_mmio_start", "_pmp_mmio_end",
           "_cell_text_start", "_cell_text_end", "_cell_area_start",
           "_keyvault_start", "_keyvault_end"]
CELL_HEADER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "include", "cell.h")


def read_cell_constants():
    """Cell geometry comes from include/cell.h, the same header the kernel uses."""
    consts = {}
    with open(CELL_HEADER, encoding="utf-8") as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "#define" and parts[1].startswith("CELL_"):
                try:
                    consts[parts[1]] = int(parts[2], 0)
                except ValueError:
                    pass
    for k in ("CELL_MAX", "CELL_STRIDE", "CELL_CODE_SIZE", "CELL_PMP_ENTRIES"):
        if k not in consts:
            fail(f"{k} missing from include/cell.h", 2)
    if consts["CELL_MAX"] != PROOF_CELLS or consts["CELL_PMP_ENTRIES"] != CELL_SLOTS:
        fail("include/cell.h geometry does not match the certificate format", 2)
    return consts


def fail(msg, code=1):
    print(f"pmp_prover: FAILED: {msg}", file=sys.stderr)
    sys.exit(code)


def read_symbols(elf):
    out = subprocess.run(["llvm-nm", elf], capture_output=True, text=True, check=True).stdout
    syms = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] in SYMBOLS:
            syms[parts[2]] = int(parts[0], 16)
    missing = [s for s in SYMBOLS if s not in syms]
    if missing:
        fail(f"symbols missing from ELF: {missing}", 2)
    return syms


def finalize(regions):
    regions = sorted((r for r in regions if r[1] > r[0]), key=lambda r: r[0])
    for i, (lo, hi, perm, name) in enumerate(regions):
        if lo % 4096 or hi % 4096:
            fail(f"region {name} not 4 KiB aligned")
        if i and lo < regions[i - 1][1]:
            fail(f"regions {regions[i - 1][3]} and {name} overlap")
    return regions


def cell_regions(s, c, k):
    base = s["_cell_area_start"] + k * c["CELL_STRIDE"]
    return finalize([
        (s["_cell_text_start"], s["_cell_text_end"], R | X, "cell-runtime"),
        (base, base + c["CELL_CODE_SIZE"], R | X, "cell-code"),
        (base + c["CELL_CODE_SIZE"], base + c["CELL_STRIDE"], R | W, "cell-data"),
    ])


def build_policy(s):
    regions = [
        (0, s["_pmp_null_end"], 0, "null-guard"),
        (s["_pmp_mmio_start"], s["_pmp_mmio_end"], R | W, "mmio"),
        (s["_kernel_start"], s["_text_end"], R | X, "kernel-text"),
        (s["_text_end"], s["_rodata_end"], R, "rodata"),
        (s["_rodata_end"], s["_jit_start"], R | W, "data-bss-stacks"),
        (s["_jit_start"], s["_jit_end"], R | W | X, "jit-arena"),
        (s["_keyvault_start"], s["_keyvault_end"], 0, "key-vault"),
        (s["_keyvault_end"], s["_ram_end"], R | W, "heap"),
    ]
    return finalize(regions)


def keyhart_regions(s):
    return finalize([
        (0, s["_pmp_null_end"], 0, "null-guard"),
        (s["_kernel_start"], s["_text_end"], R | X, "kernel-text"),
        (s["_text_end"], s["_rodata_end"], R, "rodata"),
        (s["_rodata_end"], s["_jit_start"], R | W, "data-bss-stacks"),
        (s["_keyvault_start"], s["_keyvault_end"], R | W, "key-vault"),
        (s["_keyvault_end"], s["_ram_end"], R | W, "heap"),
    ])


def build_layout(regions):
    addrs, cfgs, cur = [], [], 0
    for lo, hi, perm, _ in regions:
        if lo > cur:
            addrs.append(lo >> 2)
            cfgs.append(L | A_TOR)
        addrs.append(hi >> 2)
        cfgs.append(L | A_TOR | perm)
        cur = hi
    addrs.append((1 << (PA_BITS - 2)) - 1)
    cfgs.append(L | A_NAPOT)
    if len(addrs) > MAX_ENTRIES:
        fail(f"layout needs {len(addrs)} entries (max {MAX_ENTRIES})")
    return addrs, cfgs


# -----------------------------------------------------------------------------
# Z3 model
# -----------------------------------------------------------------------------

def bv(v):
    return z3.BitVecVal(v, 64)


def match(a, addrs, cfgs, i):
    mode = cfgs[i] & 0x18
    if mode == A_TOR:
        lo = bv(0) if i == 0 else bv(addrs[i - 1] << 2)
        return z3.And(z3.ULE(lo, a), z3.ULT(a, bv(addrs[i] << 2)))
    if mode == A_NAPOT:
        y = addrs[i]
        t = y ^ (y + 1)
        return (z3.LShR(a, 2) | bv(t)) == bv(y | t)
    raise ValueError("unsupported mode in model")


def hw_allows(a, addrs, cfgs, perm_bit):
    """M-mode access decision of the hardware for access type perm_bit."""
    expr = z3.BoolVal(True)                     # no match: M-mode allowed
    for i in reversed(range(len(addrs))):
        locked = bool(cfgs[i] & L)
        allowed = z3.BoolVal((cfgs[i] & perm_bit) != 0) if locked else z3.BoolVal(True)
        expr = z3.If(match(a, addrs, cfgs, i), allowed, expr)
    return expr


def governed_by_locked(a, addrs, cfgs):
    expr = z3.BoolVal(False)
    for i in reversed(range(len(addrs))):
        expr = z3.If(match(a, addrs, cfgs, i), z3.BoolVal(bool(cfgs[i] & L)), expr)
    return expr


def policy_allows(a, regions, perm_bit):
    return z3.Or([z3.And(z3.ULE(bv(lo), a), z3.ULT(a, bv(hi)))
                  for lo, hi, perm, _ in regions if perm & perm_bit] or [z3.BoolVal(False)])


def in_range(a, lo, hi):
    return z3.And(z3.ULE(bv(lo), a), z3.ULT(a, bv(hi)))


def prove(name, claim_violation, a, limit):
    """Proves that no address below `limit` satisfies `claim_violation`."""
    s = z3.Solver()
    s.add(z3.ULT(a, bv(limit)), claim_violation)
    r = s.check()
    if r == z3.unsat:
        print(f"  [PROVEN] {name}")
        return True
    if r == z3.sat:
        print(f"  [FALSE ] {name}: counterexample address 0x{s.model()[a].as_long():x}")
    else:
        print(f"  [UNKNOWN] {name}")
    return False


def run_proofs(addrs, cfgs, regions, s):
    a = z3.BitVec("addr", 64)
    limit = 1 << PA_BITS
    ok = True
    for bit, label in ((R, "read"), (W, "write"), (X, "execute")):
        ok &= prove(f"hardware {label} permission == policy for all addresses",
                    hw_allows(a, addrs, cfgs, bit) != policy_allows(a, regions, bit), a, limit)
    ok &= prove("every address is governed by a locked entry (no M-mode default allow)",
                z3.Not(governed_by_locked(a, addrs, cfgs)), a, limit)
    ok &= prove("W^X: no address is writable and executable outside the JIT arena",
                z3.And(hw_allows(a, addrs, cfgs, W), hw_allows(a, addrs, cfgs, X),
                       z3.Not(in_range(a, s["_jit_start"], s["_jit_end"]))), a, limit)
    ok &= prove("kernel code is never writable",
                z3.And(in_range(a, s["_kernel_start"], s["_text_end"]), hw_allows(a, addrs, cfgs, W)), a, limit)
    ok &= prove("read-only data is never writable or executable",
                z3.And(in_range(a, s["_text_end"], s["_rodata_end"]),
                       z3.Or(hw_allows(a, addrs, cfgs, W), hw_allows(a, addrs, cfgs, X))), a, limit)
    ok &= prove("NULL guard denies read, write and execute",
                z3.And(in_range(a, 0, s["_pmp_null_end"]),
                       z3.Or(hw_allows(a, addrs, cfgs, R), hw_allows(a, addrs, cfgs, W),
                             hw_allows(a, addrs, cfgs, X))), a, limit)
    ok &= prove("data, stacks and heap are never executable",
                z3.And(z3.Or(in_range(a, s["_rodata_end"], s["_jit_start"]),
                             in_range(a, s["_jit_end"], s["_ram_end"])),
                       hw_allows(a, addrs, cfgs, X)), a, limit)
    ok &= prove("key vault is unreachable (no read, write or execute) on kernel harts",
                z3.And(in_range(a, s["_keyvault_start"], s["_keyvault_end"]),
                       z3.Or(hw_allows(a, addrs, cfgs, R), hw_allows(a, addrs, cfgs, W),
                             hw_allows(a, addrs, cfgs, X))), a, limit)
    ok &= prove("device registers are never executable",
                z3.And(in_range(a, s["_pmp_mmio_start"], s["_pmp_mmio_end"]),
                       hw_allows(a, addrs, cfgs, X)), a, limit)
    return ok


def run_cell_proofs(addrs, cfgs, regions, s, c, k):
    """A cell may only touch its runtime (R-X), its code (R-X) and its data (RW-)."""
    a = z3.BitVec("addr", 64)
    limit = 1 << PA_BITS
    base = s["_cell_area_start"] + k * c["CELL_STRIDE"]
    code = (base, base + c["CELL_CODE_SIZE"])
    data = (base + c["CELL_CODE_SIZE"], base + c["CELL_STRIDE"])
    runtime = (s["_cell_text_start"], s["_cell_text_end"])
    any_access = lambda: z3.Or(hw_allows(a, addrs, cfgs, R), hw_allows(a, addrs, cfgs, W),
                               hw_allows(a, addrs, cfgs, X))
    own = z3.Or(in_range(a, *code), in_range(a, *data), in_range(a, *runtime))
    tag = f"cell {k}:"
    ok = True
    for bit, label in ((R, "read"), (W, "write"), (X, "execute")):
        ok &= prove(f"{tag} hardware {label} permission == cell policy",
                    hw_allows(a, addrs, cfgs, bit) != policy_allows(a, regions, bit), a, limit)
    ok &= prove(f"{tag} every address governed by a locked entry",
                z3.Not(governed_by_locked(a, addrs, cfgs)), a, limit)
    ok &= prove(f"{tag} no access at all outside its runtime, code and data (kernel, vault, devices, other cells)",
                z3.And(z3.Not(own), any_access()), a, limit)
    ok &= prove(f"{tag} kernel data/BSS (vault key) unreadable",
                z3.And(in_range(a, s["_rodata_end"], s["_jit_start"]), hw_allows(a, addrs, cfgs, R)), a, limit)
    ok &= prove(f"{tag} W^X: nothing writable and executable",
                z3.And(hw_allows(a, addrs, cfgs, W), hw_allows(a, addrs, cfgs, X)), a, limit)
    ok &= prove(f"{tag} its code and the runtime are not writable",
                z3.And(z3.Or(in_range(a, *code), in_range(a, *runtime)), hw_allows(a, addrs, cfgs, W)), a, limit)
    ok &= prove(f"{tag} its data is not executable",
                z3.And(in_range(a, *data), hw_allows(a, addrs, cfgs, X)), a, limit)
    return ok


def run_keyhart_proofs(addrs, cfgs, regions, s):
    a = z3.BitVec("addr", 64)
    limit = 1 << PA_BITS
    ok = True
    for bit, label in ((R, "read"), (W, "write"), (X, "execute")):
        ok &= prove(f"key hart: hardware {label} permission == key hart policy",
                    hw_allows(a, addrs, cfgs, bit) != policy_allows(a, regions, bit), a, limit)
    ok &= prove("key hart: every address governed by a locked entry",
                z3.Not(governed_by_locked(a, addrs, cfgs)), a, limit)
    ok &= prove("key hart: W^X everywhere (it never runs generated code)",
                z3.And(hw_allows(a, addrs, cfgs, W), hw_allows(a, addrs, cfgs, X)), a, limit)
    ok &= prove("key hart: key vault is never executable",
                z3.And(in_range(a, s["_keyvault_start"], s["_keyvault_end"]), hw_allows(a, addrs, cfgs, X)), a, limit)
    ok &= prove("key hart: no access to device registers",
                z3.And(in_range(a, s["_pmp_mmio_start"], s["_pmp_mmio_end"]),
                       z3.Or(hw_allows(a, addrs, cfgs, R), hw_allows(a, addrs, cfgs, W))), a, limit)
    ok &= prove("key hart: no access to the JIT arena",
                z3.And(in_range(a, s["_jit_start"], s["_jit_end"]),
                       z3.Or(hw_allows(a, addrs, cfgs, R), hw_allows(a, addrs, cfgs, W),
                             hw_allows(a, addrs, cfgs, X))), a, limit)
    ok &= prove("key hart: kernel code is not writable",
                z3.And(in_range(a, s["_kernel_start"], s["_text_end"]), hw_allows(a, addrs, cfgs, W)), a, limit)
    return ok


def section_size(elf, name):
    out = subprocess.run(["llvm-objdump", "-h", elf], capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] == name:
            return int(parts[2], 16)
    fail(f"section {name} not found", 2)


def patch_elf(elf, addrs, cfgs, cells, kh):
    count = len(addrs)
    tag = f"z3 {z3.get_version_string()}".encode()[:31]
    cell_entries = len(cells[0][0]) if cells else 0
    cell_addr, cell_cfg = [], []
    for k in range(PROOF_CELLS):
        ca, cc = cells[k] if k < len(cells) else ([], [])
        cell_addr += ca + [0] * (CELL_SLOTS - len(ca))
        cell_cfg += cc + [0] * (CELL_SLOTS - len(cc))
    blob = struct.pack(PROOF_FMT, PROOF_MAGIC, PROOF_VERSION, count, len(cells),
                       *(addrs + [0] * (MAX_ENTRIES - count)),
                       *(cfgs + [0] * (MAX_ENTRIES - count)),
                       cell_entries, 0, *cell_addr, *cell_cfg,
                       len(kh[0]), 0, *(kh[0] + [0] * (MAX_ENTRIES - len(kh[0]))),
                       *(kh[1] + [0] * (MAX_ENTRIES - len(kh[1]))), tag)
    # llvm-objcopy would silently shrink or grow the section: refuse any mismatch.
    if section_size(elf, ".pmp_proof") != len(blob):
        fail(f".pmp_proof is {section_size(elf, '.pmp_proof')} bytes, certificate is {len(blob)} "
             "(PmpProof in include/pmp.h and PROOF_FMT disagree)", 2)
    with tempfile.NamedTemporaryFile(suffix=".pmp_proof", delete=False) as f:
        f.write(blob)
        path = f.name
    try:
        subprocess.run(["llvm-objcopy", f"--update-section=.pmp_proof={path}", elf], check=True)
    finally:
        os.unlink(path)


def mutation_self_test(addrs, cfgs, regions, s):
    """The prover must reject deliberately broken layouts (a proof that can
    never fail proves nothing)."""
    import contextlib
    import io

    text_idx = next(i for i, c in enumerate(cfgs) if (c & 7) == (R | X))
    heap_idx = len(cfgs) - 2
    mutants = {
        "catch-all removed": (addrs[:-1], cfgs[:-1]),
        "catch-all unlocked": (addrs, cfgs[:-1] + [cfgs[-1] & ~L]),
        "kernel text writable": (addrs, [c | W if i == text_idx else c for i, c in enumerate(cfgs)]),
        "kernel text entry unlocked": (addrs, [c & ~L if i == text_idx else c for i, c in enumerate(cfgs)]),
        "heap executable": (addrs, [c | X if i == heap_idx else c for i, c in enumerate(cfgs)]),
        "text boundary off by one page": ([a + (4096 >> 2) if i == text_idx else a for i, a in enumerate(addrs)], cfgs),
        "null guard readable": (addrs, [cfgs[0] | R] + cfgs[1:]),
        "key vault readable on kernel harts": (addrs, [c | R if (i > 0 and (addrs[i - 1] << 2) == s["_keyvault_start"]) else c
                                                       for i, c in enumerate(cfgs)]),
    }
    ok = True
    for name, (ma, mc) in mutants.items():
        with contextlib.redirect_stdout(io.StringIO()):
            proven = run_proofs(list(ma), list(mc), regions, s)
        print(f"  [{'DETECTED' if not proven else 'MISSED  '}] mutant: {name}")
        ok &= not proven
    return ok


def cell_mutation_self_test(addrs, cfgs, regions, s, c):
    import contextlib
    import io

    code_idx = next(i for i, a in enumerate(addrs)
                    if (a << 2) == s["_cell_area_start"] + c["CELL_CODE_SIZE"])
    data_idx = code_idx + 1
    other_cell = c["CELL_STRIDE"] >> 2
    mutants = {
        "cell code writable": (addrs, [x | W if i == code_idx else x for i, x in enumerate(cfgs)]),
        "cell data executable": (addrs, [x | X if i == data_idx else x for i, x in enumerate(cfgs)]),
        "cell data reaches next cell": ([x + other_cell if i == data_idx else x for i, x in enumerate(addrs)], cfgs),
        "cell catch-all removed": (addrs[:-1], cfgs[:-1]),
        "cell entry unlocked": (addrs, [x & ~L if i == data_idx else x for i, x in enumerate(cfgs)]),
        "cell can read below runtime (kernel)": (addrs, [cfgs[0] | R] + cfgs[1:]),
    }
    ok = True
    for name, (ma, mc) in mutants.items():
        with contextlib.redirect_stdout(io.StringIO()):
            proven = run_cell_proofs(list(ma), list(mc), regions, s, c, 0)
        print(f"  [{'DETECTED' if not proven else 'MISSED  '}] mutant: {name}")
        ok &= not proven
    return ok


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    elf = sys.argv[1]
    s = read_symbols(elf)
    regions = build_policy(s)
    addrs, cfgs = build_layout(regions)

    print(f"pmp_prover: {os.path.basename(elf)} - {len(addrs)} entries, {PA_BITS}-bit physical address space")
    for lo, hi, perm, name in regions:
        p = ("R" if perm & R else "-") + ("W" if perm & W else "-") + ("X" if perm & X else "-")
        print(f"  policy [0x{lo:010x}, 0x{hi:010x}) {p}  {name}")
    if not run_proofs(addrs, cfgs, regions, s):
        fail("PMP layout does not satisfy the policy")

    c = read_cell_constants()
    cells = []
    for k in range(c["CELL_MAX"]):
        cregions = cell_regions(s, c, k)
        ca, cc = build_layout(cregions)
        if len(ca) > CELL_SLOTS:
            fail(f"cell {k} layout needs {len(ca)} entries (max {CELL_SLOTS})")
        if not run_cell_proofs(ca, cc, cregions, s, c, k):
            fail(f"cell {k} PMP layout does not isolate the cell")
        cells.append((ca, cc))

    kregions = keyhart_regions(s)
    ka, kc = build_layout(kregions)
    if not run_keyhart_proofs(ka, kc, kregions, s):
        fail("key hart PMP layout does not satisfy its policy")

    if "--self-test" in sys.argv:
        print("pmp_prover: mutation self-test")
        if not mutation_self_test(addrs, cfgs, regions, s):
            fail("prover accepted a broken layout")
        if not cell_mutation_self_test(cells[0][0], cells[0][1], cell_regions(s, c, 0), s, c):
            fail("prover accepted a broken cell layout")
    if "--no-patch" not in sys.argv:
        patch_elf(elf, addrs, cfgs, cells, (ka, kc))
        print("pmp_prover: certificate written to .pmp_proof")


if __name__ == "__main__":
    main()
