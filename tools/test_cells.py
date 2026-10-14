#!/usr/bin/env python3
"""
Boot test for PMP cells (phase 2): hart 3 must lock its cell layout, and
hostile programs run in it must be contained by hardware (PMP), the
instruction verifier and the watchdog. Non-zero exit status on failure.
"""
import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import yesos_harness as harness  # noqa: E402

failures = []


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label)
    if not cond:
        failures.append(label)


def main():
    tmpdir = tempfile.mkdtemp(prefix="yesos_cells_")
    disk = os.path.join(tmpdir, "disk.img")
    shutil.copyfile(harness.SRC_DISK, disk)
    vm = harness.YesOS(disk, 40000 + os.getpid() % 20000)
    try:
        check(vm.wait_for("YesOS [", 90), "system boots")
        out = vm.output()
        check("PMP cell on hart 3: locked" in out, "hart 3 locked its cell layout and the readback verified")
        check("FATAL" not in out and "RISC-V EXCEPTION" not in out, "no faults during boot")

        m = vm.send("cell test", 12)
        res = vm.since(m)
        check("ALL HOSTILE PROGRAMS CONTAINED" in res, "cell security self-test")
        npass = res.count("[PASS]")
        check(npass == 19 and "[FAIL]" not in res, f"self-test: {npass}/19 checks")
        check("hello from an isolated cell, x=42" in res, "cell output arrives through the RPC")
        check("<pointer outside cell refused>" in res, "kernel pointer passed to print is refused")
        check("KERNEL-SECRET" not in res, "kernel secret never printed")

        m = vm.send("write /HOME/SQ.HQ I64 sq(I64 x) { return x * x + 1; }", 3)
        m = vm.send("cell run /HOME/SQ.HQ 12", 4)
        check("[CELL] result = 145" in vm.since(m), "cell run executes a HolyQ file in the cell")

        m = vm.send("pmp test", 3)
        check("ALL PROBES MATCH THE POLICY" in vm.since(m), "kernel PMP self-test still passes")
        time.sleep(1)
    finally:
        vm.stop()
        shutil.rmtree(tmpdir, ignore_errors=True)

    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED")
        sys.exit(1)
    print("All checks passed")


if __name__ == "__main__":
    main()
