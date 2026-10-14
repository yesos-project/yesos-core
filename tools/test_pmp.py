#!/usr/bin/env python3
"""
Boot test for the locked, proven PMP layout (phase 1).

Boots YesOS headless in QEMU with 1 GiB of RAM: the kernel's policy only
covers 512 MiB, so the "read beyond end of RAM" probe hits real memory and
can only fault because of the PMP catch-all entry.

Checks: certificate accepted, every hart locked and verified, self-test probes
all match the policy, the JIT still compiles and runs code from its arena.
Usage: python3 tools/test_pmp.py      (non-zero exit status on failure)
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


class BigRamYesOS(harness.YesOS):
    def __init__(self, disk, host_port):
        orig = harness.subprocess.Popen

        def popen(cmd, *a, **kw):
            cmd = [("1G" if c == "512M" else c) for c in cmd]
            return orig(cmd, *a, **kw)

        harness.subprocess.Popen = popen
        try:
            super().__init__(disk, host_port)
        finally:
            harness.subprocess.Popen = orig


def main():
    tmpdir = tempfile.mkdtemp(prefix="yesos_pmp_")
    disk = os.path.join(tmpdir, "disk.img")
    shutil.copyfile(harness.SRC_DISK, disk)
    vm = BigRamYesOS(disk, 40000 + os.getpid() % 20000)
    try:
        check(vm.wait_for("YesOS [", 90), "system boots to shell with locked PMP")
        out = vm.output()
        check("Z3-proven + boot-verified" in out, "build-time certificate accepted by the kernel")
        check("FATAL" not in out and "RISC-V EXCEPTION" not in out, "no PMP faults during boot")

        m = vm.send("pmp test", 3)
        res = vm.since(m)
        check("ALL PROBES MATCH THE POLICY" in res, "self-test: every probe matches the policy")
        check(res.count("[PASS]") == 13 and "[FAIL]" not in res, "self-test: 13/13 probes (incl. key vault)")

        m = vm.send("pmp", 2)
        res = vm.since(m)
        check(res.count("LOCKED") >= 8, "pmp: all entries reported LOCKED on hart 0")
        check("Harts locked : 2" in res, "pmp: harts 0-1 locked and verified the kernel layout")
        # Secondary harts report asynchronously; under load the line can come late.
        check(vm.wait_for("Key hart 2: private key vault locked", 30), "hart 2 locked the key hart layout")
        check(vm.wait_for("PMP cell on hart 3: locked", 30), "hart 3 locked the (different) cell layout")

        m = vm.send("keyhart test", 3)
        res = vm.since(m)
        check("KEY NOT REACHABLE OUTSIDE THE KEY HART" in res, "key hart self-test (vault locked)")

        m = vm.send("I64 pmpjit(I64 a) { return a * 7 + 1; }", 2)
        m = vm.send("kprintf(\"JIT=%d\\n\", pmpjit(6));", 3)
        check("JIT=43" in vm.since(m), "JIT compiles and executes from the PMP arena")
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
