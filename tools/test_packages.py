#!/usr/bin/env python3
"""
Packages (.ypk) run in PMP cells.

Builds packages on the host (tools/deploy_app.py), injects them into a
scratch disk (tools/redsea_injector.py), then installs and runs them inside
YesOS: the real HolySynth app, a multi-function program with forward calls,
hostile packages, and a malformed package for the installer.
Non-zero exit status on failure.
"""
import io
import os
import shutil
import subprocess
import sys
import tempfile
import time
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import yesos_harness as harness  # noqa: E402
import deploy_app  # noqa: E402
import redsea_injector  # noqa: E402

ROOT = harness.ROOT
failures = []


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label)
    if not cond:
        failures.append(label)


def kernel_symbol(name):
    out = subprocess.run(["llvm-nm", harness.KERNEL], capture_output=True, text=True).stdout
    for line in out.splitlines():
        p = line.split()
        if len(p) == 3 and p[2] == name:
            return int(p[0], 16)
    raise KeyError(name)


def make_pkg(tmp, name, main_hq):
    d = os.path.join(tmp, name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "APP.INFO"), "w") as f:
        f.write(f"NAME={name}\nID=test.{name.lower()}\nEXEC=MAIN.HQ\nICON=PKG\nVERSION=1.0\nAUTHOR=test\n")
    with open(os.path.join(d, "MAIN.HQ"), "w") as f:
        f.write(main_hq)
    with redirect_stdout(io.StringIO()):
        return deploy_app.pack_app_folder(d)


MULTI = """
extern U0 kprintf(U8* fmt, ...);
U0 Main() {
    kprintf("sum of squares 1..10 = %d\\n", SumSquares(10));
    kprintf("fib(15) = %d\\n", Fib(15));
}
I64 Square(I64 x) { return x * x; }
I64 SumSquares(I64 n) {
    I64 s = 0;
    I64 i = 1;
    while (i <= n) { s = s + Square(i); i = i + 1; }
    return s;
}
I64 Fib(I64 n) { if (n < 2) { return n; } return Fib(n - 1) + Fib(n - 2); }
Main();
"""


def main():
    tmp = tempfile.mkdtemp(prefix="yesos_pkg_")
    disk = os.path.join(tmp, "disk.img")
    shutil.copyfile(harness.SRC_DISK, disk)

    secret_addr = kernel_symbol("g_cell_selftest_marker")
    pkgs = {
        "PKG/SYNTH.YPK": None,
        "PKG/MULTI.YPK": make_pkg(tmp, "Multi", MULTI),
        "PKG/EVILREAD.YPK": make_pkg(tmp, "EvilRead",
            f'U0 Steal() {{ I64 p = 0x{secret_addr:x}; kprintf("stolen: %x\\n", p[0]); }}\nSteal();\n'),
        "PKG/EVILCALL.YPK": make_pkg(tmp, "EvilCall", 'U0 Go() { Malloc(4096); }\nGo();\n'),
        "PKG/SPIN.YPK": make_pkg(tmp, "Spin", 'U0 Spin() { while (1) { } }\nSpin();\n'),
    }
    with redirect_stdout(io.StringIO()):
        pkgs["PKG/SYNTH.YPK"] = deploy_app.pack_app_folder(os.path.join(ROOT, "apps", "holysynth"))
    bad = bytearray(pkgs["PKG/MULTI.YPK"])
    bad[(4 + 4 + 32 * 4 + 16 + 32 + 4 + 4):(4 + 4 + 32 * 4 + 16 + 32 + 4 + 4) + 4] = (0x7FFFFFFF).to_bytes(4, "little")
    pkgs["PKG/BAD.YPK"] = bytes(bad)   # compressed_payload_size far beyond the file

    with redirect_stdout(io.StringIO()):
        for name, data in pkgs.items():
            assert redsea_injector.inject_bytes(disk, data, name), name

    vm = harness.YesOS(disk, 40000 + os.getpid() % 10000)
    try:
        check(vm.wait_for("YesOS [", 90), "system boots")

        m = vm.send("pkg install PKG/SYNTH.YPK", 3)
        check("installed into RedSea-EML" in vm.since(m), "HolySynth package installs")
        m = vm.send("pkg run HolySynth", 6)
        res = vm.since(m)
        check("in an isolated PMP cell" in res, "HolySynth is launched in a cell")
        check("[cell 3]" in res and "HOLYSYNTH v1.0" in res, "HolySynth output arrives from the cell")
        check("finished in its cell" in res, "HolySynth finishes normally (beeps and sleeps via RPC)")

        vm.send("pkg install PKG/MULTI.YPK", 3)
        m = vm.send("pkg run Multi", 5)
        res = vm.since(m)
        check("sum of squares 1..10 = 385" in res, "multi-function program with forward calls")
        check("fib(15) = 610" in res, "recursion inside a multi-function cell program")

        vm.send("pkg install PKG/EVILREAD.YPK", 3)
        m = vm.send("pkg run EvilRead", 5)
        res = vm.since(m)
        check("hardware fault mcause=5" in res and "stolen" not in res,
              "package reading kernel memory is stopped by the PMP")

        vm.send("pkg install PKG/EVILCALL.YPK", 3)
        m = vm.send("pkg run EvilCall", 4)
        check("kernel function not callable from a cell: 'Malloc'" in vm.since(m),
              "package calling a kernel function is rejected at compile time")

        vm.send("pkg install PKG/SPIN.YPK", 3)
        m = vm.send("pkg run Spin", 35)
        check("watchdog" in vm.since(m), "package that never returns is killed by the watchdog")

        m = vm.send("pkg install PKG/BAD.YPK", 3)
        res = vm.since(m)
        check("inconsistent payload sizes" in res, "installer rejects a malformed package")

        m = vm.send("pkg run Multi", 5)
        check("sum of squares 1..10 = 385" in vm.since(m), "cell still healthy after hostile packages")
        out = vm.output()
        check("FATAL" not in out and "RISC-V EXCEPTION" not in out, "no kernel faults at any point")
        time.sleep(1)
    finally:
        vm.stop()
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED")
        sys.exit(1)
    print("All checks passed")


if __name__ == "__main__":
    main()
