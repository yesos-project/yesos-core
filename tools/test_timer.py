#!/usr/bin/env python3
"""
Clock test: the kernel's uptime must follow real time. It is read from the
CLINT mtime counter; when it was counted from timer interrupts it fell ~3%
behind (lost ticks), which stretched every timeout and lockout. The guest
uptime is compared with the host clock over an idle stretch and over a
stretch of heavy work (Argon2id PIN hashing, cell and PMP self-tests).
Non-zero exit status on failure.
"""
import os
import re
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import yesos_harness as harness  # noqa: E402

TOLERANCE_S = 0.3   # serial round trips; the old clock drifted ~0.8 s per 30 s

failures = []


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label)
    if not cond:
        failures.append(label)


def uptime(vm):
    m = len(vm.output())
    t = time.monotonic()
    vm.send("uptime", 0.5)
    vm.wait_for("Uptime:", 10, m)
    v = re.search(r"Uptime: (\d+)\.(\d+) seconds", vm.since(m))
    return (int(v.group(1)) + int(v.group(2)) / 1000 if v else None), t


def compare(vm, label, work):
    g1, t1 = uptime(vm)
    work()
    g2, t2 = uptime(vm)
    if g1 is None or g2 is None:
        check(False, f"{label}: uptime readable")
        return
    host, guest = t2 - t1, g2 - g1
    check(abs(guest - host) <= TOLERANCE_S,
          f"{label}: guest {guest:.2f} s vs host {host:.2f} s (tolerance {TOLERANCE_S} s)")


def main():
    tmpdir = tempfile.mkdtemp(prefix="yesos_timer_")
    disk = os.path.join(tmpdir, "disk.img")
    shutil.copyfile(harness.SRC_DISK, disk)
    vm = harness.YesOS(disk, 40000 + os.getpid() % 20000)
    try:
        check(vm.wait_for("YesOS [", 90), "system boots")
        check("[CLINT] Timer: mtime at 10000000 Hz" in vm.output(), "timer reads the CLINT mtime counter")

        compare(vm, "idle 30 s", lambda: time.sleep(30))

        def heavy():
            for cmd, done in (("pin set 482915", "Master PIN successfully updated"),
                              ("cell test", "ALL HOSTILE PROGRAMS CONTAINED"),
                              ("pin change 482915 123456", "Master PIN successfully updated"),
                              ("pmp test", "ALL PROBES MATCH THE POLICY")):
                m = len(vm.output())
                vm.send(cmd, 0.5)
                check(vm.wait_for(done, 120, m), f"load step: {cmd}")
        compare(vm, "under load", heavy)

        out = vm.output()
        check("FATAL" not in out and "RISC-V EXCEPTION" not in out, "no kernel faults")
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
