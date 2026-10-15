#!/usr/bin/env python3
"""
PCI test: drivers/pci.c enumerates bus 0 and hands out memory BARs from one
allocator. Boots QEMU with an Intel HD Audio controller next to the virtio
disk and NIC, and checks that `pci` lists all of them with their class, that
every assigned BAR is inside the 32-bit MMIO window without overlapping
another, and that the disk and the network still work on the shared BARs.
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

failures = []
EXTRA = ["-device", "intel-hda", "-device", "hda-output", "-audiodev", "none,id=snd0"]


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label)
    if not cond:
        failures.append(label)


class PciYesOS(harness.YesOS):
    """The standard VM plus an HD Audio controller and codec."""

    def __init__(self, disk, host_port):
        orig = harness.subprocess.Popen

        def popen(cmd, *a, **kw):
            cmd = list(cmd) + EXTRA
            cmd[cmd.index("hda-output")] = "hda-output,audiodev=snd0"
            return orig(cmd, *a, **kw)

        harness.subprocess.Popen = popen
        try:
            super().__init__(disk, host_port)
        finally:
            harness.subprocess.Popen = orig


def main():
    tmpdir = tempfile.mkdtemp(prefix="yesos_pci_")
    disk = os.path.join(tmpdir, "disk.img")
    shutil.copyfile(harness.SRC_DISK, disk)
    vm = PciYesOS(disk, 40000 + os.getpid() % 20000)
    try:
        check(vm.wait_for("YesOS [", 90), "system boots with an HD Audio controller on the bus")
        out = vm.output()
        check("Persistent volume mounted" in out, "virtio-blk disk mounted on the shared BAR allocator")
        check("VIRTIO-NET PCI" in out and "[ OK ] VIRTIO-NET" in out, "virtio-net up on the shared BAR allocator")

        m = vm.send("pci", 2)
        res = vm.since(m)
        devs = re.findall(r"^\s+([0-9a-fA-F]{2})\.(\d)\s+([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\s+class ([0-9a-fA-F]{2})\.([0-9a-fA-F]{2})\s*(.*?)\s*$",
                          res, re.M)
        kinds = {d[6].strip() for d in devs}
        check("virtio-blk" in kinds, "pci lists the virtio-blk disk")
        check("virtio-net" in kinds, "pci lists the virtio-net NIC")
        check(any(d[4].lower() == "04" and d[5].lower() == "03" for d in devs), "pci lists the HD Audio controller (class 04.03)")

        bars = [(int(a, 16), int(k) * 1024) for a, k in re.findall(r"BAR\d 0x([0-9a-fA-F]+) \((\d+) KiB\)", res)]
        check(len(bars) >= 2, f"BARs assigned to the enabled devices ({len(bars)})")
        check(all(0x40000000 <= a and a + s <= 0x80000000 for a, s in bars), "every BAR is inside the 32-bit MMIO window")
        ordered = sorted(bars)
        check(all(ordered[i][0] + ordered[i][1] <= ordered[i + 1][0] for i in range(len(ordered) - 1)),
              "no two BARs overlap")

        m = vm.send("disk", 2)
        check("VirtIO-Block PCI" in vm.since(m), "disk still answers after the listing")
        check("FATAL" not in vm.output() and "RISC-V EXCEPTION" not in vm.output(), "no kernel faults")
        time.sleep(0.5)
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
