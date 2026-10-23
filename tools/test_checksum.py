#!/usr/bin/env python3
"""
Checksum test: RedSea's checksum (kernel/barrett_poly.c, Barrett reduction
with the Zbc carry-less multiply) must equal the same function computed one
bit at a time in the kernel and, on the host, by tools/redsea_fsck.py (both
its bit-for-bit port and its tables), for whole words and a short last word;
a flipped bit must change it. It is not a standard CRC-64: the standard
CRC-64/XZ of the same data is checked to differ, so nobody takes one for the
other. Non-zero exit status on failure.
"""
import os
import re
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import yesos_harness as harness  # noqa: E402
import redsea_fsck  # noqa: E402

failures = []


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label)
    if not cond:
        failures.append(label)


def crc64_xz(data):
    crc = (1 << 64) - 1
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xC96C5795D7870F42 if crc & 1 else crc >> 1
    return crc ^ ((1 << 64) - 1)


def main():
    tmp = tempfile.mkdtemp(prefix="yesos_checksum_")
    disk = os.path.join(tmp, "disk.img")
    shutil.copyfile(harness.SRC_DISK, disk)
    vm = harness.YesOS(disk, 40000 + os.getpid() % 20000)
    try:
        check(vm.wait_for("YesOS [", 90), "system boots")
        m = vm.send("barrett", 3)
        vm.wait_for("[RESULT]", 60, m)
        out = vm.since(m)
        pattern = bytes((i * 109 + 37) & 0xFF for i in range(512))
        for size in (512, 509):
            r = re.search(rf"{size} bytes: Zbc 0x([0-9a-fA-F]+), bit by bit 0x([0-9a-fA-F]+) \[(\w+)\]", out)
            check(r is not None and r.group(3) == "MATCH", f"{size} bytes: Zbc equals the kernel's bit-by-bit reference")
            if not r:
                continue
            zbc = int(r.group(1), 16)
            data = pattern[:size]
            check(zbc == redsea_fsck._kernel_crc64_slow(data), f"{size} bytes: equals redsea_fsck.py's bit-for-bit port (0x{zbc:016x})")
            check(zbc & 0xFFFFFFFF == redsea_fsck.kernel_crc64(data) & 0xFFFFFFFF,
                  f"{size} bytes: its low 32 bits, the ones RedSea stores, equal redsea_fsck.py's tables")
            check(zbc != crc64_xz(data), f"{size} bytes: differs from the standard CRC-64/XZ (0x{crc64_xz(data):016x})")
        check("One bit flipped:" in out and "[DETECTED]" in out, "a flipped bit changes the checksum")
        check("[RESULT] checksum OK" in out, "the demo reports OK")
        check("FATAL" not in vm.output() and "RISC-V EXCEPTION" not in vm.output(), "no kernel faults")
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
