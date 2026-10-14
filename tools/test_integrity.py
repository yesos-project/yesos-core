#!/usr/bin/env python3
"""
Integrity monitor test (phase 4a).

Boots YesOS with QEMU's gdbstub, unlocks a vault, then flips one bit of the
kernel's read-only data from OUTSIDE the guest through the GDB remote
protocol. Like a hardware fault or a DMA write, this bypasses the PMP. The
key hart must detect the changed chunk, lock the vault and raise an alarm.
Non-zero exit status on failure.
"""
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import yesos_harness as harness  # noqa: E402

ROOT = harness.ROOT
CHUNK = 64 * 1024
# Messages this test reads back: the corrupted byte must never fall inside them.
WATCHED = [b"DOES NOT MATCH", b"could not arm", b"INTEGRITY", b"YesOS ["]


def rodata_probe_offset(elf):
    """An offset inside .rodata, in the middle of a text string (never a pointer
    or jump table, which would crash the code that uses it), at least 1 KiB away
    from every watched message."""
    sections = subprocess.run(["llvm-readelf", "-S", "-W", elf], capture_output=True, text=True).stdout
    fields = next(l.split() for l in sections.splitlines() if " .rodata " in l)
    i = fields.index(".rodata")
    off, size = int(fields[i + 3], 16), int(fields[i + 4], 16)
    data = open(elf, "rb").read()[off:off + size]
    hits = [m.start() for w in WATCHED for m in re.finditer(re.escape(w), data)]
    for run in re.finditer(rb"[\x20-\x7e]{64,}", data[0x10000:]):
        cand = 0x10000 + (run.start() + run.end()) // 2
        if all(abs(cand - h) > 1024 for h in hits):
            return cand
    raise RuntimeError("no safe .rodata probe offset")


RODATA_PROBE_OFFSET = rodata_probe_offset(harness.KERNEL)
failures = []


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label)
    if not cond:
        failures.append(label)


def symbol(name):
    out = subprocess.run(["llvm-nm", harness.KERNEL], capture_output=True, text=True).stdout
    for line in out.splitlines():
        p = line.split()
        if len(p) == 3 and p[2] == name:
            return int(p[0], 16)
    raise KeyError(name)


class Gdb:
    """Minimal GDB remote serial protocol client (memory read/write only)."""

    def __init__(self, port):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=5)

    def _send(self, payload):
        cs = sum(payload.encode()) % 256
        self.s.sendall(f"${payload}#{cs:02x}".encode())

    def _recv_packet(self):
        buf = b""
        while True:
            c = self.s.recv(1)
            if not c:
                raise IOError("gdbstub closed")
            if c in (b"+", b"-") and not buf:
                continue
            buf += c
            if b"#" in buf and len(buf.split(b"#", 1)[1]) >= 2:
                self.s.sendall(b"+")
                return buf[buf.index(b"$") + 1:buf.index(b"#")].decode()

    def cmd(self, payload):
        self._send(payload)
        return self._recv_packet()

    def halt(self):
        # QEMU stops the guest as soon as a debugger attaches; "?" confirms it.
        return self.cmd("?")

    def cont(self):
        self._send("c")

    def read(self, addr, n):
        return bytes.fromhex(self.cmd(f"m{addr:x},{n:x}"))

    def write(self, addr, data):
        return self.cmd(f"M{addr:x},{len(data):x}:{data.hex()}")


class GdbYesOS(harness.YesOS):
    def __init__(self, disk, host_port, gdb_port):
        orig = harness.subprocess.Popen

        def popen(cmd, *a, **kw):
            return orig(cmd + ["-gdb", f"tcp:127.0.0.1:{gdb_port}"], *a, **kw)

        harness.subprocess.Popen = popen
        try:
            super().__init__(disk, host_port)
        finally:
            harness.subprocess.Popen = orig


def main():
    tmpdir = tempfile.mkdtemp(prefix="yesos_integ_")
    disk = os.path.join(tmpdir, "disk.img")
    shutil.copyfile(harness.SRC_DISK, disk)
    gdb_port = 41000 + os.getpid() % 10000
    vm = GdbYesOS(disk, 40000 + os.getpid() % 10000, gdb_port)
    try:
        check(vm.wait_for("YesOS [", 90), "system boots")
        out = vm.output()
        check("Kernel image: BLAKE2b-256 of .text+.rodata matches the build" in out, "boot image hash matches build")
        check("Integrity monitor armed" in out, "integrity monitor armed")

        vm.send("vault init", 1)
        vm.send(harness.PASS, 0.5)
        m = vm.send(harness.PASS, 0.5)
        check(vm.wait_for("Vault created and unlocked", 60, m), "vault created and unlocked")
        vm.send("write /vault/S.TXT integrity-test-secret", 2)

        time.sleep(3)
        m = vm.send("integrity", 2)
        res = vm.since(m)
        check("ARMED" in res and "Alarm           : none" in res, "monitor running, no alarm on a clean system")
        passes = [l for l in res.splitlines() if "full passes" in l]
        check(passes and not passes[0].strip().endswith("passes: 0"), f"monitor completed full passes ({passes[0].strip() if passes else '?'})")

        # Flip one bit of read-only data from outside the guest (bypasses PMP)
        kstart = symbol("_kernel_start")
        target = symbol("_rodata_start") + RODATA_PROBE_OFFSET
        g = Gdb(gdb_port)
        g.halt()
        orig = g.read(target, 1)
        g.write(target, bytes([orig[0] ^ 0x01]))
        check(g.read(target, 1) != orig, f"bit flipped at 0x{target:x} through the debugger")
        g.cont()

        expected_chunk = kstart + ((target - kstart) // CHUNK) * CHUNK
        check(vm.wait_for("[INTEGRITY] ALERT", 20), "alarm raised after the bit flip")
        res = vm.output()
        check(f"0x{expected_chunk:016X}" in res.upper() or f"{expected_chunk:016x}" in res.lower(),
              f"alarm pinpoints the changed 64 KiB chunk (0x{expected_chunk:x})")
        check("locked the vault" in res, "key hart locked the vault on its own")

        m = vm.send("cat /vault/S.TXT", 2)
        check("integrity-test-secret" not in vm.since(m) and "locked" in vm.since(m),
              "vault contents no longer readable after the alarm")
        m = vm.send("integrity", 2)
        check("ALARM" in vm.since(m), "integrity status shows the alarm")
        time.sleep(1)
    finally:
        vm.stop()

    # Second boot: a kernel image corrupted on disk must be reported at boot
    bad_elf = os.path.join(tmpdir, "corrupt.elf")
    os.makedirs(tmpdir, exist_ok=True)
    shutil.copyfile(harness.KERNEL, bad_elf)
    sections = subprocess.run(["llvm-readelf", "-S", "-W", bad_elf], capture_output=True, text=True).stdout
    off = next(int(l.split()[l.split().index(".rodata") + 3], 16) for l in sections.splitlines() if " .rodata " in l)
    with open(bad_elf, "r+b") as f:
        f.seek(off + RODATA_PROBE_OFFSET)
        b = f.read(1)
        f.seek(off + RODATA_PROBE_OFFSET)
        f.write(bytes([b[0] ^ 0x80]))
    shutil.copyfile(harness.SRC_DISK, disk)
    harness.KERNEL = bad_elf
    vm = harness.YesOS(disk, 40000 + (os.getpid() + 7) % 10000)
    try:
        check(vm.wait_for("YesOS [", 90), "corrupted kernel image still boots (to report)")
        out = vm.output()
        check("kernel image hash DOES NOT MATCH the build" in out, "boot check detects the corrupted image")
        check("could not arm the monitor" in out, "monitor refuses to take a baseline of a corrupted image")
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
