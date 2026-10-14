#!/usr/bin/env python3
"""
YesOS test harness: boots a YesOS image headless in QEMU (serial console on
stdio, virtio disk, user network with the NAS UDP port forwarded) and drives
its console. Tests may add NICs by wrapping subprocess.Popen.

ROOT is the product directory the tests run from (YESOS_ROOT or the current
directory); KERNEL is the image to boot (YESOS_KERNEL or ROOT/yesos.elf).
"""
import os
import subprocess
import threading
import time

ROOT = os.environ.get("YESOS_ROOT") or os.getcwd()
KERNEL = os.environ.get("YESOS_KERNEL") or os.path.join(ROOT, "yesos.elf")
SRC_DISK = os.path.join(ROOT, "yesos_disk.img")
PASS = "correct horse battery"           # vault passphrase used by the tests
SECRET = "TOP-SECRET-PAYLOAD-7f3a9c"     # vault content used by the tests
NAS_PORT = 31415


class YesOS:
    def __init__(self, disk, host_port, kernel=None):
        cmd = [
            "qemu-system-riscv64", "-machine", "virt", "-smp", "4",
            "-cpu", "rv64,v=true,vext_spec=v1.0,vlen=128,zba=true,zbb=true,zbc=true,zbs=true,zkr=true",
            "-m", "512M", "-bios", "none", "-kernel", kernel or KERNEL,
            "-drive", f"file={disk},if=none,format=raw,id=hd0", "-device", "virtio-blk-pci,drive=hd0",
            "-netdev", f"user,id=net0,hostfwd=udp:127.0.0.1:{host_port}-:{NAS_PORT}",
            "-device", "virtio-net-pci,netdev=net0",
            "-display", "none", "-serial", "stdio", "-monitor", "none",
        ]
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT)
        self.buf = b""
        self.lock = threading.Lock()
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        while True:
            b = self.p.stdout.read1(4096)
            if not b:
                break
            with self.lock:
                self.buf += b

    def output(self):
        with self.lock:
            return self.buf.decode(errors="replace")

    def wait_for(self, text, timeout=60.0, start=0):
        end = time.time() + timeout
        while time.time() < end:
            out = self.output()
            if text in out[start:]:
                return True
            time.sleep(0.2)
        return False

    def send(self, line, settle=1.0):
        mark = len(self.output())
        for ch in line + "\r":
            self.p.stdin.write(ch.encode())
            self.p.stdin.flush()
            time.sleep(0.1)
        time.sleep(settle)
        return mark

    def since(self, mark):
        return self.output()[mark:]

    def stop(self):
        self.p.kill()
        self.p.wait()
        log = os.environ.get("YESOS_SERIAL_LOG")
        if log:
            with open(log, "a", encoding="utf-8") as f:
                f.write(self.output())
