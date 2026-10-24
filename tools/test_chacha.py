#!/usr/bin/env python3
"""
ChaCha20 test (optional core module "chacha", kernel/chacha20*.c).
1. Host build of the scalar version (-DCC20_HOST, ctypes):
   - RFC 8439 2.4.2 (the "Ladies and Gentlemen" sunscreen text) exactly;
   - 3 000 random keys, nonces, counters, lengths (0-2 000 bytes) and data
     offsets 0-7 against the `cryptography` package (OpenSSL's ChaCha20);
   - across the 32-bit counter's wrap: block by block equal to counters
     0xFFFFFFFD, ..., 0xFFFFFFFF, 0, 1, ... with the same nonce.
2. The kernel (`chacha test` in the core self-test image, QEMU with V): the
   self-check (kernel/chacha20_selftest.c) hashes must equal the host build's
   of the same file, for the scalar and for the vector version.
Non-zero exit status on failure.
"""
import ctypes
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

HERE = os.path.dirname(os.path.abspath(__file__))
CORE = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import yesos_harness as harness  # noqa: E402

failures = []


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label)
    if not cond:
        failures.append(label)


def host_lib(d):
    so = os.path.join(d, "cc20.so")
    subprocess.run(["cc", "-O2", "-Wall", "-DCC20_HOST", "-shared", "-fPIC", "-I", os.path.join(CORE, "include"),
                    *(os.path.join(CORE, "kernel", f) for f in ("chacha20.c", "chacha20_selftest.c")), "-o", so],
                   check=True)
    lib = ctypes.CDLL(so)
    lib.cc20_xor.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint64]
    return lib


def ours(lib, key, nonce, counter, data, off=0):
    buf = (ctypes.c_uint8 * (len(data) + off + 8))()
    ctypes.memmove(ctypes.byref(buf, off), data, len(data))
    lib.cc20_xor(key, nonce, counter, ctypes.byref(buf, off), len(data))
    return bytes(buf)[off:off + len(data)]


def openssl(key, nonce, counter, data):
    c = Cipher(algorithms.ChaCha20(key, counter.to_bytes(4, "little") + nonce), mode=None).encryptor()
    return c.update(data) + c.finalize()


def host(lib):
    # RFC 8439 2.4.2
    key = bytes(range(32))
    nonce = bytes.fromhex("000000000000004a00000000")
    text = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
            b"sunscreen would be it.")
    want = bytes.fromhex(
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b357"
        "1639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42874d")
    got = ours(lib, key, nonce, 1, text)
    check(got == want, "RFC 8439 2.4.2: the sunscreen text encrypts to the RFC's 114 bytes")
    check(openssl(key, nonce, 1, text) == want, "the reference (cryptography/OpenSSL) agrees with the RFC")

    rng = random.Random(8439)
    bad = []
    lengths = [0, 1, 63, 64, 65, 127, 128, 129, 511, 512, 513, 1500, 2000]
    for i in range(3000):
        key, nonce = rng.randbytes(32), rng.randbytes(12)
        counter = rng.randrange(0, 2 ** 32 - 64)
        n = lengths[i] if i < len(lengths) else rng.randrange(0, 2001)
        data, off = rng.randbytes(n), rng.randrange(8)
        if ours(lib, key, nonce, counter, data, off) != openssl(key, nonce, counter, data):
            bad.append((n, off, counter))
    check(not bad, f"3000 random cases equal to OpenSSL's ChaCha20 (lengths 0-2000, offsets 0-7){'' if not bad else bad[:3]}")

    key, nonce = rng.randbytes(32), rng.randbytes(12)
    data = rng.randbytes(64 * 8)
    got = ours(lib, key, nonce, 0xFFFFFFFD, data)
    ok = all(got[64 * j:64 * j + 64] == openssl(key, nonce, (0xFFFFFFFD + j) % 2 ** 32, data[64 * j:64 * j + 64])
             for j in range(8))
    check(ok, "across the counter's wrap: blocks for 0xFFFFFFFD..0xFFFFFFFF, then 0..4, same nonce")

    got = []
    cb_t = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_uint64, ctypes.c_uint64)
    cb = cb_t(lambda what, n, h: got.append((what.decode(), n, h)))
    lib.cc20_selftest.argtypes = [cb_t]
    lib.cc20_selftest(cb)
    return got


def kernel():
    tmp = tempfile.mkdtemp(prefix="yesos_chacha_")
    disk = os.path.join(tmp, "disk.img")
    shutil.copyfile(harness.SRC_DISK, disk)
    vm = harness.YesOS(disk, 40000 + os.getpid() % 20000)
    try:
        check(vm.wait_for("YesOS [", 90), "system boots")
        m = vm.send("chacha", 2)
        check("vector (RVV 1.0) version in use" in vm.since(m), "chacha: the vector version is in use")
        m = vm.send("chacha test", 3)
        vm.wait_for("[RESULT]", 120, m)
        out = vm.since(m)
        check("FATAL" not in vm.output() and "RISC-V EXCEPTION" not in vm.output(), "no kernel faults")
    finally:
        vm.stop()
        shutil.rmtree(tmp, ignore_errors=True)
    return re.findall(r"^\s+(len|wrap) (\d+) (scalar|rvv)\s+([0-9A-Fa-f]{16})", out, re.M), out


def main():
    d = tempfile.mkdtemp(prefix="cc20_host_")
    try:
        print("1. host build (scalar)")
        expected = host(host_lib(d))
    finally:
        shutil.rmtree(d, ignore_errors=True)
    print("\n2. kernel (chacha test)")
    lines, out = kernel()
    for mode in ("scalar", "rvv"):
        got = [(w, int(n), int(h, 16)) for w, n, m, h in lines if m == mode]
        check(got == expected, f"{mode}: {len(got)} kernel hashes equal to the host build's ({len(expected)} expected)")
    check("[RESULT] chacha self-check OK: vector results identical" in out, "the kernel reports OK")
    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED")
        sys.exit(1)
    print("All checks passed")


if __name__ == "__main__":
    main()
