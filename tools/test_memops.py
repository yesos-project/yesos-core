#!/usr/bin/env python3
"""
No unaligned accesses: the memory primitives (kernel/memops.c) and LZ4
(kernel/lz4.c), built on the host with UBSan's alignment check in trap mode,
so any unaligned access stops the process with SIGILL (on RISC-V such an
access may trap, and the kernel has no handler for it). First a probe proves
that the check is live; then every combination of destination and source
offset 0-15 with lengths around the word size and larger, overlapping moves
in both directions and fills, all compared with Python with guard bytes
around; and LZ4 round trips of random, repetitive and mixed data at source
and destination offsets 0-7. Non-zero exit status on failure.
"""
import ctypes
import os
import random
import signal
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CORE = os.path.dirname(HERE)
FLAGS = ["-O2", "-fno-builtin", "-shared", "-fPIC", "-fsanitize=alignment", "-fsanitize-trap=alignment",
         "-I", os.path.join(CORE, "include")]
PROBE = "typedef unsigned long long U64;\nU64 probe(const unsigned char* p) { return *(const U64*)p; }\n"
LENGTHS = list(range(0, 41)) + [63, 64, 65, 127, 128, 129, 1000, 4097]
failures = []


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label)
    if not cond:
        failures.append(label)


def build(d):
    so = os.path.join(d, "memops.so")
    subprocess.run(["clang", *FLAGS, os.path.join(CORE, "kernel", "memops.c"), os.path.join(CORE, "kernel", "lz4.c"),
                    "-o", so], check=True)
    probe_c, probe_so = os.path.join(d, "probe.c"), os.path.join(d, "probe.so")
    open(probe_c, "w").write(PROBE)
    subprocess.run(["clang", *FLAGS, probe_c, "-o", probe_so], check=True)
    return so, probe_so


def child_probe(probe_so):
    lib = ctypes.CDLL(probe_so)
    lib.probe.restype = ctypes.c_uint64
    buf = (ctypes.c_uint8 * 32)()
    lib.probe(ctypes.byref(buf, 3))                      # unaligned: must trap
    print("probe returned")


def child_cases(so):
    lib = ctypes.CDLL(so)
    for f in ("MemCpy", "memmove", "MemSet"):
        getattr(lib, f).restype = ctypes.c_void_p
    rng = random.Random(5)
    N = 4096 + 64
    src_bytes = bytes(rng.randrange(256) for _ in range(N))
    bad, runs = [], 0
    src = (ctypes.c_uint8 * N).from_buffer_copy(src_bytes)
    for doff in range(16):
        for soff in range(16):
            for n in LENGTHS:
                runs += 1
                dst = (ctypes.c_uint8 * N)()
                r = lib.MemCpy(ctypes.byref(dst, doff), ctypes.byref(src, soff), ctypes.c_size_t(n))
                got = bytes(dst)
                if (got[doff:doff + n] != src_bytes[soff:soff + n] or any(got[:doff]) or any(got[doff + n:])
                        or (n and r != ctypes.addressof(dst) + doff)):
                    bad.append(f"MemCpy dst+{doff} src+{soff} n={n}")
    print("MEMCPY", runs, len(bad), bad[:3])
    bad, runs = [], 0
    for start in range(16):
        for shift in list(range(-17, 18)) + [-100, 100]:
            for n in (0, 1, 7, 8, 9, 15, 16, 17, 31, 64, 200, 1000):
                runs += 1
                buf = bytearray(src_bytes[:2048])
                b = (ctypes.c_uint8 * 2048).from_buffer_copy(bytes(buf))
                s0, d0 = 300 + start, 300 + start + shift
                lib.memmove(ctypes.byref(b, d0), ctypes.byref(b, s0), ctypes.c_size_t(n))
                buf[d0:d0 + n] = buf[s0:s0 + n]
                if bytes(b) != bytes(buf):
                    bad.append(f"memmove src+{s0} dst+{d0} n={n}")
    print("MEMMOVE", runs, len(bad), bad[:3])
    bad, runs = [], 0
    for doff in range(16):
        for n in LENGTHS:
            runs += 1
            dst = (ctypes.c_uint8 * N)()
            lib.MemSet(ctypes.byref(dst, doff), ctypes.c_int32(0x1A5), ctypes.c_size_t(n))   # only the low byte counts
            got = bytes(dst)
            if got[doff:doff + n] != b"\xa5" * n or any(got[:doff]) or any(got[doff + n:]):
                bad.append(f"MemSet dst+{doff} n={n}")
    print("MEMSET", runs, len(bad), bad[:3])


def child_lz4(so):
    lib = ctypes.CDLL(so)
    for f in ("lz4_compress", "lz4_decompress", "lz4_compress_bound"):
        getattr(lib, f).restype = ctypes.c_int64
    rng = random.Random(9)
    text = b"YesOS NAS: RedSea volume, WebDAV share, snapshot of /share/docs. " * 200
    datasets = {"random": bytes(rng.randrange(256) for _ in range(5000)), "text": text[:12000],
                "zeros": bytes(7000), "mixed": text[:3000] + bytes(rng.randrange(256) for _ in range(2000)) + text[:4000]}
    runs, bad, ratio = 0, [], {}
    for name, data in datasets.items():
        for soff in range(8):
            for doff in range(8):
                n = len(data) - soff - doff
                d = data[:n]
                src = (ctypes.c_uint8 * (n + 16)).from_buffer_copy(bytes(soff) + d + bytes(16 - soff))
                cap = lib.lz4_compress_bound(ctypes.c_int64(n))
                comp = (ctypes.c_uint8 * (cap + 16))()
                c = lib.lz4_compress(ctypes.byref(src, soff), ctypes.c_int64(n), ctypes.byref(comp, doff), ctypes.c_int64(cap))
                comp2 = (ctypes.c_uint8 * (c + 16)).from_buffer_copy(bytes(soff) + bytes(comp)[doff:doff + c] + bytes(16 - soff))
                out = (ctypes.c_uint8 * (n + 16))()
                m = lib.lz4_decompress(ctypes.byref(comp2, soff), ctypes.c_int64(c), ctypes.byref(out, doff), ctypes.c_int64(n))
                runs += 1
                ratio[name] = c / n
                if c <= 0 or m != n or bytes(out)[doff:doff + n] != d:
                    bad.append(f"{name} src+{soff} dst+{doff}: compressed {c}, decompressed {m}")
    print("LZ4", runs, len(bad), bad[:3], " ".join(f"{k}={v:.2f}" for k, v in ratio.items()))


def run_child(mode, path):
    r = subprocess.run([sys.executable, __file__, mode, path], capture_output=True, text=True)
    return r.returncode, r.stdout


def main():
    if len(sys.argv) == 3:                                # child process
        {"--probe": child_probe, "--cases": child_cases, "--lz4": child_lz4}[sys.argv[1]](sys.argv[2])
        return
    d = tempfile.mkdtemp(prefix="yesos_memops_")
    so, probe_so = build(d)
    rc, out = run_child("--probe", probe_so)
    check(rc == -signal.SIGILL and "probe returned" not in out,
          "the alignment check is live: an unaligned 64-bit load stops the process (SIGILL)")
    rc, out = run_child("--cases", so)
    check(rc == 0, f"no unaligned access in any case (child exit status {rc})")
    for name, count in (("MEMCPY", 16 * 16 * len(LENGTHS)), ("MEMMOVE", 16 * 37 * 12), ("MEMSET", 16 * len(LENGTHS))):
        line = next((l for l in out.splitlines() if l.startswith(name)), "")
        ok = line.startswith(f"{name} {count} 0 ")
        check(ok, f"{name.capitalize()}: {count} cases identical to Python, guard bytes untouched" + ("" if ok else f" ({line})"))
    rc, out = run_child("--lz4", so)
    line = next((l for l in out.splitlines() if l.startswith("LZ4")), "")
    check(rc == 0 and line.startswith("LZ4 256 0 "),
          f"LZ4: 256 round trips at source/destination offsets 0-7, identical, no unaligned access "
          f"(exit {rc}; compressed/original {line.split(']')[-1].strip() if line else '?'})")
    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED")
        sys.exit(1)
    print("All checks passed")


if __name__ == "__main__":
    main()
