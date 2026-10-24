#!/usr/bin/env python3
"""
yesmath test (optional core module "math", math/ and include/yesmath.h).
1. Host build of the same sources (-DYM_HOST, ctypes):
   - each Q16.16 function against exact math on 20 000 inputs: Q16-accurate,
     i.e. within one Q16.16 step (2^-16) or, for larger results, within 2^-20
     of the value; log2 within 2^-23;
   - gain, mix, biquad (8 channels), symmetric FIR, blur, memcpy, memset and fill32
     against integer references written here: identical outputs; the
     biquad's SNR and the resampler's SINAD against exact math.
2. The kernel (`math test` in the core self-test image, QEMU with V): it runs
   every function on inputs from a fixed pseudo-random sequence
   (math/ym_selftest.c) and prints a hash of each one's outputs. The hashes
   must equal the host build's of the same file, and each vector version's
   the scalar one's.
Non-zero exit status on failure.
"""
import ctypes
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
CORE = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import yesos_harness as harness  # noqa: E402

SRCS = [os.path.join(CORE, "math", f) for f in ("ym_math.c", "ym_tables.c", "ym_dispatch.c", "ym_selftest.c")]
I64, U64, I32, I16, U8, U16 = ctypes.c_int64, ctypes.c_uint64, ctypes.c_int32, ctypes.c_int16, ctypes.c_uint8, ctypes.c_uint16
BQ_COEF = [329, 658, 329, -25575, 10507]     # the self-test's low-pass, Q14 (f0 = 0.05 of the rate, Q 0.707)
RS_STEP = round(44100 / 48000 * 2 ** 32)
failures = []


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label)
    if not cond:
        failures.append(label)


def logu(rng, lo, hi, n):
    return 2.0 ** rng.uniform(math.log2(lo), math.log2(hi), n)


def q16(v):
    return np.round(np.asarray(v, dtype=float) * 65536).astype(np.int64)


def arr(ctype, values):
    return (ctype * len(values))(*[int(v) for v in values])


def sat16(v):
    return max(-32768, min(32767, v))


def host_lib(d):
    so = os.path.join(d, "ym.so")
    subprocess.run(["cc", "-O2", "-Wall", "-DYM_HOST", "-shared", "-fPIC", "-I", os.path.join(CORE, "include"),
                    *SRCS, "-o", so], check=True)
    lib = ctypes.CDLL(so)
    sig = {
        "ym_sqrt_q16": (U64, [U64]), "ym_rsqrt_q16": (U64, [U64]), "ym_rsqrt_q32": (U64, [U64]),
        "ym_log2_q32": (I64, [U64]), "ym_exp2_q16": (U64, [I64]), "ym_exp_q16": (U64, [I64]),
        "ym_ln_q16": (I64, [U64]), "ym_pow_q16": (U64, [U64, I64]), "ym_sin_q16": (I64, [I64]),
        "ym_cos_q16": (I64, [I64]), "ym_atan2_q16": (I64, [I64, I64]),
        "ym_resample_sinc8": (U64, [ctypes.c_void_p, U64, ctypes.c_void_p, U64, ctypes.c_void_p, U64]),
    }
    for name, (res, args) in sig.items():
        getattr(lib, name).restype, getattr(lib, name).argtypes = res, args
    return lib


# ---- 1. host ---------------------------------------------------------------------------
def host_math(lib):
    rng = np.random.default_rng(71)
    n = 20000

    def run(label, fn, xs, exact, filt=lambda w: True):
        worst, ok = 0.0, True
        for x in xs:
            w = exact(*[v / 65536 for v in x])
            if not filt(w):
                continue
            err = abs(fn(*x) / 65536 - w)
            ok &= err <= max(2 ** -16, 2 ** -20 * abs(w))
            worst = max(worst, err * 65536)
        check(ok, f"{label}: Q16-accurate on {len(xs)} inputs (worst {worst:.2f} steps)")

    pos = [(int(v),) for v in q16(logu(rng, 1 / 64, 30000, n))]
    run("sqrt", lib.ym_sqrt_q16, pos, math.sqrt)
    run("rsqrt_q16", lib.ym_rsqrt_q16, pos, lambda a: 1 / math.sqrt(a))
    worst = max(abs(lib.ym_rsqrt_q32(a) / 2 ** 32 * math.sqrt(a / 65536) - 1) for (a,) in pos)
    check(worst <= 2 ** -20, f"rsqrt_q32: relative error {worst:.2e} (<= 2^-20)")
    worst = max(abs(lib.ym_log2_q32(a) / 2 ** 32 - math.log2(a / 65536)) for (a,) in pos)
    check(worst <= 2 ** -23, f"log2_q32: worst error {worst:.2e} (<= 2^-23)")
    run("ln", lib.ym_ln_q16, pos, math.log)
    run("exp", lib.ym_exp_q16, [(int(v),) for v in q16(rng.uniform(-10, 10, n))], math.exp)
    worst = 0.0
    for l in (rng.uniform(-6, 46, n) * 2 ** 32).astype(np.int64):
        want = 2 ** (int(l) / 2 ** 32)
        err = abs(lib.ym_exp2_q16(int(l)) / 65536 - want)
        worst = max(worst, err / max(2 ** -16, 2 ** -20 * want))
    check(worst <= 1, f"exp2: Q16-accurate (worst {worst:.2f} of the allowance)")
    pw = zip(q16(logu(rng, 1 / 16, 100, n)), q16(rng.uniform(-3, 3, n)))
    run("pow", lib.ym_pow_q16, [(int(a), int(b)) for a, b in pw], lambda x, p: x ** p, lambda w: 1 / 64 <= w <= 30000)
    ang = [(int(v),) for v in q16(rng.uniform(-1000, 1000, n))]
    run("sin", lib.ym_sin_q16, ang, math.sin)
    run("cos", lib.ym_cos_q16, ang, math.cos)
    yx = zip(q16(rng.uniform(-1000, 1000, n)), q16(rng.uniform(-1000, 1000, n)))
    run("atan2", lib.ym_atan2_q16, [(int(a), int(b)) for a, b in yx], math.atan2)
    check(lib.ym_atan2_q16(0, 0) == 0, "atan2(0, 0) = 0")
    v = q16(rng.uniform(-1000, 1000, (3, 2000))).astype(np.int32)
    o = [(I32 * 2000)() for _ in range(3)]
    lib.ym_normalize3_batch(*(arr(I32, c) for c in v), *o, ctypes.c_uint64(2000))
    worst = 0.0
    for k in range(2000):
        want = v[:, k] / np.linalg.norm(v[:, k].astype(float))
        worst = max(worst, max(abs(o[c][k] / 65536 - want[c]) * 65536 for c in range(3)))
    check(worst <= 1, f"normalize3: within one step on 2000 vectors (worst {worst:.2f})")


def host_kernels(lib):
    rng = np.random.default_rng(61)
    a, b = rng.integers(-32768, 32768, (2, 1024))
    a[:2], b[:2] = [-32768, 32767], [-32768, 32767]
    out = (I16 * 1024)()
    lib.ym_gain_q15(arr(I16, a), out, ctypes.c_uint64(1024), ctypes.c_int16(23170))
    check(list(out) == [sat16((int(x) * 23170 + (1 << 14)) >> 15) for x in a], "gain: identical to the integer reference")
    lib.ym_mix_q15(arr(I16, a), arr(I16, b), out, ctypes.c_uint64(1024))
    check(list(out) == [sat16(int(x) + int(y)) for x, y in zip(a, b)], "mix: identical (saturating at both ends)")

    class Bq(ctypes.Structure):
        _fields_ = [(f, I64) for f in ("b0", "b1", "b2", "a1", "a2", "s1", "s2")]

    class Bq8(ctypes.Structure):
        _fields_ = [(f, I64) for f in ("b0", "b1", "b2", "a1", "a2")] + [("s1", I64 * 8), ("s2", I64 * 8)]
    frames = rng.integers(-20000, 20000, 256 * 8)
    f = Bq8()
    lib.ym_biquad8_init(ctypes.byref(f), arr(I32, BQ_COEF))
    fo = (I16 * len(frames))()
    lib.ym_biquad8_run(ctypes.byref(f), arr(I16, frames), fo, ctypes.c_uint64(256))
    b0, b1, b2, a1, a2 = BQ_COEF
    ref, s1, s2 = [0] * len(frames), [0] * 8, [0] * 8
    for i in range(256):
        for ch in range(8):
            x0 = int(frames[i * 8 + ch])
            acc = b0 * x0 + s1[ch]
            s1[ch] = b1 * x0 - ((a1 * acc) >> 14) + s2[ch]
            s2[ch] = b2 * x0 - ((a2 * acc) >> 14)
            ref[i * 8 + ch] = sat16((acc + (1 << 13)) >> 14)
    check(list(fo) == ref and list(f.s1) == s1 and list(f.s2) == s2, "biquad8: outputs and states identical to the reference")

    # quality: two tones and light noise (the lab's contest signal), against
    # the same Q14 coefficients in exact arithmetic
    t = np.arange(1024)
    xs = np.round((0.4 * np.sin(2 * np.pi * 0.01 * t) + 0.3 * np.sin(2 * np.pi * 0.2 * t)
                   + 0.05 * np.random.default_rng(51).standard_normal(1024)) * 32767).astype(int)
    c = [k / 16384 for k in BQ_COEF]
    x = xs / 32768
    y = np.zeros_like(x)
    for n in range(len(x)):
        y[n] = (c[0] * x[n] + (c[1] * x[n - 1] if n else 0) + (c[2] * x[n - 2] if n > 1 else 0)
                - (c[3] * y[n - 1] if n else 0) - (c[4] * y[n - 2] if n > 1 else 0))
    one = Bq()
    lib.ym_biquad_init(ctypes.byref(one), arr(I32, BQ_COEF))
    o = (I16 * 1024)()
    lib.ym_biquad_run(ctypes.byref(one), arr(I16, xs), o, ctypes.c_uint64(1024), ctypes.c_uint64(1))
    snr = 10 * math.log10(np.sum(y ** 2) / np.sum((np.array(list(o)) / 32768 - y) ** 2))
    check(snr > 85, f"biquad quality: SNR {snr:.1f} dB (> 85)")

    nt = np.arange(32) - 15.5
    h = 0.4 * np.sinc(0.4 * nt) * np.blackman(32)
    h = np.round(h / h.sum() * 32768).astype(int)
    fx = rng.integers(-32768, 32768, 512 + 31)
    fy = (I16 * 512)()
    lib.ym_fir_sym_q15(arr(I16, h), ctypes.c_uint32(32), arr(I16, fx), fy, ctypes.c_uint64(512))
    ref = [sat16((sum(int(h[k]) * int(fx[i + k]) for k in range(32)) + (1 << 14)) >> 15) for i in range(512)]
    check(list(fy) == ref, "fir_sym: identical to the full (non-symmetric) sum")

    rs_x = np.round(0.5 * np.sin(2 * np.pi * 5000 * (np.arange(600) - 3) / 44100) * 32767).astype(int)
    ry = (I16 * 512)()
    pos = ctypes.c_uint64(3 << 32)
    m = lib.ym_resample_sinc8(arr(I16, rs_x), 600, ry, 512, ctypes.byref(pos), RS_STEP)
    want = 0.5 * np.sin(2 * np.pi * 5000 * (np.arange(m) * 44100 / 48000) / 44100)
    sinad = 10 * math.log10(np.sum(want ** 2) / np.sum((np.array(list(ry)[:m]) / 32767 - want) ** 2))
    check(m == 512 and sinad > 55, f"resample_sinc8 44.1 -> 48 kHz: {m} outputs, SINAD {sinad:.1f} dB (> 55)")
    check(pos.value == (3 << 32) + m * RS_STEP, "resample_sinc8: returns the next position")

    img = rng.integers(0, 256, 64 * 64)
    bo = (U8 * 4096)()
    lib.ym_blur3x3_u8(arr(U8, img), bo, 64, 64, 64, (U16 * 192)())
    ref = list(img)
    for yy in range(1, 63):
        for xx in range(1, 63):
            p = lambda dy, dx: int(img[(yy + dy) * 64 + xx + dx])
            s = (p(-1, -1) + 2 * p(-1, 0) + p(-1, 1) + 2 * p(0, -1) + 4 * p(0, 0) + 2 * p(0, 1)
                 + p(1, -1) + 2 * p(1, 0) + p(1, 1))
            ref[yy * 64 + xx] = (s + 8) >> 4
    check(list(bo) == ref, "blur3x3: identical to the direct 3x3 sum, border copied")

    src = bytes(int(v) for v in rng.integers(0, 256, 4096))
    for off_d, off_s, n in ((0, 0, 4096), (3, 5, 4089), (7, 7, 1001), (1, 0, 13), (0, 0, 0)):
        dst = (U8 * 4112)()
        lib.ym_memcpy(ctypes.byref(dst, off_d), ctypes.c_char_p(src[off_s:] + b"\0"), ctypes.c_uint64(n))
        got = bytes(dst)
        check(got[off_d:off_d + n] == src[off_s:off_s + n] and not any(got[:off_d]) and not any(got[off_d + n:]),
              f"memcpy dst+{off_d} src+{off_s} {n} bytes: exactly those bytes")
    for off, n in ((0, 4096), (1, 4093), (5, 3), (0, 0)):
        dst = (U8 * 4112)()
        lib.ym_memset(ctypes.byref(dst, off), 0xA7, ctypes.c_uint64(n))
        got = bytes(dst)
        check(got[off:off + n] == bytes([0xA7]) * n and not any(got[:off]) and not any(got[off + n:]),
              f"memset dst+{off} {n} bytes: exactly those bytes")
    for off, n in ((0, 1024), (1, 1021), (1, 1), (0, 3), (0, 0)):     # off in 32-bit words
        dst = (ctypes.c_uint32 * 1028)()
        lib.ym_fill32(ctypes.byref(dst, 4 * off), ctypes.c_uint32(0x00C0FFEE), ctypes.c_uint64(n))
        got = list(dst)
        check(got[off:off + n] == [0x00C0FFEE] * n and not any(got[:off]) and not any(got[off + n:]),
              f"fill32 dst+{off} words, {n} words: exactly those words")


def host_hashes(lib):
    got = []
    cb_t = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_int, ctypes.c_uint64)
    cb = cb_t(lambda name, rvv, h: got.append((name.decode(), h)))
    lib.ym_selftest.argtypes = [cb_t]
    lib.ym_selftest(cb)
    return got


# ---- 2. kernel -------------------------------------------------------------------------
def kernel_run():
    tmp = tempfile.mkdtemp(prefix="yesos_math_")
    disk = os.path.join(tmp, "disk.img")
    shutil.copyfile(harness.SRC_DISK, disk)
    vm = harness.YesOS(disk, 40000 + os.getpid() % 20000)
    try:
        check(vm.wait_for("YesOS [", 90), "system boots")
        m = vm.send("math", 2)
        check("vector versions in use (RVV 1.0, VLEN 128 bits)" in vm.since(m), "math: finds V and uses the vector versions")
        m = vm.send("math test", 3)
        vm.wait_for("[RESULT]", 120, m)
        out = vm.since(m)
        m = vm.send("help", 2)
        check("math [test]" in vm.since(m), "help lists the math command")
        check("FATAL" not in vm.output() and "RISC-V EXCEPTION" not in vm.output(), "no kernel faults")
    finally:
        vm.stop()
        shutil.rmtree(tmp, ignore_errors=True)
    lines = re.findall(r"^\s+(\w+)\s+(scalar|rvv)\s+([0-9A-Fa-f]{16})", out, re.M)
    return [(n, mode, int(h, 16)) for n, mode, h in lines], out


def main():
    d = tempfile.mkdtemp(prefix="yesmath_host_")
    try:
        lib = host_lib(d)
        print("1. host build")
        host_math(lib)
        host_kernels(lib)
        expected = host_hashes(lib)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    print("\n2. kernel (math test)")
    lines, out = kernel_run()
    scalar = {n: h for n, mode, h in lines if mode == "scalar"}
    vector = {n: h for n, mode, h in lines if mode == "rvv"}
    for name, h in expected:
        check(scalar.get(name) == h, f"{name}: kernel result identical to the host build's")
    batch = ("normalize3", "dot", "gain", "mix", "biquad8", "fir_sym", "blur3x3", "memcpy", "memset", "fill32")
    for name in batch:
        check(name in vector and vector[name] == scalar.get(name), f"{name}: vector result identical to the scalar one")
    check(f"[RESULT] yesmath self-check OK: {len(batch)} vector results identical" in out, "the kernel reports OK")
    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED")
        sys.exit(1)
    print("All checks passed")


if __name__ == "__main__":
    main()
