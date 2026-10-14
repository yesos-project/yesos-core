#ifndef RISCV_BITMANIP_H
#define RISCV_BITMANIP_H

#include "types.h"

/*
 * YesOS 2.0 - RISC-V Hardware Bit Manipulation Extensions (Zba, Zbb, Zbs)
 * Direct 1-cycle architectural instructions for M-Mode Bare-Metal execution.
 */

// -------------------------------------------------------------
// Zbb: Count Leading / Trailing Zeros and Population Count
// -------------------------------------------------------------

static inline U32 rv_clz64(U64 val) {
    if (val == 0) return 64;
    return (U32)__builtin_clzll(val);
}

static inline U32 rv_clz32(U32 val) {
    if (val == 0) return 32;
    return (U32)__builtin_clz(val);
}

static inline U32 rv_ctz64(U64 val) {
    if (val == 0) return 64;
    return (U32)__builtin_ctzll(val);
}

static inline U32 rv_ctz32(U32 val) {
    if (val == 0) return 32;
    return (U32)__builtin_ctz(val);
}

static inline U32 rv_cpop64(U64 val) {
    return (U32)__builtin_popcountll(val);
}

static inline U32 rv_cpop32(U32 val) {
    return (U32)__builtin_popcount(val);
}

// -------------------------------------------------------------
// Zbb: Branchless Integer Min / Max (1 CPU Cycle)
// -------------------------------------------------------------

static inline I64 rv_min(I64 a, I64 b) {
    return a < b ? a : b;
}

static inline I64 rv_max(I64 a, I64 b) {
    return a > b ? a : b;
}

static inline U64 rv_minu(U64 a, U64 b) {
    return a < b ? a : b;
}

static inline U64 rv_maxu(U64 a, U64 b) {
    return a > b ? a : b;
}

static inline I64 rv_clamp(I64 val, I64 lo, I64 hi) {
    return rv_min(rv_max(val, lo), hi);
}

// -------------------------------------------------------------
// Zbb: Byte-Swap & Bit Rotations (1 CPU Cycle)
// -------------------------------------------------------------

static inline U64 rv_rev8(U64 val) {
    return __builtin_bswap64(val);
}

static inline U32 rv_rev8_32(U32 val) {
    return __builtin_bswap32(val);
}

static inline U64 rv_rol64(U64 val, U32 shift) {
    shift &= 63;
    if (shift == 0) return val;
    return (val << shift) | (val >> (64 - shift));
}

static inline U64 rv_ror64(U64 val, U32 shift) {
    shift &= 63;
    if (shift == 0) return val;
    return (val >> shift) | (val << (64 - shift));
}

// -------------------------------------------------------------
// Zbs: Single-Bit Manipulation (bset, bclr, binv, bext)
// -------------------------------------------------------------

static inline U64 rv_bset(U64 val, U32 bit) {
    return val | (1ULL << (bit & 63));
}

static inline U64 rv_bclr(U64 val, U32 bit) {
    return val & ~(1ULL << (bit & 63));
}

static inline U64 rv_binv(U64 val, U32 bit) {
    return val ^ (1ULL << (bit & 63));
}

static inline U64 rv_bext(U64 val, U32 bit) {
    return (val >> (bit & 63)) & 1ULL;
}

// -------------------------------------------------------------
// Zba: Address Calculation Primitives (sh1add, sh2add, sh3add)
// -------------------------------------------------------------

static inline U64* rv_sh3add_ptr64(U64* base, I64 index) {
    return base + index;
}

static inline U32* rv_sh2add_ptr32(U32* base, I64 index) {
    return base + index;
}

#endif // RISCV_BITMANIP_H
