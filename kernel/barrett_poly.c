#include "barrett_poly.h"
#include "kprintf.h"
#include "timer.h"
#include "memory.h"

// ----------------------------------------------------------------------------
// RedSea's checksum (see barrett_poly.h): Barrett reduction in GF(2) with the
// RISC-V Zbc carry-less multiply (clmul / clmulh).
// ----------------------------------------------------------------------------

static inline U64 rv_clmul(U64 a, U64 b) {
    U64 res;
    asm volatile("clmul %0, %1, %2" : "=r"(res) : "r"(a), "r"(b));
    return res;
}

static inline U64 rv_clmulh(U64 a, U64 b) {
    U64 res;
    asm volatile("clmulh %0, %1, %2" : "=r"(res) : "r"(a), "r"(b));
    return res;
}

U64 barrett_poly_reduce_128(U64 t_hi, U64 t_lo) {
    // 1. Quotient estimation: Q = (T_hi * mu) >> 64
    // Since mu = (1 << 64) | BARRETT_MU_LO:
    // T_hi * mu = (T_hi << 64) ^ (T_hi * BARRETT_MU_LO)
    // Division by x^64 gives: T_hi ^ clmulh(T_hi, BARRETT_MU_LO)
    U64 q = t_hi ^ rv_clmulh(t_hi, BARRETT_MU_LO);

    // 2. Product Q * P = (Q << 64) ^ (Q * BARRETT_POLY_LO)
    U64 q_p_lo = rv_clmul(q, BARRETT_POLY_LO);
    U64 q_p_hi = q ^ rv_clmulh(q, BARRETT_POLY_LO);

    // 3. Remainder: R = T ^ (Q * P)
    U64 r_lo = t_lo ^ q_p_lo;
    U64 r_hi = t_hi ^ q_p_hi;

    // 4. One final reduction step if degree >= 64
    if (r_hi != 0) {
        U64 q2 = r_hi ^ rv_clmulh(r_hi, BARRETT_MU_LO);
        r_lo ^= rv_clmul(q2, BARRETT_POLY_LO);
    }

    return r_lo;
}

U64 barrett_crc64_sector(const U8* data, size_t len) {
    if (!data || len == 0) return 0;

    const U64* words = (const U64*)data;
    size_t num_words = len / 8;
    U64 crc = 0xFFFFFFFFFFFFFFFFULL;

    for (size_t i = 0; i < num_words; i++) {
        U64 w = words[i];
        U64 t_hi = crc ^ w;
        crc = barrett_poly_reduce_128(t_hi, 0);
    }

    size_t rem = len % 8;
    if (rem > 0) {
        U64 last_word = 0;
        const U8* tail = data + (num_words * 8);
        for (size_t i = 0; i < rem; i++) {
            last_word |= ((U64)tail[i]) << (i * 8);
        }
        crc = barrett_poly_reduce_128(crc ^ last_word, 0);
    }

    return crc ^ 0xFFFFFFFFFFFFFFFFULL;
}

// ----------------------------------------------------------------------------
// Console demo: the Zbc version checked against the same function computed
// one bit at a time, then its speed (QEMU wall clock)
// ----------------------------------------------------------------------------

// The same checksum without Zbc: each word is multiplied by x^64 mod P one
// bit at a time (a shift, and P subtracted when the top bit falls out).
static U64 checksum_bitwise_ref(const U8* data, size_t len) {
    if (!data || len == 0) return 0;
    U64 crc = 0xFFFFFFFFFFFFFFFFULL;
    for (size_t i = 0; i < len; i += 8) {
        U64 w = 0;
        for (size_t k = 0; k < 8 && i + k < len; k++) w |= (U64)data[i + k] << (8 * k);
        crc ^= w;
        for (int b = 0; b < 64; b++) crc = (crc << 1) ^ ((crc >> 63) ? BARRETT_POLY_LO : 0);
    }
    return crc ^ 0xFFFFFFFFFFFFFFFFULL;
}

U0 barrett_poly_benchmark(U0) {
    kprintf("\n================ [ REDSEA CHECKSUM (Barrett reduction, Zbc clmul) ] ================\n");
    kprintf("Per little-endian 64-bit word: crc = (crc ^ w) * x^64 mod P, P = CRC-64-ECMA (MSB first).\n");
    kprintf("A polynomial code of its own, not the standard CRC-64/XZ or ECMA-182. RedSea keeps 32 bits.\n\n");

    U8 sector[512];
    for (int i = 0; i < 512; i++) sector[i] = (U8)((i * 109 + 37) & 0xFF);

    Bool all = TRUE;
    static const U32 sizes[2] = { 512, 509 };           // whole words, and a short last word
    for (U32 k = 0; k < 2; k++) {
        U64 zbc = barrett_crc64_sector(sector, sizes[k]);
        U64 ref = checksum_bitwise_ref(sector, sizes[k]);
        all = all && zbc == ref;
        kprintf("  %u bytes: Zbc 0x%p, bit by bit 0x%p [%s]\n", (U64)sizes[k], (void*)zbc, (void*)ref,
                zbc == ref ? "MATCH" : "MISMATCH");
    }
    U64 crc = barrett_crc64_sector(sector, 512);
    sector[256] ^= 0x01;
    U64 flipped = barrett_crc64_sector(sector, 512);
    sector[256] ^= 0x01;
    all = all && flipped != crc;
    kprintf("  One bit flipped: 0x%p [%s]\n", (void*)flipped, flipped != crc ? "DETECTED" : "NOT DETECTED");

    U32 num_sectors = 100000;
    U64 t0 = timer_get_uptime_ms();
    volatile U64 sink = 0;
    for (U32 s = 0; s < num_sectors; s++) sink ^= barrett_crc64_sector(sector, 512);
    U64 dt = timer_get_uptime_ms() - t0;
    if (dt == 0) dt = 1;
    kprintf("\n  %u sectors of 512 bytes in %u ms of QEMU wall clock (%u MB/s here; not a hardware figure)\n",
            (U64)num_sectors, dt, (U64)num_sectors * 512 / 1000 / dt);
    kprintf("\n[RESULT] %s\n\n", all ? "checksum OK: Zbc matches the bit-by-bit reference, a flipped bit is detected"
                                       : "checksum FAILED");
}
