#include "yesos_crypto.h"
#include "trap.h"
#include "vfs.h"
#include "memory.h"
#include "kprintf.h"
#include "timer.h"

// ============================================================================
// YesOS 2.0 - Kernel entropy pool
//
// Sources, in order of trust:
//   1. Zkr `seed` CSR (RISC-V hardware entropy source). Probed at runtime, so
//      the same kernel image boots on harts without Zkr.
//   2. SYS/RNG.SEED: 32 bytes of DRBG output persisted at the previous boot.
//      Guarantees fresh nonces across reboots even without a hardware source.
//   3. mcycle / mtime jitter around memory and timer accesses.
//
// The DRBG itself lives in rust_core (ChaCha20 with fast key erasure).
// ============================================================================

#define SEED_CSR_OPST_SHIFT 30
#define SEED_CSR_ES16       2
#define SEED_FILE           "SYS/RNG.SEED"
#define SEED_FILE_LEN       32

static Bool g_hw_entropy = FALSE;
static U64  g_jitter_buf[2048];   // static: too large for a hart stack

static inline U64 read_mcycle(U0) {
    U64 v;
    __asm__ __volatile__("csrr %0, mcycle" : "=r"(v));
    return v;
}

static inline U64 read_mtime(U0) {
    U64 v;
    __asm__ __volatile__("rdtime %0" : "=r"(v));
    return v;
}

static inline U64 read_seed_csr(U0) {
    U64 v = 0;
    // csrrw is mandatory for `seed` (a read-only csrr raises illegal-instruction).
    __asm__ __volatile__("csrrw %0, 0x015, x0" : "+r"(v) : : "memory");
    return v;
}

// Collects `count` 16-bit ES16 samples from the Zkr seed CSR.
// Returns the number of samples obtained (0 if Zkr is absent or dead).
static U32 collect_zkr(U16* out, U32 count) {
    trap_probe_begin();
    (U0)read_seed_csr();
    if (trap_probe_end()) {
        return 0;
    }

    U32 got = 0;
    U32 spins = 0;
    while (got < count && spins < 1000000) {
        U64 s = read_seed_csr();
        U32 opst = (U32)((s >> SEED_CSR_OPST_SHIFT) & 0x3);
        if (opst == SEED_CSR_ES16) {
            out[got++] = (U16)(s & 0xFFFF);
        } else if (opst == 3) { // DEAD: unrecoverable self-test failure
            kprintf("[ENTROPY] Zkr entropy source reports DEAD state.\n");
            break;
        }
        spins++;
    }
    return got;
}

// Timing jitter between cycle counter and wall clock around cache-unfriendly
// memory accesses. Credited very conservatively (1 bit per 64 samples).
static U0 collect_jitter(U64* out, U32 count) {
    static volatile U8 scratch[4096];
    U64 prev = read_mcycle();
    for (U32 i = 0; i < count; i++) {
        for (U32 j = 0; j < 64; j++) {
            scratch[(prev * 2654435761ULL + j * 97) & 4095] ^= (U8)prev;
        }
        U64 now = read_mcycle();
        out[i] = (now - prev) ^ (read_mtime() << 32);
        prev = now;
    }
}

U0 entropy_init(U0) {
    U16 hw[64];
    U32 hw_count = collect_zkr(hw, 64);
    if (hw_count == 64) {
        // 1024 raw bits; credit 256 to stay well inside the Zkr guarantee.
        yc_rng_mix((const U8*)hw, sizeof(hw), 256);
        g_hw_entropy = TRUE;
        kprintf("[ENTROPY] Zkr hardware entropy source: OK (1024 raw bits).\n");
    } else {
        kprintf("[ENTROPY] No Zkr hardware entropy source on this hart.\n");
    }
    yc_wipe((U8*)hw, sizeof(hw));

    collect_jitter(g_jitter_buf, 512);
    yc_rng_mix((const U8*)g_jitter_buf, 512 * sizeof(U64), 8);

    size_t sz = 0;
    U8* seed = vfs_read_file(SEED_FILE, &sz);
    Bool had_seed = (seed && sz >= SEED_FILE_LEN);
    if (had_seed) {
        yc_rng_mix(seed, SEED_FILE_LEN, 128);
    }
    if (seed) {
        yc_wipe(seed, sz);
        Free(seed);
    }

    if (yc_rng_entropy_bits() < 128) {
        // First boot on hardware without Zkr: there is nothing better available.
        // Credit the jitter so the system can come up, but say so loudly.
        collect_jitter(g_jitter_buf, 2048);
        yc_rng_mix((const U8*)g_jitter_buf, sizeof(g_jitter_buf), 128);
        kprintf("[ENTROPY] WARNING: seeded from timing jitter only. Keys generated on this\n");
        kprintf("[ENTROPY]          boot (vault, salts) rely on a weak entropy source.\n");
    }

    yc_wipe((U8*)g_jitter_buf, sizeof(g_jitter_buf));

    // Replace the persisted seed so the next boot never reuses DRBG state.
    U8 next[SEED_FILE_LEN];
    if (yc_rng_fill(next, sizeof(next)) == YC_OK) {
        vfs_write_file(SEED_FILE, next, sizeof(next));
    }
    yc_wipe(next, sizeof(next));

    kprintf("[ENTROPY] DRBG seeded (%s%s).\n",
            g_hw_entropy ? "hardware Zkr" : "jitter",
            had_seed ? " + persisted seed" : "");
}

Bool entropy_is_strong(U0) {
    return g_hw_entropy;
}

Bool entropy_random(U8* out, size_t len) {
    return yc_rng_fill(out, len) == YC_OK;
}
