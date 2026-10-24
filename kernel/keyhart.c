#include "keyhart.h"
#include "pmp.h"
#include "smp.h"
#include "timer.h"
#include "memory.h"
#include "kprintf.h"
#include "integrity.h"

// ============================================================================
// YesOS 2.0 - Key hart (see include/keyhart.h)
// ============================================================================

#define KH_STACK_SIZE   (64 * 1024)
#define KH_ARGON_SIZE   (YC_ARGON2_M_KIB * 1024)
#define KH_PASS_MAX     129
#define KH_TIMEOUT_MS   60000

// --- Private state: lives in .keyvault, PMP-denied on every other hart -----
// The vault data key itself is NOT here: it lives only in vector registers
// (kernel/keyhart_vkey.S). RAM holds at most transient KEK/new-key bytes
// (wiped immediately) and per-message Poly1305 one-time keys.
static U8 g_kv_stack[KH_STACK_SIZE]   __attribute__((section(".keyvault"), aligned(16)));
static U8 g_kv_argon[KH_ARGON_SIZE]   __attribute__((section(".keyvault"), aligned(64)));
static U8 g_kv_tmp[YC_KEY_LEN * 2]    __attribute__((section(".keyvault"), aligned(16)));
static U8 g_kv_otk[32]                __attribute__((section(".keyvault"), aligned(16)));
static U8 g_kv_loaded                 __attribute__((section(".keyvault")));

// Register-resident primitives (kernel/keyhart_vkey.S)
enum { SLOT_K = 0, SLOT_T = 1, SLOT_D = 2 };
extern U0  kh_vk_load(U32 slot, const U8* src32);
extern U0  kh_vk_clear(U32 slot);
extern U0  kh_vk_clear_sub(U0);
extern U0  kh_vk_hchacha(U32 src_slot, const U8* nonce16);
extern U0  kh_vk_chacha_xor(const U8* nonce12, U32 counter, const U8* in, U8* out, size_t len);
extern U0  kh_vk_chacha_to_slot(const U8* nonce12, U32 counter, const U8* in32, U32 dst_slot);
extern U0  kh_vk_chacha_from_slot(const U8* nonce12, U32 counter, U32 src_slot, U8* out32);
extern U64 kh_vk_count(U32 slot, const U8* p, size_t len);
extern I32 yc_poly1305_aead_tag(const U8* otk, const U8* aad, size_t aad_len, const U8* ct, size_t ct_len, U8* tag);

static const U8 g_kh_zero64[64] __attribute__((aligned(8)));   // vle64 needs 8-byte alignment

// --- Integrity monitor ------------------------------------------------------
#define INTEG_CHUNK       (64 * 1024)
#define INTEG_MAX_CHUNKS  128
#define INTEG_PASS_TICKS  15000000ULL    // one full pass over the image every 1.5 s (10 MHz timebase)

extern U8 _kernel_start[], _text_end[], _rodata_start[], _rodata_sec_end[], _rodata_end[];
static const volatile U64 g_integ_sym[5] = {   // absolute: see pmp.c
    (U64)_kernel_start, (U64)_text_end, (U64)_rodata_start, (U64)_rodata_sec_end, (U64)_rodata_end,
};

// Written post-link by tools/image_hash.py
__attribute__((section(".integrity"), used, aligned(8)))
const volatile KernelImageHash g_image_hash = { 0 };

static U8  g_kv_mackey[32]                       __attribute__((section(".keyvault"), aligned(16)));
static U8  g_kv_tags[INTEG_MAX_CHUNKS][32]       __attribute__((section(".keyvault"), aligned(16)));
static U32 g_kv_next_chunk                        __attribute__((section(".keyvault")));
static U64 g_kv_last_check                        __attribute__((section(".keyvault")));

static IntegrityStatus g_integ;                  // shared, not secret
static volatile U32    g_integ_reported = 0;     // hart 0 bookkeeping

// --- Shared mailbox (kernel .data, both sides) ------------------------------
enum { KH_OP_NONE = 0, KH_OP_CREATE, KH_OP_UNLOCK, KH_OP_LOCK, KH_OP_REWRAP, KH_OP_SEAL, KH_OP_OPEN, KH_OP_STATUS,
       KH_OP_SCAN, KH_OP_INTEG_ARM };

typedef struct {
    volatile U64 seq_req;
    volatile U64 seq_resp;
    U32          op;
    I32          status;
    char         pass[KH_PASS_MAX];
    char         pass2[KH_PASS_MAX];
    VaultHeader  hdr;
    VaultHeader  hdr2;
    U8           nonce[YC_NONCE_LEN];
    U8           tag[YC_TAG_LEN];
    U64          aad, aad_len, buf, len;
    U32          loaded;
    U64          scan_hits;
    U32          argon_dirty;
} KeyhartMailbox;

static KeyhartMailbox g_kh_mb;
static PmpPolicy      g_kh_policy;
static PmpLayout      g_kh_layout;
static Bool           g_kh_staged = FALSE;
static volatile U32   g_kh_boot_state = 0;      // 0 none, 1 ready, 2 PMP failed, 3 KAT failed
static Bool           g_kh_verified = FALSE;
static volatile U32   g_kh_busy = 0;

// ----------------------------------------------------------------------------
// Key hart side (runs on hart KEYHART_ID, stack in .keyvault)
// ----------------------------------------------------------------------------

static inline U0 kh_fence(U0) { __asm__ __volatile__("fence rw, rw" ::: "memory"); }

// Request buffers must be ordinary kernel data or heap, never the key vault.
static Bool kh_range_ok(U64 p, U64 len, Bool writable) {
    if (len == 0) return TRUE;
    if (p + len < p || len > 64ULL * 1024 * 1024) return FALSE;
    U64 kv_lo = pmp_symbol_keyvault_start(), kv_hi = pmp_symbol_keyvault_end();
    if (p < kv_hi && p + len > kv_lo) return FALSE;
    for (U32 i = 0; i < g_kh_policy.count; i++) {
        const PmpPolicyRegion* r = &g_kh_policy.r[i];
        if (StrCmp(r->name, "key-vault") == 0) continue;
        if (p >= r->start && p + len <= r->end) {
            if (writable && !(r->perm & PMP_W)) return FALSE;
            return (r->perm & PMP_R) != 0;
        }
    }
    return FALSE;
}

static I32 kh_derive(const char* pass, const U8* salt, U8* kek) {
    size_t n = 0;
    while (n < KH_PASS_MAX - 1 && pass[n]) n++;
    return yc_argon2id_with_memory((const U8*)pass, n, salt, YC_SALT_LEN, kek, YC_KEY_LEN,
                                   g_kv_argon, sizeof(g_kv_argon));
}

static U0 kh_nonce12(const U8* nonce24, U8* n12) {
    MemSet(n12, 0, 4);
    MemCpy(n12 + 4, nonce24 + 16, 8);
}

// XChaCha20-Poly1305 (RFC 8439 construction, XChaCha nonce extension) with the
// key held in register slot `slot` (K or T). Byte-identical to RustCrypto.
static KeyhartStatus kh_xaead(Bool seal, U32 slot, const U8* nonce, const U8* aad, size_t aad_len,
                              U8* buf, size_t len, U8* tag) {
    U8 n12[12];
    U8 calc[YC_TAG_LEN];
    kh_vk_hchacha(slot, nonce);
    kh_nonce12(nonce, n12);
    kh_vk_chacha_xor(n12, 0, g_kh_zero64, g_kv_otk, 32);
    KeyhartStatus st = KH_OK;
    if (!seal) {
        yc_poly1305_aead_tag(g_kv_otk, aad, aad_len, buf, len, calc);
        if (!yc_ct_eq(calc, tag, YC_TAG_LEN)) st = KH_ERR_AUTH;
    }
    if (st == KH_OK) {
        kh_vk_chacha_xor(n12, 1, buf, buf, len);
        if (seal) yc_poly1305_aead_tag(g_kv_otk, aad, aad_len, buf, len, tag);
    }
    yc_wipe(g_kv_otk, sizeof(g_kv_otk));
    yc_wipe(calc, sizeof(calc));
    kh_vk_clear_sub();
    return st;
}

// Unwraps hdr->wrapped_dek with the KEK in slot T straight into register slot dst.
static KeyhartStatus kh_unwrap_with_t(const VaultHeader* hdr, U32 dst) {
    U8 n12[12];
    U8 calc[YC_TAG_LEN];
    kh_vk_hchacha(SLOT_T, hdr->wrap_nonce);
    kh_nonce12(hdr->wrap_nonce, n12);
    kh_vk_chacha_xor(n12, 0, g_kh_zero64, g_kv_otk, 32);
    yc_poly1305_aead_tag(g_kv_otk, (const U8*)hdr, VAULT_HDR_AAD_LEN, hdr->wrapped_dek, YC_KEY_LEN, calc);
    KeyhartStatus st = yc_ct_eq(calc, hdr->wrap_tag, YC_TAG_LEN) ? KH_OK : KH_ERR_AUTH;
    if (st == KH_OK) kh_vk_chacha_to_slot(n12, 1, hdr->wrapped_dek, dst);
    yc_wipe(g_kv_otk, sizeof(g_kv_otk));
    kh_vk_clear_sub();
    return st;
}

// Wraps the key in register slot src with the KEK in slot T; fills hdr's wrap
// fields. A fresh random nonce is drawn unless `keep_nonce` (known-answer test,
// which runs before the DRBG is seeded).
static KeyhartStatus kh_wrap_with_t(VaultHeader* hdr, U32 src, Bool keep_nonce) {
    U8 n12[12];
    if (!keep_nonce && yc_rng_fill(hdr->wrap_nonce, YC_NONCE_LEN) != YC_OK) return KH_ERR_ENTROPY;
    kh_vk_hchacha(SLOT_T, hdr->wrap_nonce);
    kh_nonce12(hdr->wrap_nonce, n12);
    kh_vk_chacha_xor(n12, 0, g_kh_zero64, g_kv_otk, 32);
    kh_vk_chacha_from_slot(n12, 1, src, hdr->wrapped_dek);
    yc_poly1305_aead_tag(g_kv_otk, (const U8*)hdr, VAULT_HDR_AAD_LEN, hdr->wrapped_dek, YC_KEY_LEN, hdr->wrap_tag);
    yc_wipe(g_kv_otk, sizeof(g_kv_otk));
    kh_vk_clear_sub();
    return KH_OK;
}

// KEK = Argon2id(pass, salt) -> register slot T. The KEK bytes touch private
// RAM only between derivation and the register load.
static KeyhartStatus kh_load_kek(const char* pass, const U8* salt) {
    U8* kek = g_kv_tmp;
    if (kh_derive(pass, salt, kek) != YC_OK) return KH_ERR_PARAM;
    kh_vk_load(SLOT_T, kek);
    yc_wipe(kek, YC_KEY_LEN);
    return KH_OK;
}

static KeyhartStatus kh_unwrap(const char* pass, const VaultHeader* hdr, U32 dst) {
    KeyhartStatus st = kh_load_kek(pass, hdr->salt);
    if (st == KH_OK) st = kh_unwrap_with_t(hdr, dst);
    kh_vk_clear(SLOT_T);
    return st;
}

static KeyhartStatus kh_wrap(const char* pass, VaultHeader* hdr, U32 src) {
    KeyhartStatus st = kh_load_kek(pass, hdr->salt);
    if (st == KH_OK) st = kh_wrap_with_t(hdr, src, FALSE);
    kh_vk_clear(SLOT_T);
    return st;
}

static inline U64 kh_time(U0) {
    U64 t;
    __asm__ __volatile__("rdtime %0" : "=r"(t));
    return t;
}

// BLAKE2b-256(.text || .rodata) against the build-time value.
static ImageState kh_check_image(U0) {
    if (g_image_hash.magic != IMAGE_HASH_MAGIC) return IMG_NO_HASH;
    U64 tlen = g_integ_sym[1] - g_integ_sym[0];
    U64 rlen = g_integ_sym[3] - g_integ_sym[2];
    if (tlen != g_image_hash.text_len || rlen != g_image_hash.rodata_len) return IMG_MISMATCH;
    U8 h[32];
    yc_blake2b256_2((const U8*)(uintptr_t)g_integ_sym[0], tlen, (const U8*)(uintptr_t)g_integ_sym[2], rlen, h);
    U8 want[32];
    for (U32 i = 0; i < 32; i++) want[i] = g_image_hash.hash[i];
    return yc_ct_eq(h, want, 32) ? IMG_OK : IMG_MISMATCH;
}

static U32 kh_chunk_count(U0) {
    U64 len = g_integ_sym[4] - g_integ_sym[0];
    U32 n = (U32)((len + INTEG_CHUNK - 1) / INTEG_CHUNK);
    return n > INTEG_MAX_CHUNKS ? INTEG_MAX_CHUNKS : n;
}

static U0 kh_chunk_mac(U32 i, U8* out) {
    U64 lo = g_integ_sym[0] + (U64)i * INTEG_CHUNK;
    U64 hi = lo + INTEG_CHUNK;
    if (hi > g_integ_sym[4]) hi = g_integ_sym[4];
    yc_blake2b256_mac(g_kv_mackey, i, (const U8*)(uintptr_t)lo, hi - lo, out);
}

// Re-checks the image, draws a fresh MAC key and records the baseline.
static KeyhartStatus kh_integrity_arm(U0) {
    g_integ.image_state = kh_check_image();
    if (g_integ.image_state == IMG_MISMATCH) return KH_ERR_AUTH;
    if (yc_rng_fill(g_kv_mackey, sizeof(g_kv_mackey)) != YC_OK) return KH_ERR_ENTROPY;
    U32 n = kh_chunk_count();
    for (U32 i = 0; i < n; i++) kh_chunk_mac(i, g_kv_tags[i]);
    g_kv_next_chunk = 0;
    g_kv_last_check = kh_time();
    g_integ.chunks = n;
    g_integ.armed = 1;
    return KH_OK;
}

// One chunk per call, paced by the timebase so that a full pass takes
// INTEG_PASS_TICKS whatever the image size (it used to be one chunk every
// 2 ms: a pass every 14-24 ms, keeping the key hart hashing nearly all the
// time). A change locks the vault immediately: the code that guards it is
// suspect.
static U0 kh_integrity_step(U0) {
    if (!g_integ.armed) return;
    U64 now = kh_time();
    if (now - g_kv_last_check < INTEG_PASS_TICKS / g_integ.chunks) return;
    g_kv_last_check = now;
    U32 i = g_kv_next_chunk;
    U8 tag[32];
    kh_chunk_mac(i, tag);
    if (!yc_ct_eq(tag, g_kv_tags[i], 32)) {
        if (!g_integ.alarm) {
            g_integ.alarm_addr = g_integ_sym[0] + (U64)i * INTEG_CHUNK;
            g_integ.alarm = 1;
        }
        if (g_kv_loaded) {
            kh_vk_clear(SLOT_K);
            g_kv_loaded = 0;
            g_integ.vault_locked_by_alarm = 1;
        }
    }
    g_integ.chunks_checked++;
    if (++g_kv_next_chunk >= g_integ.chunks) {
        g_kv_next_chunk = 0;
        g_integ.full_passes++;
    }
}

static KeyhartStatus kh_handle(KeyhartMailbox* m) {
    m->pass[KH_PASS_MAX - 1] = '\0';
    m->pass2[KH_PASS_MAX - 1] = '\0';
    switch (m->op) {
        case KH_OP_CREATE: {
            // New key: random bytes -> register slot K, RAM copy wiped at once.
            if (yc_rng_fill(g_kv_tmp, YC_KEY_LEN) != YC_OK) return KH_ERR_ENTROPY;
            kh_vk_load(SLOT_K, g_kv_tmp);
            yc_wipe(g_kv_tmp, YC_KEY_LEN);
            KeyhartStatus st = kh_wrap(m->pass, &m->hdr, SLOT_K);
            if (st == KH_OK) g_kv_loaded = 1;
            else kh_vk_clear(SLOT_K);
            return st;
        }
        case KH_OP_UNLOCK: {
            KeyhartStatus st = kh_unwrap(m->pass, &m->hdr, SLOT_K);
            if (st == KH_OK) g_kv_loaded = 1;
            return st;
        }
        case KH_OP_LOCK:
            kh_vk_clear(SLOT_K);
            g_kv_loaded = 0;
            return KH_OK;
        case KH_OP_REWRAP: {
            KeyhartStatus st = kh_unwrap(m->pass, &m->hdr, SLOT_D);
            if (st == KH_OK) st = kh_wrap(m->pass2, &m->hdr2, SLOT_D);
            kh_vk_clear(SLOT_D);
            return st;
        }
        case KH_OP_SEAL:
        case KH_OP_OPEN: {
            if (!g_kv_loaded) return KH_ERR_LOCKED;
            if (!kh_range_ok(m->buf, m->len, TRUE) || !kh_range_ok(m->aad, m->aad_len, FALSE)) {
                return KH_ERR_PARAM;
            }
            return kh_xaead(m->op == KH_OP_SEAL, SLOT_K, m->nonce, (const U8*)(uintptr_t)m->aad, m->aad_len,
                            (U8*)(uintptr_t)m->buf, m->len, m->tag);
        }
        case KH_OP_SCAN: {
            // Self-test: occurrences of the key's first 8 bytes in private RAM
            // (whole key vault) and in the shared mailbox; Argon2 memory wiped.
            if (!g_kv_loaded) return KH_ERR_LOCKED;
            U64 kv_lo = pmp_symbol_keyvault_start(), kv_hi = pmp_symbol_keyvault_end();
            m->scan_hits = kh_vk_count(SLOT_K, (const U8*)(uintptr_t)kv_lo, kv_hi - kv_lo) +
                           kh_vk_count(SLOT_K, (const U8*)m, sizeof(*m));
            U64 nz = 0;
            for (size_t i = 0; i < sizeof(g_kv_argon); i += 8) nz |= *(const U64*)&g_kv_argon[i];
            m->argon_dirty = (nz != 0);
            return KH_OK;
        }
        case KH_OP_STATUS:
            return KH_OK;
        case KH_OP_INTEG_ARM:
            return kh_integrity_arm();
        default:
            return KH_ERR_PARAM;
    }
}

// Known-answer test at boot: the register-resident XChaCha20-Poly1305 must be
// byte-identical to RustCrypto (same files must open either way), and the
// register wrap/unwrap must round-trip. Uses a test key, never the vault key.
// KAT diagnostics (test key material only, shared with hart 0 for reporting)
static volatile U32 g_kh_kat_step = 0;
static U8 g_kh_kat_dump[4][16];

static Bool kh_known_answer_test(U0) {
    static const U8 key[32] __attribute__((aligned(8))) = {
        0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f };
    static const U8 nonce[24] = {
        0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,
        0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57 };
    static const U8 aad[12] = { 0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7 };
    static U8 a[150], b[150];
    U8 ta[16], tb[16];
    for (U32 i = 0; i < sizeof(a); i++) a[i] = b[i] = (U8)(i * 7 + 3);

    // 1. Seal: registers vs RustCrypto (odd length exercises the tail path)
    kh_vk_load(SLOT_K, key);
    Bool ok = kh_xaead(TRUE, SLOT_K, nonce, aad, sizeof(aad), a, sizeof(a), ta) == KH_OK;
    ok &= yc_aead_seal(key, nonce, aad, sizeof(aad), b, sizeof(b), tb) == YC_OK;
    MemCpy(g_kh_kat_dump[0], a, 16);
    MemCpy(g_kh_kat_dump[1], b, 16);
    MemCpy(g_kh_kat_dump[2], ta, 16);
    MemCpy(g_kh_kat_dump[3], tb, 16);
    ok &= MemCmp(a, b, sizeof(a)) == 0 && MemCmp(ta, tb, 16) == 0;
    if (!ok) { g_kh_kat_step = 1; return FALSE; }
    // 2. Open with registers, and reject a modified tag
    ok &= kh_xaead(FALSE, SLOT_K, nonce, aad, sizeof(aad), a, sizeof(a), ta) == KH_OK;
    for (U32 i = 0; i < sizeof(a); i++) ok &= (a[i] == (U8)(i * 7 + 3));
    tb[0] ^= 1;
    ok &= kh_xaead(FALSE, SLOT_K, nonce, aad, sizeof(aad), b, sizeof(b), tb) == KH_ERR_AUTH;
    if (!ok) { g_kh_kat_step = 2; return FALSE; }

    // 3. Wrap K under a test KEK (in T) and compare with RustCrypto; unwrap into D
    static VaultHeader h;
    MemSet(&h, 0, sizeof(h));
    h.magic = VAULT_HDR_MAGIC;
    kh_vk_load(SLOT_T, g_kh_zero64);       // KEK = 32 zero bytes (test only)
    MemCpy(h.wrap_nonce, nonce, YC_NONCE_LEN);
    ok &= kh_wrap_with_t(&h, SLOT_K, TRUE) == KH_OK;
    U8 ref[32];
    U8 reftag[16];
    MemCpy(ref, key, 32);
    ok &= yc_aead_seal(g_kh_zero64, h.wrap_nonce, (const U8*)&h, VAULT_HDR_AAD_LEN, ref, 32, reftag) == YC_OK;
    ok &= MemCmp(ref, h.wrapped_dek, 32) == 0 && MemCmp(reftag, h.wrap_tag, 16) == 0;
    if (!ok) {
        MemCpy(g_kh_kat_dump[0], h.wrapped_dek, 16);
        MemCpy(g_kh_kat_dump[1], ref, 16);
        MemCpy(g_kh_kat_dump[2], h.wrap_tag, 16);
        MemCpy(g_kh_kat_dump[3], reftag, 16);
        g_kh_kat_step = 3;
        return FALSE;
    }
    ok &= kh_unwrap_with_t(&h, SLOT_D) == KH_OK;
    if (!ok) { g_kh_kat_step = 4; return FALSE; }
    ok &= kh_vk_count(SLOT_D, key, 32) == 1;

    kh_vk_clear(SLOT_K);
    kh_vk_clear(SLOT_T);
    kh_vk_clear(SLOT_D);
    yc_wipe(a, sizeof(a));
    yc_wipe(b, sizeof(b));
    return ok;
}

__attribute__((noreturn)) static U0 keyhart_loop(U0) {
    KeyhartMailbox* m = &g_kh_mb;
    while (1) {
        kh_fence();
        U64 req = m->seq_req;
        if (req != m->seq_resp) {
            m->status = (I32)kh_handle(m);
            m->loaded = g_kv_loaded;
            yc_wipe((U8*)m->pass, sizeof(m->pass));
            yc_wipe((U8*)m->pass2, sizeof(m->pass2));
            kh_fence();
            m->seq_resp = req;
            kh_fence();
        } else {
            kh_integrity_step();
            __asm__ __volatile__(".word 0x0100000F");   // PAUSE hint
        }
    }
}

U0 keyhart_enter(U32 hart_id) {
    (U0)hart_id;
    // No interrupts on the key hart: it has no access to the CLINT or UART.
    __asm__ __volatile__("csrc mstatus, %0" : : "r"(1ULL << 3));
    __asm__ __volatile__("csrw mie, zero");
    __asm__ __volatile__("csrs mstatus, %0" : : "r"(3ULL << 9));   // vector unit on: keys live in v-registers
    if (!g_kh_staged || !pmp_lock_layout_silent(&g_kh_policy, &g_kh_layout)) {
        g_kh_boot_state = 2;
        kh_fence();
        while (1) __asm__ __volatile__("wfi");
    }
    // Switch to the private stack (key-derived locals never touch the shared
    // hart stacks), run the known-answer test, then serve requests forever.
    U64 sp = (U64)(uintptr_t)(g_kv_stack + sizeof(g_kv_stack));
    __asm__ __volatile__("mv sp, %0\n\tj keyhart_loop_entry" : : "r"(sp) : "memory");
    __builtin_unreachable();
}

// Assembly-visible entry (static functions are not addressable by name).
__attribute__((noreturn, used)) U0 keyhart_loop_entry(U0) {
    g_kv_loaded = 0;
    kh_vk_clear(SLOT_K);
    g_integ.image_state = kh_check_image();
    if (!kh_known_answer_test()) {
        g_kh_boot_state = 3;
        kh_fence();
        while (1) __asm__ __volatile__("wfi");
    }
    g_kh_boot_state = 1;
    kh_fence();
    keyhart_loop();
}

// ----------------------------------------------------------------------------
// Boot (hart 0)
// ----------------------------------------------------------------------------

Bool keyhart_prepare_layout(U0) {
    MemSet(&g_kh_mb, 0, sizeof(g_kh_mb));
    if (!pmp_keyhart_policy(&g_kh_policy) || !pmp_build_layout(&g_kh_policy, &g_kh_layout) ||
        g_kh_layout.count > pmp_hw_entry_count()) {
        kprintf("[KEYHART] cannot build the key hart PMP layout\n");
        return FALSE;
    }
    if (!pmp_keyhart_matches_certificate(&g_kh_layout)) {
        kprintf("[KEYHART] key hart layout differs from the Z3 certificate\n");
        return FALSE;
    }
    if (!pmp_verify_layout(&g_kh_policy, g_kh_layout.addr, g_kh_layout.cfg, g_kh_layout.count, TRUE)) {
        kprintf("[KEYHART] key hart layout does not implement its policy\n");
        return FALSE;
    }
    kh_fence();
    g_kh_staged = TRUE;
    return TRUE;
}

U0 keyhart_verify_booted(U0) {
    if (smp_get_hart_count() <= KEYHART_ID) {
        kprintf("[KEYHART] fewer than %u harts: no key hart, vault unavailable\n", KEYHART_ID + 1);
        return;
    }
    U64 t0 = timer_get_uptime_ms();
    while (g_kh_boot_state == 0 && timer_get_uptime_ms() - t0 < 500) kh_fence();
    if (g_kh_boot_state == 3) {
        kprintf("[KEYHART] register-resident XChaCha20-Poly1305 failed its known-answer test (step %u); vault unavailable\n",
                g_kh_kat_step);
        for (U32 r = 0; r < 4; r++) {
            kprintf("[KEYHART]   %s:", r == 0 ? "asm ct " : r == 1 ? "rust ct" : r == 2 ? "asm tag" : "rusttag");
            for (U32 i = 0; i < 16; i++) kprintf(" %02x", g_kh_kat_dump[r][i]);
            kprintf("\n");
        }
        return;
    }
    if (g_kh_boot_state != 1) {
        kprintf("[KEYHART] hart %u failed to lock/verify its PMP layout; vault unavailable\n", KEYHART_ID);
        return;
    }
    g_kh_verified = TRUE;
    kprintf(" [ OK ] Key hart %u: private key vault locked (%u PMP entries), DEK never visible to other harts\n",
            KEYHART_ID, g_kh_layout.count);
    kprintf(" [ OK ] Key hart %u: DEK held in vector registers only; XChaCha20-Poly1305 KAT matches RustCrypto\n",
            KEYHART_ID);
    if (g_integ.image_state == IMG_OK) {
        kprintf(" [ OK ] Kernel image: BLAKE2b-256 of .text+.rodata matches the build\n");
    } else {
        kprintf("[INTEGRITY] WARNING: kernel image hash %s\n",
                g_integ.image_state == IMG_MISMATCH ? "DOES NOT MATCH the build (corrupted image)" : "not available");
    }
}

Bool keyhart_available(U0) {
    return g_kh_verified;
}

// ----------------------------------------------------------------------------
// Hart 0 API
// ----------------------------------------------------------------------------

static KeyhartStatus kh_call(U32 op) {
    if (!g_kh_verified) return KH_ERR_UNAVAILABLE;
    KeyhartMailbox* m = &g_kh_mb;
    m->op = op;
    kh_fence();
    U64 req = m->seq_resp + 1;
    m->seq_req = req;
    kh_fence();
    U64 t0 = timer_get_uptime_ms();
    while (m->seq_resp != req) {
        if (timer_get_uptime_ms() - t0 > KH_TIMEOUT_MS) return KH_ERR_TIMEOUT;
        kh_fence();
    }
    return (KeyhartStatus)m->status;
}

static Bool kh_acquire(U0) {
    while (__atomic_exchange_n(&g_kh_busy, 1, __ATOMIC_ACQUIRE)) {
    }
    return TRUE;
}

static U0 kh_release(U0) {
    yc_wipe((U8*)g_kh_mb.pass, sizeof(g_kh_mb.pass));
    yc_wipe((U8*)g_kh_mb.pass2, sizeof(g_kh_mb.pass2));
    __atomic_store_n(&g_kh_busy, 0, __ATOMIC_RELEASE);
}

static U0 kh_copy_pass(char* dst, const char* src) {
    size_t i = 0;
    for (; src && src[i] && i < KH_PASS_MAX - 1; i++) dst[i] = src[i];
    dst[i] = '\0';
}

KeyhartStatus keyhart_create(const char* pass, VaultHeader* hdr) {
    kh_acquire();
    kh_copy_pass(g_kh_mb.pass, pass);
    MemCpy(&g_kh_mb.hdr, hdr, sizeof(*hdr));
    KeyhartStatus st = kh_call(KH_OP_CREATE);
    if (st == KH_OK) MemCpy(hdr, &g_kh_mb.hdr, sizeof(*hdr));
    kh_release();
    return st;
}

KeyhartStatus keyhart_unlock(const char* pass, const VaultHeader* hdr) {
    kh_acquire();
    kh_copy_pass(g_kh_mb.pass, pass);
    MemCpy(&g_kh_mb.hdr, hdr, sizeof(*hdr));
    KeyhartStatus st = kh_call(KH_OP_UNLOCK);
    kh_release();
    return st;
}

KeyhartStatus keyhart_lock(U0) {
    kh_acquire();
    KeyhartStatus st = kh_call(KH_OP_LOCK);
    kh_release();
    return st;
}

KeyhartStatus keyhart_rewrap(const char* old_pass, const VaultHeader* old_hdr,
                             const char* new_pass, VaultHeader* new_hdr) {
    kh_acquire();
    kh_copy_pass(g_kh_mb.pass, old_pass);
    kh_copy_pass(g_kh_mb.pass2, new_pass);
    MemCpy(&g_kh_mb.hdr, old_hdr, sizeof(*old_hdr));
    MemCpy(&g_kh_mb.hdr2, new_hdr, sizeof(*new_hdr));
    KeyhartStatus st = kh_call(KH_OP_REWRAP);
    if (st == KH_OK) MemCpy(new_hdr, &g_kh_mb.hdr2, sizeof(*new_hdr));
    kh_release();
    return st;
}

static KeyhartStatus kh_aead(U32 op, const U8* nonce, const U8* aad, size_t aad_len, U8* buf, size_t len, U8* tag) {
    kh_acquire();
    MemCpy(g_kh_mb.nonce, nonce, YC_NONCE_LEN);
    if (op == KH_OP_OPEN) MemCpy(g_kh_mb.tag, tag, YC_TAG_LEN);
    g_kh_mb.aad = (U64)(uintptr_t)aad;
    g_kh_mb.aad_len = aad_len;
    g_kh_mb.buf = (U64)(uintptr_t)buf;
    g_kh_mb.len = len;
    KeyhartStatus st = kh_call(op);
    if (st == KH_OK && op == KH_OP_SEAL) MemCpy(tag, g_kh_mb.tag, YC_TAG_LEN);
    kh_release();
    return st;
}

KeyhartStatus keyhart_seal(const U8* nonce, const U8* aad, size_t aad_len, U8* buf, size_t len, U8* tag) {
    return kh_aead(KH_OP_SEAL, nonce, aad, aad_len, buf, len, tag);
}

KeyhartStatus keyhart_open(const U8* nonce, const U8* aad, size_t aad_len, U8* buf, size_t len, const U8* tag) {
    return kh_aead(KH_OP_OPEN, nonce, aad, aad_len, buf, len, (U8*)tag);
}

Bool keyhart_is_unlocked(U0) {
    if (!g_kh_verified) return FALSE;
    kh_acquire();
    KeyhartStatus st = kh_call(KH_OP_STATUS);
    Bool loaded = (st == KH_OK) && g_kh_mb.loaded;
    kh_release();
    return loaded;
}

// ----------------------------------------------------------------------------
// Self-test (hart 0)
// ----------------------------------------------------------------------------

extern Bool pmp_probe_load(U64 addr);

Bool keyhart_self_test(U0) {
    kprintf("\n================ [ KEY HART SELF-TEST ] ================\n");
    if (!g_kh_verified) {
        kprintf("  Key hart not available.\n");
        return FALSE;
    }
    Bool ok = TRUE;
    U64 kv = pmp_symbol_keyvault_start();

    Bool f1 = pmp_probe_load((U64)(uintptr_t)g_kv_tmp);
    kprintf("  %s hart 0 cannot read the key hart's private RAM (0x%p)\n", f1 ? "[PASS]" : "[FAIL]",
            (void*)(uintptr_t)g_kv_tmp);
    ok &= f1;
    Bool f2 = pmp_probe_load((U64)(uintptr_t)g_kv_argon);
    kprintf("  %s hart 0 cannot read the Argon2 memory\n", f2 ? "[PASS]" : "[FAIL]");
    ok &= f2;

    // Confused deputy: ask the key hart to seal/open buffers inside its vault
    U8 nonce[YC_NONCE_LEN] = { 0 };
    U8 tag[YC_TAG_LEN] = { 0 };
    kh_acquire();
    MemCpy(g_kh_mb.nonce, nonce, sizeof(nonce));
    g_kh_mb.aad = 0; g_kh_mb.aad_len = 0;
    g_kh_mb.buf = kv; g_kh_mb.len = 32;
    KeyhartStatus st = kh_call(KH_OP_SEAL);
    kh_release();
    Bool f3 = (st == KH_ERR_PARAM || st == KH_ERR_LOCKED);
    kprintf("  %s key hart refuses buffers inside the key vault (%u)\n", f3 ? "[PASS]" : "[FAIL]", (U32)st);
    ok &= f3;

    kh_acquire();
    g_kh_mb.buf = 0x10000000; g_kh_mb.len = 16;   // device registers
    st = kh_call(KH_OP_SEAL);
    kh_release();
    Bool f4 = (st == KH_ERR_PARAM || st == KH_ERR_LOCKED);
    kprintf("  %s key hart refuses device-register buffers (%u)\n", f4 ? "[PASS]" : "[FAIL]", (U32)st);
    ok &= f4;

    // Round trip through the key hart with a loaded key (only if unlocked)
    if (keyhart_is_unlocked()) {
        static U8 msg[32] = "round-trip through the key hart";
        U8 copy[32];
        MemCpy(copy, msg, sizeof(copy));
        Bool f5 = keyhart_seal(nonce, NULL, 0, msg, sizeof(msg), tag) == KH_OK &&
                  MemCmp(msg, copy, sizeof(msg)) != 0 &&
                  keyhart_open(nonce, NULL, 0, msg, sizeof(msg), tag) == KH_OK &&
                  MemCmp(msg, copy, sizeof(msg)) == 0;
        kprintf("  %s seal/open round trip with the register-resident DEK\n", f5 ? "[PASS]" : "[FAIL]");
        ok &= f5;

        kh_acquire();
        st = kh_call(KH_OP_SCAN);
        U64 hits = g_kh_mb.scan_hits;
        U32 dirty = g_kh_mb.argon_dirty;
        kh_release();
        Bool f6 = (st == KH_OK && hits == 0);
        kprintf("  %s DEK absent from key hart RAM and mailbox (%u occurrences)\n", f6 ? "[PASS]" : "[FAIL]", (U32)hits);
        ok &= f6;
        Bool f7 = (st == KH_OK && !dirty);
        kprintf("  %s Argon2 working memory wiped after use\n", f7 ? "[PASS]" : "[FAIL]");
        ok &= f7;
    } else {
        kprintf("  [SKIP] seal/open round trip (vault locked)\n");
    }
    (U0)tag;
    kprintf("  Result: %s\n", ok ? "KEY NOT REACHABLE OUTSIDE THE KEY HART" : "FAILURE");
    kprintf("========================================================\n");
    return ok;
}

// ----------------------------------------------------------------------------
// Integrity monitor, hart 0 side
// ----------------------------------------------------------------------------

const IntegrityStatus* integrity_status(U0) {
    return &g_integ;
}

Bool integrity_arm(U0) {
    if (!g_kh_verified) return FALSE;
    kh_acquire();
    KeyhartStatus st = kh_call(KH_OP_INTEG_ARM);
    kh_release();
    if (st == KH_OK) {
        kprintf(" [ OK ] Integrity monitor armed on key hart: %u x 64 KiB chunks of code and read-only data,\n"
                "        keyed BLAKE2b-256 baseline, continuous re-verification\n", g_integ.chunks);
        return TRUE;
    }
    kprintf("[INTEGRITY] could not arm the monitor (status %u, image %u)\n", (U32)st, g_integ.image_state);
    return FALSE;
}

U0 integrity_poll(U0) {
    if (!g_integ.alarm || g_integ_reported) return;
    g_integ_reported = 1;
    kprintf("\n[INTEGRITY] ALERT: kernel code/read-only data changed after boot (chunk at 0x%p).\n",
            (void*)(uintptr_t)g_integ.alarm_addr);
    kprintf("[INTEGRITY] The PMP forbids such writes in software: suspect a hardware fault or DMA.\n");
    if (g_integ.vault_locked_by_alarm) {
        kprintf("[INTEGRITY] The key hart locked the vault and wiped its key. Reboot before unlocking.\n");
    }
#ifdef YESOS_WITH_VAULT
    extern U0 vault_lock(U0);
    vault_lock();
#endif
}

U0 integrity_print_status(U0) {
    static const char* const img[] = { "unknown", "OK (matches build)", "MISMATCH", "no build hash" };
    kprintf("\n================ [ INTEGRITY MONITOR (key hart) ] ================\n");
    kprintf("  Boot image hash : %s\n", img[g_integ.image_state & 3]);
    kprintf("  Monitor         : %s\n", g_integ.armed ? "ARMED (keyed BLAKE2b-256 per 64 KiB chunk)" : "not armed");
    kprintf("  Coverage        : %u chunks (kernel code + read-only data)\n", g_integ.chunks);
    kprintf("  Chunks checked  : %u | full passes: %u\n", (U32)g_integ.chunks_checked, (U32)g_integ.full_passes);
    if (g_integ.alarm) {
        kprintf("  ALARM           : chunk at 0x%p changed%s\n", (void*)(uintptr_t)g_integ.alarm_addr,
                g_integ.vault_locked_by_alarm ? "; vault locked by the key hart" : "");
    } else {
        kprintf("  Alarm           : none\n");
    }
    kprintf("==================================================================\n");
}
