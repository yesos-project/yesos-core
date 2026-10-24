// ChaCha20 keystream (RFC 8439), scalar and RVV 1.0 (see chacha20.h).
//
// The vector version runs up to 8 blocks per pass, block j in lane j of
// sixteen e32 registers (one per state word), so the quarter rounds are the
// scalar ones on whole registers; the keystream is stored with a 64-byte
// stride (no transpose) into an aligned buffer and XORed into the data byte
// by byte (e8), so the data's alignment never matters. Afterwards every
// vector register is cleared and the keystream buffer wiped: no key-derived
// value stays behind. Built with -DCC20_HOST, only the scalar version exists
// (tools/test_chacha.py runs it on the host).
#include "chacha20.h"

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define QR(a, b, c, d) do { \
    a += b; d ^= a; d = ROTL(d, 16); c += d; b ^= c; b = ROTL(b, 12); \
    a += b; d ^= a; d = ROTL(d, 8);  c += d; b ^= c; b = ROTL(b, 7); } while (0)

static Bool g_rvv;

static inline U32 le32(const U8* p) { return (U32)p[0] | ((U32)p[1] << 8) | ((U32)p[2] << 16) | ((U32)p[3] << 24); }

static U0 setup(U32 st[16], const U8 key[32], const U8 nonce[12], U32 counter) {
    st[0] = 0x61707865; st[1] = 0x3320646e; st[2] = 0x79622d32; st[3] = 0x6b206574;   // "expand 32-byte k"
    for (U32 i = 0; i < 8; i++) st[4 + i] = le32(key + 4 * i);
    st[12] = counter;
    for (U32 i = 0; i < 3; i++) st[13 + i] = le32(nonce + 4 * i);
}

static U0 wipe(volatile U8* p, size_t n) {
    while (n--) *p++ = 0;
}

// One block of keystream, little-endian, into ks.
static U0 block_scalar(const U32 st[16], U32 counter, U8 ks[64]) {
    U32 x[16];
    for (U32 i = 0; i < 16; i++) x[i] = st[i];
    x[12] = counter;
    for (U32 r = 0; r < 10; r++) {
        QR(x[0], x[4], x[8],  x[12]); QR(x[1], x[5], x[9],  x[13]);
        QR(x[2], x[6], x[10], x[14]); QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]); QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8],  x[13]); QR(x[3], x[4], x[9],  x[14]);
    }
    for (U32 i = 0; i < 16; i++) {
        U32 v = x[i] + (i == 12 ? counter : st[i]);
        ks[4 * i] = (U8)v; ks[4 * i + 1] = (U8)(v >> 8); ks[4 * i + 2] = (U8)(v >> 16); ks[4 * i + 3] = (U8)(v >> 24);
    }
    wipe((volatile U8*)x, sizeof(x));
}

static U0 xor_scalar(const U32 st[16], U32 counter, U8* data, size_t len) {
    U8 ks[64];
    while (len) {
        block_scalar(st, counter++, ks);
        size_t n = len < 64 ? len : 64;
        for (size_t i = 0; i < n; i++) data[i] ^= ks[i];
        data += n;
        len -= n;
    }
    wipe(ks, sizeof(ks));
}

#if defined(__riscv_vector) && !defined(CC20_HOST)
// kernel/chacha20_rvv.c (a file of its own: <riscv_vector.h> brings
// <stdint.h>, whose 64-bit types clash with types.h; the ABI is the same)
U0 cc20_xor_rvv(const U32 st[16], U32 counter, U8* data, size_t len);
#define xor_rvv cc20_xor_rvv
#endif

U0 cc20_init(U0) {
    g_rvv = FALSE;
#if defined(__riscv_vector) && !defined(CC20_HOST)
    U64 misa;
    __asm__ __volatile__("csrr %0, misa" : "=r"(misa));
    g_rvv = (misa >> ('V' - 'A')) & 1;
#endif
}

Bool cc20_has_rvv(U0) { return g_rvv; }

U0 cc20_use_rvv(Bool on) {
#if defined(__riscv_vector) && !defined(CC20_HOST)
    if (!on) g_rvv = FALSE;
    else cc20_init();
#else
    (void)on;
#endif
}

U0 cc20_xor(const U8 key[32], const U8 nonce[12], U32 counter, U8* data, size_t len) {
    if (!len) return;
    U32 st[16];
    setup(st, key, nonce, counter);
#if defined(__riscv_vector) && !defined(CC20_HOST)
    if (g_rvv) xor_rvv(st, counter, data, len);
    else
#endif
    xor_scalar(st, counter, data, len);
    wipe((volatile U8*)st, sizeof(st));
}
