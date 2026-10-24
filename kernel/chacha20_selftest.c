// ChaCha20 self-check: keystreams for keys, nonces and data from a fixed
// pseudo-random sequence, at data offsets 0-3 and lengths around the block
// size up to past a TLS record, plus a run across the counter's wrap: one
// FNV-1a hash per length; then one hash over Poly1305 tags (plain and AEAD).
// Built into the kernel (`chacha test`, scalar and vector) and, with
// CC20_HOST, into the host library of tools/test_chacha.py, which compares
// the hashes.
#include "chacha20.h"

typedef U0 (*Cc20Report)(const char* what, U64 len, U64 hash);

static const U32 g_lens[] = { 0, 1, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1000, 4096, 16401 };
#define BUF_MAX (16401 + 8)
static U8 g_buf[BUF_MAX];
static U64 g_rng;

static U64 rnd(U0) { g_rng ^= g_rng << 13; g_rng ^= g_rng >> 7; g_rng ^= g_rng << 17; return g_rng; }
static U0 fill(U8* p, U64 n) { for (U64 i = 0; i < n; i++) p[i] = (U8)rnd(); }
static U64 fnv(const U8* p, U64 n, U64 h) {
    for (U64 i = 0; i < n; i++) { h ^= p[i]; h *= 0x100000001B3ULL; }
    return h;
}
#define FNV0 0xCBF29CE484222325ULL

U0 cc20_selftest(Cc20Report rep) {
    g_rng = 0x4343323053454C46ULL;                 // "CC20SELF"
    U8 key[32], nonce[12];
    for (U32 k = 0; k < sizeof(g_lens) / sizeof(g_lens[0]); k++) {
        U64 h = FNV0;
        for (U32 off = 0; off < 4; off++) {
            fill(key, 32);
            fill(nonce, 12);
            U32 counter = (U32)rnd() & 0xFFFF;
            fill(g_buf + off, g_lens[k]);
            cc20_xor(key, nonce, counter, g_buf + off, g_lens[k]);
            h = fnv(g_buf + off, g_lens[k], h);
        }
        rep("len", g_lens[k], h);
    }
    fill(key, 32);                                  // 8 blocks across the 32-bit counter's wrap
    fill(nonce, 12);
    fill(g_buf, 512);
    cc20_xor(key, nonce, 0xFFFFFFFDu, g_buf, 512);
    rep("wrap", 512, fnv(g_buf, 512, FNV0));
    U64 h = FNV0;                                   // Poly1305 tags over the same lengths
    for (U32 k = 0; k < sizeof(g_lens) / sizeof(g_lens[0]); k++) {
        U8 tag[16];
        fill(key, 32);
        fill(g_buf + 1, g_lens[k]);
        cc20_poly1305(key, g_buf + 1, g_lens[k], tag);
        h = fnv(tag, 16, h);
        cc20_poly1305_aead(key, g_buf + 1, g_lens[k] % 37, g_buf + 1 + g_lens[k] % 37, g_lens[k] - g_lens[k] % 37, tag);
        h = fnv(tag, 16, h);
    }
    rep("poly", 0, h);
}
