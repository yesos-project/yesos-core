// Poly1305 (RFC 8439 2.5), the "donna-64" layout: the accumulator and r in
// three limbs of 44, 44 and 42 bits, so every product of a block fits a
// 64x64->128-bit multiply (mul + mulhu on RV64). Constant time: no branch or
// memory access depends on the key or the data. Scalar, part of the optional
// core module "chacha" (see chacha20.h); also built on the host by
// tools/test_chacha.py.
#include "chacha20.h"

typedef unsigned __int128 U128;

#define M44 0xFFFFFFFFFFFULL
#define M42 0x3FFFFFFFFFFULL

typedef struct {
    U64 r0, r1, r2, s1, s2;     // r clamped; s = r * 5 * 4 (the reduction folded in)
    U64 h0, h1, h2;             // accumulator
    U64 pad0, pad1;             // the key's second half, added at the end
} Poly;

static inline U64 le64(const U8* p) {
    U64 v = 0;
    for (U32 i = 0; i < 8; i++) v |= (U64)p[i] << (8 * i);
    return v;
}

typedef U64 __attribute__((may_alias)) Word;

// The two little-endian words of a 16-byte block at any address, with
// aligned loads only (an unaligned access may trap on RISC-V): when m is
// unaligned, three aligned words are shifted together; each holds at least
// one byte of the block, so nothing past it is read. The branch depends on
// the address, not on the key or the data.
static inline U0 ld_block(const U8* m, U64* t0, U64* t1) {
    U32 off = (U32)((U64)m & 7);
    if (off == 0) {
        *t0 = ((const Word*)m)[0];
        *t1 = ((const Word*)m)[1];
    } else {
        const Word* a = (const Word*)(m - off);
        U32 lo = off * 8, hi = 64 - lo;
        U64 w0 = a[0], w1 = a[1], w2 = a[2];
        *t0 = (w0 >> lo) | (w1 << hi);
        *t1 = (w1 >> lo) | (w2 << hi);
    }
}

static inline U0 st64(U8* p, U64 v) {
    for (U32 i = 0; i < 8; i++) p[i] = (U8)(v >> (8 * i));
}

static U0 poly_init(Poly* p, const U8 key[32]) {
    U64 t0 = le64(key), t1 = le64(key + 8);
    p->r0 = t0 & 0xFFC0FFFFFFFULL;                          // clamped as RFC 8439 2.5.1
    p->r1 = ((t0 >> 44) | (t1 << 20)) & 0xFFFFFC0FFFFULL;
    p->r2 = (t1 >> 24) & 0x00FFFFFFC0FULL;
    p->s1 = p->r1 * (5 << 2);
    p->s2 = p->r2 * (5 << 2);
    p->h0 = p->h1 = p->h2 = 0;
    p->pad0 = le64(key + 16);
    p->pad1 = le64(key + 24);
}

// Whole 16-byte blocks; hibit is 2^128 in the top limb (1 << 40), or 0 for
// a final short block that already carries its 0x01 pad.
static U0 poly_blocks(Poly* p, const U8* m, size_t n, U64 hibit) {
    U64 r0 = p->r0, r1 = p->r1, r2 = p->r2, s1 = p->s1, s2 = p->s2;
    U64 h0 = p->h0, h1 = p->h1, h2 = p->h2;
    for (; n >= 16; n -= 16, m += 16) {
        U64 t0, t1;
        ld_block(m, &t0, &t1);
        h0 += t0 & M44;
        h1 += ((t0 >> 44) | (t1 << 20)) & M44;
        h2 += ((t1 >> 24) & M42) | hibit;
        U128 d0 = (U128)h0 * r0 + (U128)h1 * s2 + (U128)h2 * s1;
        U128 d1 = (U128)h0 * r1 + (U128)h1 * r0 + (U128)h2 * s2;
        U128 d2 = (U128)h0 * r2 + (U128)h1 * r1 + (U128)h2 * r0;
        U64 c = (U64)(d0 >> 44); h0 = (U64)d0 & M44;
        d1 += c; c = (U64)(d1 >> 44); h1 = (U64)d1 & M44;
        d2 += c; c = (U64)(d2 >> 42); h2 = (U64)d2 & M42;
        h0 += c * 5; c = h0 >> 44; h0 &= M44;
        h1 += c;
    }
    p->h0 = h0; p->h1 = h1; p->h2 = h2;
}

static U0 poly_finish(Poly* p, U8 tag[16]) {
    U64 h0 = p->h0, h1 = p->h1, h2 = p->h2, c;
    c = h1 >> 44; h1 &= M44; h2 += c;                       // full carry
    c = h2 >> 42; h2 &= M42; h0 += c * 5;
    c = h0 >> 44; h0 &= M44; h1 += c;
    c = h1 >> 44; h1 &= M44; h2 += c;
    c = h2 >> 42; h2 &= M42; h0 += c * 5;
    c = h0 >> 44; h0 &= M44; h1 += c;
    U64 g0 = h0 + 5; c = g0 >> 44; g0 &= M44;               // g = h + 5 - 2^130
    U64 g1 = h1 + c; c = g1 >> 44; g1 &= M44;
    U64 g2 = h2 + c - (1ULL << 42);
    c = (g2 >> 63) - 1;                                     // all ones if h >= 2^130 - 5
    g0 &= c; g1 &= c; g2 &= c;
    c = ~c;
    h0 = (h0 & c) | g0; h1 = (h1 & c) | g1; h2 = (h2 & c) | g2;
    U64 t0 = p->pad0, t1 = p->pad1;                         // h + s mod 2^128
    h0 += t0 & M44; c = h0 >> 44; h0 &= M44;
    h1 += (((t0 >> 44) | (t1 << 20)) & M44) + c; c = h1 >> 44; h1 &= M44;
    h2 += (t1 >> 24) + c; h2 &= M42;
    st64(tag, h0 | (h1 << 44));
    st64(tag + 8, (h1 >> 20) | (h2 << 24));
}

static U0 poly_wipe(Poly* p) {
    volatile U8* b = (volatile U8*)p;
    for (size_t i = 0; i < sizeof(*p); i++) b[i] = 0;
}

U0 cc20_poly1305(const U8 key[32], const U8* msg, size_t len, U8 tag[16]) {
    Poly p;
    poly_init(&p, key);
    size_t whole = len & ~(size_t)15;
    poly_blocks(&p, msg, whole, 1ULL << 40);
    if (len > whole) {                                      // last short block: 0x01, then zeros
        U8 b[16] = { 0 };
        for (size_t i = 0; i < len - whole; i++) b[i] = msg[whole + i];
        b[len - whole] = 1;
        poly_blocks(&p, b, 16, 0);
    }
    poly_finish(&p, tag);
    poly_wipe(&p);
}

// aad, then data, each zero-padded to 16 bytes and fed as whole blocks.
static U0 poly_padded(Poly* p, const U8* m, size_t n) {
    size_t whole = n & ~(size_t)15;
    poly_blocks(p, m, whole, 1ULL << 40);
    if (n > whole) {
        U8 b[16] = { 0 };
        for (size_t i = 0; i < n - whole; i++) b[i] = m[whole + i];
        poly_blocks(p, b, 16, 1ULL << 40);
    }
}

U0 cc20_poly1305_aead(const U8 otk[32], const U8* aad, size_t aad_len, const U8* ct, size_t ct_len, U8 tag[16]) {
    Poly p;
    poly_init(&p, otk);
    poly_padded(&p, aad, aad_len);
    poly_padded(&p, ct, ct_len);
    U8 lens[16];
    st64(lens, (U64)aad_len);
    st64(lens + 8, (U64)ct_len);
    poly_blocks(&p, lens, 16, 1ULL << 40);
    poly_finish(&p, tag);
    poly_wipe(&p);
}
