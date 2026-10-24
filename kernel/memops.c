// Memory primitives: MemSet, MemCpy, memset, memcpy, memmove.
//
// No unaligned access, ever: RISC-V cores may trap on one, and in M-mode
// YesOS has no handler that would emulate it. Bulk work is done with 64-bit
// words on 8-byte boundaries; when source and destination are aligned
// differently, aligned source words are shifted together into each aligned
// store. Scalar only: these are reachable from the key hart, which must
// never execute a vector instruction (tools/check_keyhart_vector.py).
// tools/test_memops.py checks them on the host under UBSan's alignment check.
#include "memory.h"

typedef U64 __attribute__((may_alias)) Word;

static inline Word splat(U8 v) { return (Word)v * 0x0101010101010101ULL; }

void* MemSet(void* dest, I32 val, size_t count) {
    if (!dest || count == 0) return dest;
    U8* d = (U8*)dest;
    U8 v = (U8)val;
    while (count && ((U64)d & 7)) { *d++ = v; count--; }
    Word w = splat(v);
    for (; count >= 8; count -= 8, d += 8) *(Word*)d = w;
    while (count--) *d++ = v;
    return dest;
}

// Forward copy of n bytes, d below s or not overlapping.
static inline __attribute__((always_inline)) U0 copy_forward(U8* d, const U8* s, size_t n) {
    if (n >= 16) {
        while ((U64)d & 7) { *d++ = *s++; n--; }       // d aligned from here on
        U32 off = (U32)((U64)s & 7);
        size_t bulk = n & ~(size_t)7;
        Word* dw = (Word*)d;
        Word* end = (Word*)(d + bulk);
        if (off == 0) {
            const Word* sw = (const Word*)s;
            while (dw != end) *dw++ = *sw++;
        } else {
            // Each aligned source word read holds at least one byte that is
            // copied, so no read reaches past the source's last aligned word.
            const Word* sw = (const Word*)(s - off);
            U32 lo = off * 8, hi = 64 - lo;
            Word w0 = *sw++;
            if ((bulk >> 3) & 1) {                     // an odd word first, then pairs
                Word w1 = *sw++;
                *dw++ = (w0 >> lo) | (w1 << hi);       // little-endian
                w0 = w1;
            }
            while (dw != end) {
                Word w1 = sw[0], w2 = sw[1];
                sw += 2;
                dw[0] = (w0 >> lo) | (w1 << hi);
                dw[1] = (w1 >> lo) | (w2 << hi);
                dw += 2;
                w0 = w2;
            }
        }
        d += bulk;
        s += bulk;
        n -= bulk;
    }
    while (n--) *d++ = *s++;
}

void* MemCpy(void* dest, const void* src, size_t count) {
    if (!dest || !src || count == 0) return dest;
    copy_forward((U8*)dest, (const U8*)src, count);
    return dest;
}

void* memcpy(void* dest, const void* src, size_t count) {
    return MemCpy(dest, src, count);
}

void* memset(void* dest, int val, size_t count) {
    return MemSet(dest, val, count);
}

void* memmove(void* dest, const void* src, size_t count) {
    if (!dest || !src || count == 0 || dest == src) return dest;
    U8* d = (U8*)dest;
    const U8* s = (const U8*)src;
    if (d < s || d >= s + count) {                     // forward is safe
        copy_forward(d, s, count);
        return dest;
    }
    d += count;                                        // overlapping, d above s: backwards
    s += count;
    if ((((U64)d ^ (U64)s) & 7) == 0) {
        while (count && ((U64)d & 7)) { *--d = *--s; count--; }
        for (; count >= 8; count -= 8) { d -= 8; s -= 8; *(Word*)d = *(const Word*)s; }
    }
    while (count--) *--d = *--s;
    return dest;
}
