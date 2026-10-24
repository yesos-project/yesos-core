#include "lz4.h"
#include "memory.h"
#include "kprintf.h"
#include "timer.h"
#include "riscv_bitmanip.h"

// Loads and stores at any byte position, without unaligned accesses (a
// RISC-V core may trap on one and M-mode has no handler): direct when the
// address is aligned, else assembled from bytes (little-endian).
typedef U16 __attribute__((may_alias)) A16;
typedef U32 __attribute__((may_alias)) A32;
typedef U64 __attribute__((may_alias)) A64;
static inline U16 ld16(const U8* p) { return ((U64)p & 1) ? (U16)(p[0] | (p[1] << 8)) : *(const A16*)p; }
static inline U32 ld32(const U8* p) {
    if (((U64)p & 3) == 0) return *(const A32*)p;
    return (U32)p[0] | ((U32)p[1] << 8) | ((U32)p[2] << 16) | ((U32)p[3] << 24);
}
static inline U64 ld64(const U8* p) {
    if (((U64)p & 7) == 0) return *(const A64*)p;
    return (U64)ld32(p) | ((U64)ld32(p + 4) << 32);
}
static inline U0 st16(U8* p, U16 v) { p[0] = (U8)v; p[1] = (U8)(v >> 8); }

#define LZ4_MIN_MATCH 4
#define LZ4_HASH_MULT 2654435761U // Golden Ratio 32-bit Hash Multiplier

static inline U32 lz4_hash4(const U8* p) {
    U32 v = ld32(p);
    return (v * LZ4_HASH_MULT) >> (32 - LZ4_MEMORY_USAGE);
}

I64 lz4_compress_bound(I64 isize) {
    return isize + (isize / 255) + 32;
}

// Static BSS hash table to avoid kernel stack overflow
static const U8* s_lz4_hash_table[LZ4_HASH_SIZE];

I64 lz4_compress(const U8* src, I64 src_size, U8* dst, I64 dst_capacity) {
    if (!src || !dst || src_size <= 0 || dst_capacity < lz4_compress_bound(src_size)) {
        return 0;
    }

    const U8* ip = src;
    const U8* const iend = src + src_size;
    const U8* const mflimit = iend - 12;
    const U8* anchor = ip;

    U8* op = dst;
    U8* const oend = dst + dst_capacity;

    for (int i = 0; i < LZ4_HASH_SIZE; i++) s_lz4_hash_table[i] = src;

    if (src_size < 13) goto _last_literals;

    // First byte
    s_lz4_hash_table[lz4_hash4(ip)] = ip;
    ip++;

    while (ip < mflimit) {
        // Find match
        const U8* match;
        U32 h = lz4_hash4(ip);
        match = s_lz4_hash_table[h];
        s_lz4_hash_table[h] = ip;

        if ((match >= src) && (match < ip) && (ip - match < 65536) && (ld32(match) == ld32(ip))) {
            // Match found! Encode literals
            I64 lit_len = ip - anchor;
            U8* token = op++;

            if (op + lit_len + (2 + 1 + (lit_len / 255)) > oend) return 0;

            if (lit_len >= 15) {
                *token = 15 << 4;
                I64 len = lit_len - 15;
                while (len >= 255) {
                    *op++ = 255;
                    len -= 255;
                }
                *op++ = (U8)len;
            } else {
                *token = (U8)(lit_len << 4);
            }

            // Copy literals
            MemCpy(op, anchor, lit_len);
            op += lit_len;

            // Encode match offset (16-bit little endian)
            U16 offset = (U16)(ip - match);
            st16(op, offset);
            op += 2;

            // Encode match length
            ip += 4;
            match += 4;
            const U8* match_start = ip;
            while (ip < (iend - 8)) {
                U64 diff = ld64(ip) ^ ld64(match);
                if (diff == 0) {
                    ip += 8;
                    match += 8;
                } else {
                    ip += (rv_ctz64(diff) >> 3);
                    goto _match_done;
                }
            }
            while (ip < (iend - 5) && (*ip == *match)) {
                ip++;
                match++;
            }
_match_done: ;
            I64 match_len = ip - match_start;

            if (match_len >= 15) {
                *token |= 15;
                I64 len = match_len - 15;
                while (len >= 255) {
                    *op++ = 255;
                    len -= 255;
                }
                *op++ = (U8)len;
            } else {
                *token |= (U8)match_len;
            }

            anchor = ip;
            if (ip >= mflimit) break;

            // Fill hash table for current positions
            s_lz4_hash_table[lz4_hash4(ip - 2)] = ip - 2;
        } else {
            ip++;
        }
    }

_last_literals:
    {
        I64 last_lit = iend - anchor;
        if (op + last_lit + (1 + (last_lit / 255)) > oend) return 0;

        if (last_lit >= 15) {
            *op++ = (15 << 4);
            I64 len = last_lit - 15;
            while (len >= 255) {
                *op++ = 255;
                len -= 255;
            }
            *op++ = (U8)len;
        } else {
            *op++ = (U8)(last_lit << 4);
        }

        MemCpy(op, anchor, last_lit);
        op += last_lit;
    }

    return (I64)(op - dst);
}

I64 lz4_decompress(const U8* src, I64 src_size, U8* dst, I64 dst_capacity) {
    if (!src || !dst || src_size <= 0 || dst_capacity <= 0) return 0;

    const U8* ip = src;
    const U8* const iend = src + src_size;

    U8* op = dst;
    U8* const oend = dst + dst_capacity;

    while (ip < iend) {
        U8 token = *ip++;

        // 1. Literal length
        I64 lit_len = token >> 4;
        if (lit_len == 15) {
            U8 s;
            do {
                if (ip >= iend) return 0;
                s = *ip++;
                lit_len += s;
            } while (s == 255);
        }

        if (op + lit_len > oend || ip + lit_len > iend) return 0;
        MemCpy(op, ip, lit_len);
        op += lit_len;
        ip += lit_len;

        if (ip >= iend) break;

        // 2. Match offset (16-bit)
        if (ip + 2 > iend) return 0;
        U16 offset = ld16(ip);
        ip += 2;

        if (offset == 0) return 0;
        const U8* match = op - offset;
        if (match < dst) return 0;

        // 3. Match length
        I64 match_len = token & 0x0F;
        if (match_len == 15) {
            U8 s;
            do {
                if (ip >= iend) return 0;
                s = *ip++;
                match_len += s;
            } while (s == 255);
        }
        match_len += LZ4_MIN_MATCH;

        if (op + match_len > oend) return 0;

        // Copy match (handling overlap correctly)
        for (I64 i = 0; i < match_len; i++) {
            *op++ = *match++;
        }
    }

    return (I64)(op - dst);
}

// ================= [ BENCHMARK & DEMO ] =================

