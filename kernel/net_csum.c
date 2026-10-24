// The Internet checksum (RFC 1071): one's-complement sum of big-endian
// 16-bit words. The bulk is summed as aligned 64-bit words (two 32-bit
// halves added into a 64-bit accumulator, folded at the end) instead of byte
// pairs; the one's-complement sum does not depend on byte order, so the
// native little-endian sum is byte-swapped once at the end, and the words'
// sum once more if they start at an odd position. No unaligned access.
// tools/test_memops.py checks it on the host against RFC 1071 done in Python.
#include "virtio_net.h"

typedef U64 __attribute__((may_alias)) Word;

static inline U64 fold16(U64 s) {
    s = (s & 0xFFFFFFFFULL) + (s >> 32);
    s = (s & 0xFFFFFFFFULL) + (s >> 32);
    s = (s & 0xFFFF) + (s >> 16);
    s = (s & 0xFFFF) + (s >> 16);
    return (s & 0xFFFF) + (s >> 16);
}

static inline U64 swap16(U64 v) { return ((v & 0xFF) << 8) | (v >> 8); }

U32 net_csum_add(const void* data, size_t len, U32 sum) {
    const U8* p = (const U8*)data;
    U64 acc = 0;                                    // little-endian pairs (p[2k] | p[2k+1] << 8)
    size_t i = 0;
    while (i < len && ((U64)(p + i) & 7)) { acc += (U64)p[i] << ((i & 1) * 8); i++; }
    size_t nw = (len - i) / 8;
    if (nw) {
        const Word* w = (const Word*)(p + i);
        U64 mid = 0;
        for (size_t k = 0; k < nw; k++) mid += (w[k] & 0xFFFFFFFFULL) + (w[k] >> 32);
        mid = fold16(mid);
        acc += (i & 1) ? swap16(mid) : mid;         // words starting at an odd byte: lanes swapped
        i += nw * 8;
    }
    for (; i < len; i++) acc += (U64)p[i] << ((i & 1) * 8);
    return sum + (U32)swap16(fold16(acc));
}

U16 net_csum_fold(U32 sum) {
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (U16)~sum;
}
