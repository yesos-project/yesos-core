#ifndef CHACHA20_H
#define CHACHA20_H

// ChaCha20 keystream and Poly1305 (RFC 8439), optional core module "chacha".
// ChaCha20: a scalar version and an RVV 1.0 one (several blocks at once, one
// per vector lane), chosen at boot from misa; both give the same bytes.
// Poly1305: scalar, 64-bit limbs (kernel/poly1305.c), constant time. The
// AEAD's tag comparison is the caller's (in constant time).
// Never call it on the key hart (tools/check_keyhart_vector.py proves it).

#include "types.h"

U0   cc20_init(U0);                 // vector version if this hart has V
Bool cc20_has_rvv(U0);              // 1 if the vector version is in use
U0   cc20_use_rvv(Bool on);         // tests: force one or the other

// data[i] ^= keystream byte i, the keystream starting at block `counter` of
// (key, nonce). The 32-bit block counter wraps around (RFC 8439 leaves 2^32
// blocks undefined; a TLS record is far below). Any alignment and length.
U0 cc20_xor(const U8 key[32], const U8 nonce[12], U32 counter, U8* data, size_t len);

// The Poly1305 tag of msg under a one-time key (RFC 8439 2.5).
U0 cc20_poly1305(const U8 key[32], const U8* msg, size_t len, U8 tag[16]);
// The ChaCha20-Poly1305 tag (RFC 8439 2.8): Poly1305 under otk (block 0 of
// the keystream) over aad and ct, each zero-padded to 16 bytes, then both
// lengths as 64-bit little-endian numbers.
U0 cc20_poly1305_aead(const U8 otk[32], const U8* aad, size_t aad_len, const U8* ct, size_t ct_len, U8 tag[16]);

#endif // CHACHA20_H
