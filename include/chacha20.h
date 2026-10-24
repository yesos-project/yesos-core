#ifndef CHACHA20_H
#define CHACHA20_H

// ChaCha20 keystream (RFC 8439), optional core module "chacha": a scalar
// version and an RVV 1.0 one (several blocks at once, one per vector lane),
// chosen at boot from misa; both give the same bytes. Only the keystream:
// the AEAD around it (Poly1305, the tag check) is the caller's.
// Never call it on the key hart (tools/check_keyhart_vector.py proves it).

#include "types.h"

U0   cc20_init(U0);                 // vector version if this hart has V
Bool cc20_has_rvv(U0);              // 1 if the vector version is in use
U0   cc20_use_rvv(Bool on);         // tests: force one or the other

// data[i] ^= keystream byte i, the keystream starting at block `counter` of
// (key, nonce). The 32-bit block counter wraps around (RFC 8439 leaves 2^32
// blocks undefined; a TLS record is far below). Any alignment and length.
U0 cc20_xor(const U8 key[32], const U8 nonce[12], U32 counter, U8* data, size_t len);

#endif // CHACHA20_H
