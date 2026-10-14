#ifndef YESOS_CRYPTO_H
#define YESOS_CRYPTO_H

#include "types.h"

// ============================================================================
// YesOS 2.0 - Cryptographic primitives (implemented in rust_core/src/crypto.rs
// on top of the audited RustCrypto crates) and the kernel entropy pool.
// ============================================================================

#define YC_OK               0
#define YC_ERR_PARAM       -1
#define YC_ERR_AUTH        -2
#define YC_ERR_BUSY        -3
#define YC_ERR_KDF         -4
#define YC_ERR_NO_ENTROPY  -5

#define YC_KEY_LEN    32
#define YC_NONCE_LEN  24   // XChaCha20-Poly1305 extended nonce
#define YC_TAG_LEN    16
#define YC_SALT_LEN   16

// Argon2id cost parameters compiled into rust_core (recorded in on-disk headers).
#define YC_ARGON2_M_KIB  (8 * 1024)
#define YC_ARGON2_T_COST 3
#define YC_ARGON2_P_COST 1

// --- Rust FFI ---------------------------------------------------------------
U0  yc_rng_mix(const U8* material, size_t len, U32 entropy_bits);
U32 yc_rng_entropy_bits(U0);
I32 yc_rng_fill(U8* out, size_t len);

I32 yc_argon2id(const U8* pw, size_t pw_len, const U8* salt, size_t salt_len,
                U8* out, size_t out_len);

I32 yc_argon2id_with_memory(const U8* pw, size_t pw_len, const U8* salt, size_t salt_len,
                            U8* out, size_t out_len, U8* mem, size_t mem_len);

I32 yc_aead_seal(const U8* key, const U8* nonce, const U8* aad, size_t aad_len,
                 U8* buf, size_t len, U8* tag_out);
I32 yc_aead_open(const U8* key, const U8* nonce, const U8* aad, size_t aad_len,
                 U8* buf, size_t len, const U8* tag);

I32 yc_blake2b256_2(const U8* a, size_t a_len, const U8* b, size_t b_len, U8* out32);
I32 yc_blake2b256_mac(const U8* key32, U64 index, const U8* data, size_t len, U8* out32);

I32 yc_ct_eq(const U8* a, const U8* b, size_t len);
U0  yc_wipe(U8* p, size_t len);

// --- Noise_NK_25519_ChaChaPoly_BLAKE2s responder (rust_core/src/noise.rs) ---
#define YC_ERR_REPLAY      -6
#define YC_ERR_NO_SESSION  -7
#define YC_ERR_NO_KEY      -8
#define YC_NOISE_MAX_SESSIONS 8

I32 yc_noise_set_static_key(const U8* private_key);
I32 yc_noise_public_key(U8* out32);
I32 yc_noise_accept(const U8* msg, size_t msg_len, U8* out, size_t out_cap, size_t* out_len,
                    U32* slot_out, U64* id_out, U64 now_ms);
I32 yc_noise_decrypt(U64 id, U64 nonce, const U8* ct, size_t ct_len, U8* out, size_t out_cap,
                     size_t* out_len, U32* slot_out, U64 now_ms);
I32 yc_noise_encrypt(U64 id, U64 nonce, const U8* pt, size_t pt_len, U8* out, size_t out_cap,
                     size_t* out_len);
U0  yc_noise_close(U32 slot);

// --- Kernel entropy pool (kernel/entropy.c) ---------------------------------
// Seeds the DRBG from the Zkr `seed` CSR (probed at runtime),
// timer jitter and the persisted SYS/RNG.SEED file. Must run after the
// RedSea volume is mounted and before any subsystem generates keys or salts.
U0   entropy_init(U0);
Bool entropy_is_strong(U0);     // TRUE when a hardware entropy source was used
Bool entropy_random(U8* out, size_t len);

#endif // YESOS_CRYPTO_H
