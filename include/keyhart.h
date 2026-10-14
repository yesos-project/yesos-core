#ifndef KEYHART_H
#define KEYHART_H

#include "types.h"
#include "yesos_crypto.h"

/*
 * YesOS 2.0 - Key hart: an HSM-like core for the vault data key (DEK).
 *
 * Hart KEYHART_ID locks a PMP layout that grants it a private "key vault"
 * region (.keyvault: DEK, Argon2 working memory, its stack). Every other
 * hart's locked layout denies that region, so the DEK cannot be read even by
 * Machine-mode code on hart 0. Hart 0 asks the key hart to wrap, unwrap,
 * seal and open through a mailbox; it never receives the key.
 *
 * Limits (by design of this step): a compromised hart 0 can still request
 * operations while the vault is unlocked (it cannot extract the key), and
 * the key lives in RAM (a later step keeps it in registers only).
 */

#define KEYHART_ID 2

// On-disk vault header (SYS/VAULT.HDR)
#define VAULT_HDR_MAGIC     0x544C5659u  // "YVLT"
#define VAULT_HDR_VERSION   1u

typedef struct {
    U32 magic;
    U32 version;
    U32 argon_m_kib;
    U32 argon_t_cost;
    U32 argon_p_cost;
    U8  salt[YC_SALT_LEN];
    // Everything above is authenticated as AAD of the key wrap below.
    U8  wrap_nonce[YC_NONCE_LEN];
    U8  wrapped_dek[YC_KEY_LEN];
    U8  wrap_tag[YC_TAG_LEN];
} __attribute__((packed)) VaultHeader;

#define VAULT_HDR_AAD_LEN ((size_t)&((VaultHeader*)0)->wrap_nonce)

typedef enum {
    KH_OK = 0,
    KH_ERR_UNAVAILABLE,     // key hart not running / not verified
    KH_ERR_AUTH,            // wrong passphrase or tampered data
    KH_ERR_LOCKED,          // no DEK loaded
    KH_ERR_PARAM,           // buffer outside the allowed regions, bad length
    KH_ERR_ENTROPY,
    KH_ERR_TIMEOUT,
} KeyhartStatus;

// Hart 0 side
Bool          keyhart_available(U0);
Bool          keyhart_is_unlocked(U0);
// Generates a new DEK inside the key hart and wraps it with `pass`.
// `hdr` must carry magic/version/params/salt; wrap fields are filled in.
KeyhartStatus keyhart_create(const char* pass, VaultHeader* hdr);
KeyhartStatus keyhart_unlock(const char* pass, const VaultHeader* hdr);
KeyhartStatus keyhart_lock(U0);
// Re-wraps the DEK of `old_hdr` (opened with old_pass) under new_pass and
// new_hdr->salt; fills new_hdr's wrap fields. The loaded DEK is unchanged.
KeyhartStatus keyhart_rewrap(const char* old_pass, const VaultHeader* old_hdr,
                             const char* new_pass, VaultHeader* new_hdr);
// AEAD with the loaded DEK, in place on hart-0 buffers.
KeyhartStatus keyhart_seal(const U8* nonce, const U8* aad, size_t aad_len, U8* buf, size_t len, U8* tag);
KeyhartStatus keyhart_open(const U8* nonce, const U8* aad, size_t aad_len, U8* buf, size_t len, const U8* tag);

// Boot
Bool          keyhart_prepare_layout(U0);            // hart 0, from pmp_init context
U0            keyhart_enter(U32 hart_id) __attribute__((noreturn));   // hart 2
U0            keyhart_verify_booted(U0);             // hart 0, after smp_init
Bool          keyhart_self_test(U0);

#endif // KEYHART_H
