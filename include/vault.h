#ifndef VAULT_H
#define VAULT_H

#include "types.h"

// ============================================================================
// YesOS 2.0 - Encrypted /vault
//
// Every file stored under /vault is encrypted individually with
// XChaCha20-Poly1305 under a random 256-bit data key (DEK). The DEK is
// wrapped by a key derived from the vault passphrase with Argon2id and kept
// in SYS/VAULT.HDR. Plaintext never reaches the disk, and the DEK only lives
// in RAM while the vault is unlocked.
// ============================================================================

#define VAULT_MIN_PASSPHRASE 8
#define VAULT_MAX_PASSPHRASE 128

typedef enum {
    VAULT_OK = 0,
    VAULT_ERR_NOT_INITIALIZED,
    VAULT_ERR_ALREADY_INITIALIZED,
    VAULT_ERR_LOCKED,
    VAULT_ERR_BAD_PASSPHRASE,
    VAULT_ERR_WEAK_PASSPHRASE,
    VAULT_ERR_LOCKOUT,
    VAULT_ERR_CORRUPT,
    VAULT_ERR_NO_ENTROPY,
    VAULT_ERR_IO,
    VAULT_ERR_NO_MEMORY,
} VaultResult;

U0          vault_init(U0);
Bool        vault_is_initialized(U0);
Bool        vault_is_unlocked(U0);
U32         vault_lockout_remaining_sec(U0);
const char* vault_result_str(VaultResult r);

VaultResult vault_create(const char* passphrase);
VaultResult vault_unlock(const char* passphrase);
U0          vault_lock(U0);
VaultResult vault_change_passphrase(const char* old_pass, const char* new_pass);

// TRUE for "/vault" and anything below it (canonical, case-insensitive).
Bool        vault_path_is_protected(const char* canon_path);

// Encrypted file I/O. `canon_path` is the canonical VFS path ("/vault/...").
// vault_read returns a Malloc'd, NUL-terminated plaintext buffer.
U8*         vault_read(const char* canon_path, size_t* out_size, VaultResult* out_err);
VaultResult vault_write(const char* canon_path, const void* data, size_t size);

U0          vault_print_status(U0);

// Replication: header export/import (import only when no vault exists yet)
U8*         vault_export_header(size_t* out_size);
VaultResult vault_import_header(const U8* data, size_t size);
Bool        vault_blob_plausible(const U8* data, size_t size);

U0 vault_shell_register(U0);   // console commands (module "vault")

#endif // VAULT_H
