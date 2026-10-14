#include "vault.h"
#include "yesos_crypto.h"
#include "redsea_eml.h"
#include "memory.h"
#include "kprintf.h"
#include "timer.h"
#include "keyhart.h"

#define VAULT_HDR_FILE      "SYS/VAULT.HDR"
#define VAULT_FILE_MAGIC    0x31465659u  // "YVF1"
#define VAULT_MAX_FAILED    5
#define VAULT_LOCKOUT_MS    30000

typedef struct {
    U32 magic;
    U8  nonce[YC_NONCE_LEN];
    U8  tag[YC_TAG_LEN];
} __attribute__((packed)) VaultFileHeader;

static VaultHeader g_hdr;
static Bool        g_initialized = FALSE;
static Bool        g_unlocked = FALSE;   // mirrors the key hart; the DEK itself never lives here
static U32         g_failed = 0;
static U64         g_lockout_until_ms = 0;

const char* vault_result_str(VaultResult r) {
    switch (r) {
        case VAULT_OK:                      return "OK";
        case VAULT_ERR_NOT_INITIALIZED:     return "vault not initialized (run: vault init)";
        case VAULT_ERR_ALREADY_INITIALIZED: return "vault already initialized";
        case VAULT_ERR_LOCKED:              return "vault is locked (run: vault unlock)";
        case VAULT_ERR_BAD_PASSPHRASE:      return "wrong passphrase";
        case VAULT_ERR_WEAK_PASSPHRASE:     return "passphrase must be 8-128 characters";
        case VAULT_ERR_LOCKOUT:             return "too many failed attempts, try again later";
        case VAULT_ERR_CORRUPT:             return "data failed authentication (corrupt or tampered)";
        case VAULT_ERR_NO_ENTROPY:          return "entropy pool not seeded";
        case VAULT_ERR_IO:                  return "disk I/O error";
        case VAULT_ERR_NO_MEMORY:           return "out of memory";
    }
    return "unknown error";
}

static Bool hdr_params_supported(const VaultHeader* h) {
    return h->magic == VAULT_HDR_MAGIC && h->version == VAULT_HDR_VERSION &&
           h->argon_m_kib == YC_ARGON2_M_KIB && h->argon_t_cost == YC_ARGON2_T_COST &&
           h->argon_p_cost == YC_ARGON2_P_COST;
}

U0 vault_init(U0) {
    MemSet(&g_hdr, 0, sizeof(g_hdr));
    g_initialized = FALSE;
    g_unlocked = FALSE;

    size_t sz = 0;
    U8* data = redsea_eml_read_file(VAULT_HDR_FILE, &sz);
    if (data) {
        if (sz == sizeof(VaultHeader)) {
            MemCpy(&g_hdr, data, sizeof(VaultHeader));
            if (hdr_params_supported(&g_hdr)) {
                g_initialized = TRUE;
            } else {
                kprintf("[VAULT] %s has unsupported format/parameters; vault unavailable.\n", VAULT_HDR_FILE);
            }
        } else {
            kprintf("[VAULT] %s has unexpected size; vault unavailable.\n", VAULT_HDR_FILE);
        }
        Free(data);
    }

    kprintf("[VAULT] Encrypted /vault: %s (XChaCha20-Poly1305, Argon2id %u MiB/t=%u).\n",
            g_initialized ? "initialized, LOCKED" : "not initialized (run: vault init)",
            YC_ARGON2_M_KIB / 1024, YC_ARGON2_T_COST);
}

Bool vault_is_initialized(U0) { return g_initialized; }
Bool vault_is_unlocked(U0)    { return g_unlocked; }

U32 vault_lockout_remaining_sec(U0) {
    U64 now = timer_get_uptime_ms();
    if (now >= g_lockout_until_ms) return 0;
    return (U32)((g_lockout_until_ms - now) / 1000) + 1;
}

static Bool passphrase_ok(const char* p) {
    if (!p) return FALSE;
    size_t n = StrLen(p);
    return n >= VAULT_MIN_PASSPHRASE && n <= VAULT_MAX_PASSPHRASE;
}

static VaultResult from_kh(KeyhartStatus st) {
    switch (st) {
        case KH_OK:              return VAULT_OK;
        case KH_ERR_AUTH:        return VAULT_ERR_BAD_PASSPHRASE;
        case KH_ERR_LOCKED:      return VAULT_ERR_LOCKED;
        case KH_ERR_ENTROPY:     return VAULT_ERR_NO_ENTROPY;
        case KH_ERR_UNAVAILABLE: return VAULT_ERR_IO;
        default:                 return VAULT_ERR_IO;
    }
}

static U0 note_failure(U0) {
    if (++g_failed >= VAULT_MAX_FAILED) {
        g_failed = 0;
        g_lockout_until_ms = timer_get_uptime_ms() + VAULT_LOCKOUT_MS;
    }
}

VaultResult vault_create(const char* passphrase) {
    if (g_initialized) return VAULT_ERR_ALREADY_INITIALIZED;
    if (!passphrase_ok(passphrase)) return VAULT_ERR_WEAK_PASSPHRASE;
    if (!redsea_eml_is_mounted() || !keyhart_available()) return VAULT_ERR_IO;

    VaultHeader h;
    MemSet(&h, 0, sizeof(h));
    h.magic = VAULT_HDR_MAGIC;
    h.version = VAULT_HDR_VERSION;
    h.argon_m_kib = YC_ARGON2_M_KIB;
    h.argon_t_cost = YC_ARGON2_T_COST;
    h.argon_p_cost = YC_ARGON2_P_COST;
    if (!entropy_random(h.salt, YC_SALT_LEN)) return VAULT_ERR_NO_ENTROPY;

    // The DEK is generated and kept inside the key hart.
    VaultResult r = from_kh(keyhart_create(passphrase, &h));
    if (r != VAULT_OK) return r;
    if (!redsea_eml_write_file_path(VAULT_HDR_FILE, &h, sizeof(VaultHeader), 0)) {
        keyhart_lock();
        return VAULT_ERR_IO;
    }
    MemCpy(&g_hdr, &h, sizeof(h));
    g_initialized = TRUE;
    g_unlocked = TRUE;
    if (!entropy_is_strong()) {
        kprintf("[VAULT] WARNING: vault key generated without a hardware entropy source.\n");
    }
    return VAULT_OK;
}

VaultResult vault_unlock(const char* passphrase) {
    if (g_unlocked) return VAULT_OK;
    if (!g_initialized) return VAULT_ERR_NOT_INITIALIZED;
    if (vault_lockout_remaining_sec() > 0) return VAULT_ERR_LOCKOUT;
    if (!passphrase) return VAULT_ERR_BAD_PASSPHRASE;
    VaultResult r = from_kh(keyhart_unlock(passphrase, &g_hdr));
    if (r == VAULT_OK) {
        g_failed = 0;
        g_unlocked = TRUE;
    } else if (r == VAULT_ERR_BAD_PASSPHRASE) {
        note_failure();
    }
    return r;
}

U0 vault_lock(U0) {
    keyhart_lock();
    g_unlocked = FALSE;
}

VaultResult vault_change_passphrase(const char* old_pass, const char* new_pass) {
    if (!passphrase_ok(new_pass)) return VAULT_ERR_WEAK_PASSPHRASE;
    if (!g_initialized) return VAULT_ERR_NOT_INITIALIZED;
    if (vault_lockout_remaining_sec() > 0) return VAULT_ERR_LOCKOUT;

    VaultHeader h;
    MemCpy(&h, &g_hdr, sizeof(h));
    if (!entropy_random(h.salt, YC_SALT_LEN)) return VAULT_ERR_NO_ENTROPY;
    VaultResult r = from_kh(keyhart_rewrap(old_pass, &g_hdr, new_pass, &h));
    if (r == VAULT_ERR_BAD_PASSPHRASE) note_failure();
    if (r != VAULT_OK) return r;
    if (!redsea_eml_write_file_path(VAULT_HDR_FILE, &h, sizeof(VaultHeader), 0)) return VAULT_ERR_IO;
    MemCpy(&g_hdr, &h, sizeof(h));
    g_failed = 0;
    return VAULT_OK;
}

Bool vault_path_is_protected(const char* p) {
    if (!p) return FALSE;
    while (*p == '/') p++;
    if (StrNICmp(p, "vault", 5) != 0) return FALSE;
    return p[5] == '\0' || p[5] == '/';
}

// AAD binds each ciphertext to its location, so files cannot be swapped or
// renamed inside the vault without detection. Case-folded because RedSea
// lookups are case-insensitive.
static size_t build_aad(const char* canon, U8* aad, size_t cap) {
    U32 magic = VAULT_FILE_MAGIC;
    MemCpy(aad, &magic, 4);
    size_t n = 4;
    while (*canon == '/') canon++;
    for (; *canon && n < cap; canon++) {
        char c = *canon;
        if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
        aad[n++] = (U8)c;
    }
    return n;
}

U8* vault_read(const char* canon, size_t* out_size, VaultResult* out_err) {
    VaultResult dummy;
    if (!out_err) out_err = &dummy;
    if (!g_initialized) { *out_err = VAULT_ERR_NOT_INITIALIZED; return NULL; }
    if (!g_unlocked)    { *out_err = VAULT_ERR_LOCKED; return NULL; }

    const char* clean = canon;
    while (*clean == '/') clean++;

    size_t sz = 0;
    U8* blob = redsea_eml_read_file(clean, &sz);
    if (!blob) { *out_err = VAULT_ERR_IO; return NULL; }
    if (sz < sizeof(VaultFileHeader)) {
        Free(blob);
        *out_err = VAULT_ERR_CORRUPT;
        return NULL;
    }

    VaultFileHeader fh;
    MemCpy(&fh, blob, sizeof(fh));
    if (fh.magic != VAULT_FILE_MAGIC) {
        Free(blob);
        *out_err = VAULT_ERR_CORRUPT;
        return NULL;
    }

    size_t pt_len = sz - sizeof(VaultFileHeader);
    U8 aad[4 + REDSEA_MAX_FILENAME];
    size_t aad_len = build_aad(canon, aad, sizeof(aad));

    U8* pt = blob + sizeof(VaultFileHeader);
    if (keyhart_open(fh.nonce, aad, aad_len, pt, pt_len, fh.tag) != KH_OK) {
        Free(blob);
        *out_err = VAULT_ERR_CORRUPT;
        return NULL;
    }

    U8* out = (U8*)Malloc(pt_len + 1);
    if (!out) {
        yc_wipe(blob, sz);
        Free(blob);
        *out_err = VAULT_ERR_NO_MEMORY;
        return NULL;
    }
    MemCpy(out, pt, pt_len);
    out[pt_len] = '\0';
    yc_wipe(blob, sz);
    Free(blob);

    if (out_size) *out_size = pt_len;
    *out_err = VAULT_OK;
    return out;
}

VaultResult vault_write(const char* canon, const void* data, size_t size) {
    if (!g_initialized) return VAULT_ERR_NOT_INITIALIZED;
    if (!g_unlocked)    return VAULT_ERR_LOCKED;
    if (!data && size) return VAULT_ERR_IO;

    size_t total = sizeof(VaultFileHeader) + size;
    U8* blob = (U8*)Malloc(total);
    if (!blob) return VAULT_ERR_NO_MEMORY;

    VaultFileHeader fh;
    fh.magic = VAULT_FILE_MAGIC;
    if (!entropy_random(fh.nonce, YC_NONCE_LEN)) {
        Free(blob);
        return VAULT_ERR_NO_ENTROPY;
    }

    U8* ct = blob + sizeof(VaultFileHeader);
    if (size) MemCpy(ct, data, size);

    U8 aad[4 + REDSEA_MAX_FILENAME];
    size_t aad_len = build_aad(canon, aad, sizeof(aad));
    if (keyhart_seal(fh.nonce, aad, aad_len, ct, size, fh.tag) != KH_OK) {
        yc_wipe(blob, total);
        Free(blob);
        return VAULT_ERR_IO;
    }
    MemCpy(blob, &fh, sizeof(fh));

    const char* clean = canon;
    while (*clean == '/') clean++;
    Bool ok = redsea_eml_write_file_path(clean, blob, total, REDSEA_FLAG_ENCRYPTED);
    Free(blob);
    return ok ? VAULT_OK : VAULT_ERR_IO;
}

U0 vault_print_status(U0) {
    kprintf("\n==================== [ YESOS ENCRYPTED VAULT ] ====================\n");
    kprintf("  State        : %s\n",
            !g_initialized ? "NOT INITIALIZED" : (g_unlocked ? "UNLOCKED (key in RAM)" : "LOCKED"));
    kprintf("  Cipher       : XChaCha20-Poly1305 (per-file random 192-bit nonce)\n");
    kprintf("  KDF          : Argon2id m=%u MiB t=%u p=%u, 128-bit random salt\n",
            YC_ARGON2_M_KIB / 1024, YC_ARGON2_T_COST, YC_ARGON2_P_COST);
    kprintf("  Header       : %s\n", VAULT_HDR_FILE);
    kprintf("  Entropy      : %s\n", entropy_is_strong() ? "hardware (Zkr)" : "timing jitter + persisted seed (WEAK)");
    kprintf("  Key custody  : %s\n", keyhart_available()
            ? "key hart (DEK in PMP-private memory, unreachable from other harts)" : "KEY HART UNAVAILABLE");
    if (vault_lockout_remaining_sec() > 0) {
        kprintf("  Lockout      : %u s remaining\n", vault_lockout_remaining_sec());
    }
    kprintf("===================================================================\n");
}

// ---------------------------------------------------------------------------
// Replication (kernel/webadmin.c): the header holds the data key wrapped
// with Argon2id(passphrase); exporting it is as safe as the passphrase.
// ---------------------------------------------------------------------------
U8* vault_export_header(size_t* out_size) {
    if (!g_initialized) return NULL;
    return redsea_eml_read_file(VAULT_HDR_FILE, out_size);
}

// Installs a header from a backup, only on a NAS that has no vault yet.
VaultResult vault_import_header(const U8* data, size_t size) {
    if (g_initialized) return VAULT_ERR_ALREADY_INITIALIZED;
    if (!data || size != sizeof(VaultHeader)) return VAULT_ERR_CORRUPT;
    VaultHeader h;
    MemCpy(&h, data, sizeof(h));
    if (!hdr_params_supported(&h)) return VAULT_ERR_CORRUPT;
    if (!redsea_eml_write_file_path(VAULT_HDR_FILE, data, size, 0)) return VAULT_ERR_IO;
    vault_init();
    return g_initialized ? VAULT_OK : VAULT_ERR_CORRUPT;
}

// Restored vault files must carry the vault file format (YVF1 header).
Bool vault_blob_plausible(const U8* data, size_t size) {
    if (!data || size < sizeof(VaultFileHeader)) return FALSE;
    U32 magic;
    MemCpy(&magic, data, sizeof(magic));
    return magic == VAULT_FILE_MAGIC;
}
