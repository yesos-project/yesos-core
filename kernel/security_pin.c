#include "security_pin.h"
#include "yesos_crypto.h"
#include "vfs.h"
#include "memory.h"
#include "kprintf.h"
#include "timer.h"
#include "speaker.h"

static SecurityPinState g_pin_state;
static const char* PIN_CONFIG_FILE = "SYS/PIN.CFG";

#define PIN_CFG_MAGIC 0x324E5059u // "YPN2"

typedef struct __attribute__((packed)) {
    U32 magic;
    U8  salt[16];
    U8  hash[32];
} PinConfig;

static Bool compute_pin_hash(const char* pin, const U8* salt, U8* out) {
    if (!pin) return FALSE;
    I32 r;
    while ((r = yc_argon2id((const U8*)pin, StrLen(pin), salt, 16, out, 32)) == YC_ERR_BUSY) {
    }
    return r == YC_OK;
}

static Bool pin_matches(const char* pin) {
    if (!g_pin_state.pin_set || !pin) return FALSE;
    U8 test[32];
    Bool ok = compute_pin_hash(pin, g_pin_state.pin_salt, test) &&
              yc_ct_eq(test, g_pin_state.pin_hash, sizeof(test));
    yc_wipe(test, sizeof(test));
    return ok;
}

U0 security_pin_init(U0) {
    MemSet(&g_pin_state, 0, sizeof(SecurityPinState));
    g_pin_state.is_locked = FALSE;

    size_t sz = 0;
    U8* data = vfs_read_file(PIN_CONFIG_FILE, &sz);
    if (data) {
        const PinConfig* cfg = (const PinConfig*)data;
        if (sz == sizeof(PinConfig) && cfg->magic == PIN_CFG_MAGIC) {
            MemCpy(g_pin_state.pin_salt, cfg->salt, 16);
            MemCpy(g_pin_state.pin_hash, cfg->hash, 32);
            g_pin_state.pin_set = TRUE;
        } else {
            kprintf("[SECURITY] Discarding legacy %s (insecure hash format).\n", PIN_CONFIG_FILE);
        }
        yc_wipe(data, sz);
        Free(data);
    }

    if (g_pin_state.pin_set) {
        kprintf("[SECURITY] Physical Master PIN gateway initialized.\n");
    } else {
        kprintf("[SECURITY] No Master PIN configured; console lock disabled until: pin set <6 digits>\n");
    }
}

SecurityPinState* security_pin_get_state(U0) {
    return &g_pin_state;
}

Bool security_pin_is_locked(U0) {
    return g_pin_state.is_locked;
}

Bool security_pin_is_set(U0) {
    return g_pin_state.pin_set;
}

U0 security_pin_lock(U0) {
    if (!g_pin_state.pin_set) {
        kprintf("[SECURITY] Cannot lock console: no Master PIN configured (pin set <6 digits>).\n");
        speaker_event(BEEP_WARN);
        return;
    }
    g_pin_state.is_locked = TRUE;
    speaker_event(BEEP_WARN);
}

Bool security_pin_is_in_lockout(U0) {
    if (!g_pin_state.is_in_lockout) return FALSE;
    U64 now = timer_get_uptime_ms();
    if (now >= g_pin_state.lockout_end_tick) {
        g_pin_state.is_in_lockout = FALSE;
        g_pin_state.failed_attempts = 0;
        return FALSE;
    }
    return TRUE;
}

U32 security_pin_get_remaining_lockout_sec(U0) {
    if (!g_pin_state.is_in_lockout) return 0;
    U64 now = timer_get_uptime_ms();
    if (now >= g_pin_state.lockout_end_tick) return 0;
    return (U32)((g_pin_state.lockout_end_tick - now) / 1000) + 1;
}

Bool security_pin_unlock(const char* pin) {
    if (!pin) return FALSE;

    if (security_pin_is_in_lockout()) {
        U32 rem = security_pin_get_remaining_lockout_sec();
        kprintf("\n[SECURITY] Lockout active: try again in %u s\n", rem);
        speaker_event(BEEP_WARN);
        return FALSE;
    }

    if (pin_matches(pin)) {
        g_pin_state.is_locked = FALSE;
        g_pin_state.failed_attempts = 0;
        g_pin_state.is_in_lockout = FALSE;
        speaker_event(BEEP_SUCCESS);
        kprintf("\n[SECURITY] ✅ Physical Console Unlocked by Master PIN!\n");
        return TRUE;
    }

    // Failed attempt
    g_pin_state.failed_attempts++;

    if (g_pin_state.failed_attempts >= PIN_MAX_FAILED) {
        g_pin_state.is_in_lockout = TRUE;
        g_pin_state.lockout_end_tick = timer_get_uptime_ms() + PIN_LOCKOUT_MS;
        kprintf("\n[SECURITY] 🚨 PENALTY LOCKOUT TRIGGERED (5 Failed PIN Attempts)\n");
    } else {
        U32 rem = PIN_MAX_FAILED - g_pin_state.failed_attempts;
        kprintf("\n[SECURITY] ⚠️ Incorrect Master PIN entered (%u attempts left)\n", rem);
    }

    speaker_event(BEEP_WARN);
    return FALSE;
}

Bool security_pin_change(const char* old_pin, const char* new_pin) {
    if (!new_pin) return FALSE;

    // Check old PIN if provided, or if console is currently locked
    if (g_pin_state.pin_set && (g_pin_state.is_locked || (old_pin && *old_pin))) {
        if (!pin_matches(old_pin)) {
            kprintf("[SECURITY] ❌ Cannot change PIN: Current/Old PIN is incorrect.\n");
            speaker_event(BEEP_WARN);
            return FALSE;
        }
    }

    // Validate new pin length (exactly 6 digits)
    size_t len = StrLen(new_pin);
    if (len != PIN_MAX_LEN) {
        kprintf("[SECURITY] ❌ Error: Master PIN must be exactly 6 numeric digits (0-9).\n");
        speaker_event(BEEP_WARN);
        return FALSE;
    }
    for (size_t i = 0; i < len; i++) {
        if (new_pin[i] < '0' || new_pin[i] > '9') {
            kprintf("[SECURITY] ❌ Error: Master PIN must only contain digits 0-9.\n");
            speaker_event(BEEP_WARN);
            return FALSE;
        }
    }

    PinConfig cfg;
    cfg.magic = PIN_CFG_MAGIC;
    if (!entropy_random(cfg.salt, sizeof(cfg.salt)) || !compute_pin_hash(new_pin, cfg.salt, cfg.hash)) {
        kprintf("[SECURITY] ❌ Error: could not derive PIN hash.\n");
        speaker_event(BEEP_WARN);
        return FALSE;
    }
    MemCpy(g_pin_state.pin_salt, cfg.salt, 16);
    MemCpy(g_pin_state.pin_hash, cfg.hash, 32);
    g_pin_state.pin_set = TRUE;
    vfs_write_file(PIN_CONFIG_FILE, &cfg, sizeof(cfg));
    yc_wipe((U8*)&cfg, sizeof(cfg));
    kprintf("\n[SECURITY] ✅ Master PIN successfully updated.\n");
    kprintf("[SECURITY] 💾 Persisted to %s (RedSea VFS & RamFS).\n", PIN_CONFIG_FILE);
    speaker_event(BEEP_SUCCESS);
    return TRUE;
}
