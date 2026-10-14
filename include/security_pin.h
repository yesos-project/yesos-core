#ifndef SECURITY_PIN_H
#define SECURITY_PIN_H

#include "types.h"

#define PIN_MAX_LEN           6
#define PIN_MAX_FAILED        5
#define PIN_LOCKOUT_MS        30000

typedef struct {
    Bool is_locked;
    Bool pin_set;              // FALSE until a PIN is configured (no default PIN)
    U8   pin_salt[16];
    U8   pin_hash[32];         // Argon2id(PIN, salt)
    U32  failed_attempts;
    U64  last_failed_tick;
    Bool is_in_lockout;
    U64  lockout_end_tick;
} SecurityPinState;

U0                security_pin_init(U0);
SecurityPinState* security_pin_get_state(U0);
Bool              security_pin_is_locked(U0);
Bool              security_pin_is_set(U0);
U0                security_pin_lock(U0);
Bool              security_pin_unlock(const char* pin);
Bool              security_pin_change(const char* old_pin, const char* new_pin);
Bool              security_pin_is_in_lockout(U0);
U32               security_pin_get_remaining_lockout_sec(U0);

#endif // SECURITY_PIN_H
