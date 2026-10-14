// ============================================================================
// YesOS core (optional module "vault") - console commands of the vault and
// the hidden passphrase prompt, registered as a shell extension.
// ============================================================================

#include "vault.h"
#include "shell.h"
#include "yesos_crypto.h"
#include "kprintf.h"
#include "memory.h"
#include "speaker.h"

// ----------------------------------------------------------------------------
// Secret input (vault passphrases)
// ----------------------------------------------------------------------------

typedef enum { SECRET_NONE = 0, SECRET_VAULT_INIT, SECRET_VAULT_UNLOCK, SECRET_VAULT_PASSWD } SecretOp;

static SecretOp g_secret_op = SECRET_NONE;
static U32      g_secret_stage = 0;
static char     g_secret_buf[2][VAULT_MAX_PASSPHRASE + 1];

static const char* const g_secret_labels[][3] = {
    [SECRET_NONE]         = { "", "", "" },
    [SECRET_VAULT_INIT]   = { "New vault passphrase", "Repeat passphrase", "" },
    [SECRET_VAULT_UNLOCK] = { "Vault passphrase", "", "" },
    [SECRET_VAULT_PASSWD] = { "Current passphrase", "New passphrase", "Repeat new passphrase" },
};

static Bool vault_prompt_active(U0) {
    return g_secret_op != SECRET_NONE;
}

static const char* vault_prompt_label(U0) {
    return g_secret_labels[g_secret_op][g_secret_stage];
}

static U0 secret_reset(U0) {
    yc_wipe((U8*)g_secret_buf, sizeof(g_secret_buf));
    g_secret_op = SECRET_NONE;
    g_secret_stage = 0;
}

static U0 secret_begin(SecretOp op) {
    secret_reset();
    g_secret_op = op;
    kprintf("%s (empty line cancels): ", vault_prompt_label());
}

static U0 secret_report(VaultResult r, const char* ok_msg) {
    if (r == VAULT_OK) {
        kprintf("[VAULT] %s\n", ok_msg);
        speaker_event(BEEP_SUCCESS);
    } else {
        kprintf("[VAULT] Error: %s\n", vault_result_str(r));
        speaker_event(BEEP_WARN);
    }
}

static U0 secret_submit(const char* line) {
    if (*line == '\0') {
        kprintf("[VAULT] Cancelled.\n");
        secret_reset();
        return;
    }
    if (StrLen(line) > VAULT_MAX_PASSPHRASE) {
        kprintf("[VAULT] Error: passphrase too long.\n");
        secret_reset();
        return;
    }

    SecretOp op = g_secret_op;
    U32 stage = g_secret_stage;
    U32 last_stage = (op == SECRET_VAULT_INIT) ? 1 : (op == SECRET_VAULT_PASSWD ? 2 : 0);

    if (stage < last_stage) {
        StrNCpy(g_secret_buf[stage], line, VAULT_MAX_PASSPHRASE);
        g_secret_stage++;
        kprintf("%s: ", vault_prompt_label());
        return;
    }

    // Final stage: `line` is the confirmation (init/passwd) or the passphrase (unlock).
    const char* new_pass = (op == SECRET_VAULT_PASSWD) ? g_secret_buf[1] : g_secret_buf[0];
    if ((op == SECRET_VAULT_INIT || op == SECRET_VAULT_PASSWD) && StrCmp(new_pass, line) != 0) {
        kprintf("[VAULT] Error: passphrases do not match.\n");
        speaker_event(BEEP_WARN);
        secret_reset();
        return;
    }

    kprintf("[VAULT] Deriving key (Argon2id)...\n");
    switch (op) {
        case SECRET_VAULT_INIT:
            secret_report(vault_create(line), "Vault created and unlocked. Files under /vault are now encrypted.");
            break;
        case SECRET_VAULT_UNLOCK:
            secret_report(vault_unlock(line), "Vault unlocked.");
            break;
        case SECRET_VAULT_PASSWD:
            secret_report(vault_change_passphrase(g_secret_buf[0], line), "Vault passphrase changed.");
            break;
        default:
            break;
    }
    secret_reset();
}

static U0 shell_cmd_vault(const char* sub) {
    while (*sub == ' ') sub++;
    if (*sub == '\0' || StrCmp(sub, "status") == 0) {
        vault_print_status();
        kprintf("  Commands: vault init | unlock | lock | passwd | status\n");
    } else if (StrCmp(sub, "init") == 0) {
        if (vault_is_initialized()) {
            kprintf("[VAULT] Already initialized. Use: vault passwd\n");
        } else {
            if (!entropy_is_strong()) {
                kprintf("[VAULT] WARNING: no hardware entropy source; the vault key will be generated\n");
                kprintf("[VAULT]          from timing jitter + persisted seed.\n");
            }
            secret_begin(SECRET_VAULT_INIT);
        }
    } else if (StrCmp(sub, "unlock") == 0) {
        if (!vault_is_initialized()) {
            kprintf("[VAULT] %s\n", vault_result_str(VAULT_ERR_NOT_INITIALIZED));
        } else if (vault_is_unlocked()) {
            kprintf("[VAULT] Already unlocked.\n");
        } else if (vault_lockout_remaining_sec() > 0) {
            kprintf("[VAULT] Too many failed attempts. Retry in %u s.\n", vault_lockout_remaining_sec());
        } else {
            secret_begin(SECRET_VAULT_UNLOCK);
        }
    } else if (StrCmp(sub, "lock") == 0) {
        vault_lock();
        kprintf("[VAULT] Locked. Data key wiped from RAM.\n");
        speaker_event(BEEP_CONFIRM);
    } else if (StrCmp(sub, "passwd") == 0) {
        if (!vault_is_initialized()) {
            kprintf("[VAULT] %s\n", vault_result_str(VAULT_ERR_NOT_INITIALIZED));
        } else {
            secret_begin(SECRET_VAULT_PASSWD);
        }
    } else {
        kprintf("Usage: vault [status | init | unlock | lock | passwd]\n");
        kprintf("  Passphrases are typed at a hidden prompt, never as arguments.\n");
    }
}


static Bool vault_shell_run(const char* cmd) {
    if (StrCmp(cmd, "vault") != 0 && StrNCmp(cmd, "vault ", 6) != 0) return FALSE;
    shell_cmd_vault(cmd + 5);
    return TRUE;
}

static U0 vault_shell_help(U0) {
    kprintf("  Vault\n");
    kprintf("    vault [status|init|unlock|lock|passwd]   (hidden passphrase prompt)\n");
}

static Bool vault_shell_capture(const char* line) {
    if (!vault_prompt_active()) return FALSE;
    secret_submit(line);
    return TRUE;
}

static const char* vault_shell_prompt(U0) {
    return vault_prompt_active() ? vault_prompt_label() : NULL;
}

U0 vault_shell_register(U0) {
    static const ShellExtension ext = { vault_shell_run, vault_shell_help, vault_shell_capture, vault_shell_prompt };
    shell_register(&ext);
}
