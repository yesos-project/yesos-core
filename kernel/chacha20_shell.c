// Console command of the optional core module "chacha".
//   chacha        which version is in use
//   chacha test   the self-check (chacha20_selftest.c), scalar then vector:
//                 one hash per length; the vector ones must equal the scalar
//                 ones (tools/test_chacha.py also compares them with the host)
#include "chacha20.h"
#include "kprintf.h"
#include "memory.h"
#include "shell.h"

typedef U0 (*Cc20Report)(const char* what, U64 len, U64 hash);
U0 cc20_selftest(Cc20Report rep);
U0 cc20_shell_register(U0);

#define MAX_LINES 24
static U64 g_scalar[MAX_LINES];
static U32 g_line, g_pass, g_mismatch;

static U0 report(const char* what, U64 len, U64 hash) {
    kprintf("  %s %u %s %016x", what, len, g_pass ? "rvv   " : "scalar", hash);   // poly: scalar in both passes
    if (g_line < MAX_LINES) {
        if (!g_pass) g_scalar[g_line] = hash;
        else if (g_scalar[g_line] != hash) g_mismatch++;
        if (g_pass) kprintf("  %s", g_scalar[g_line] == hash ? "[MATCH]" : "[MISMATCH]");
    }
    kprintf("\n");
    g_line++;
}

static U0 status(U0) {
    kprintf("chacha: %s version in use\n", cc20_has_rvv() ? "vector (RVV 1.0)" : "scalar");
}

static Bool chacha_run(const char* cmd) {
    if (StrCmp(cmd, "chacha") == 0) {
        status();
    } else if (StrCmp(cmd, "chacha test") == 0) {
        Bool was = cc20_has_rvv();
        g_mismatch = 0;
        g_pass = 0;
        g_line = 0;
        cc20_use_rvv(FALSE);
        cc20_selftest(report);
        if (was) {
            g_pass = 1;
            g_line = 0;
            cc20_use_rvv(TRUE);
            cc20_selftest(report);
        }
        cc20_use_rvv(was);
        if (g_mismatch) kprintf("[RESULT] chacha self-check FAILED: %u vector result(s) differ\n", (U64)g_mismatch);
        else kprintf("[RESULT] chacha self-check OK: %s\n", was ? "vector results identical to the scalar ones" : "scalar only");
    } else if (StrNCmp(cmd, "chacha ", 7) == 0) {
        kprintf("Usage: chacha [test]\n");
    } else {
        return FALSE;
    }
    return TRUE;
}

static U0 chacha_help(U0) {
    kprintf("  ChaCha20\n");
    kprintf("    chacha [test]   version in use; self-check scalar vs vector\n");
}

U0 cc20_shell_register(U0) {
    static const ShellExtension ext = { chacha_run, chacha_help, NULL, NULL };
    shell_register(&ext);
}
