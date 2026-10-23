// Console command of the optional core module "math" (yesmath).
//   math         which versions are in use (vector if the hart has V)
//   math test    runs the self-check (ym_selftest.c): one line per function
//                with the hash of its outputs;
//                each vector result must equal the scalar one.
// tools/test_math.py compares the hashes with the host build's.
#include "kprintf.h"
#include "memory.h"
#include "shell.h"
#include "ym_internal.h"

typedef void (*YmReport)(const char* name, int rvv, ym_u64 hash);
void ym_selftest(YmReport rep);
U0 ym_shell_register(U0);

static struct { const char* name; ym_u64 hash; } g_scalar[24];
static U32 g_nscalar, g_compared, g_mismatch;

static U0 ym_report(const char* name, int rvv, ym_u64 hash) {
    kprintf("  %s", name);
    for (U32 n = (U32)StrLen(name); n < 12; n++) kprintf(" ");
    kprintf("%s  %016x", rvv ? "rvv   " : "scalar", hash);
    if (!rvv) {
        if (g_nscalar < 24) { g_scalar[g_nscalar].name = name; g_scalar[g_nscalar].hash = hash; g_nscalar++; }
        kprintf("\n");
        return;
    }
    for (U32 i = 0; i < g_nscalar; i++) {
        if (StrCmp(g_scalar[i].name, name) != 0) continue;
        Bool same = g_scalar[i].hash == hash;
        g_compared++;
        if (!same) g_mismatch++;
        kprintf("  %s\n", same ? "[MATCH]" : "[MISMATCH]");
        return;
    }
    g_mismatch++;
    kprintf("  [NO SCALAR RESULT]\n");
}

static U0 ym_status(U0) {
    if (ym_has_rvv()) {
        U64 vlenb;
        __asm__ __volatile__("csrr %0, vlenb" : "=r"(vlenb));
        kprintf("yesmath: vector versions in use (RVV 1.0, VLEN %u bits)\n", vlenb * 8);
    } else {
        kprintf("yesmath: scalar versions in use (this hart has no V extension)\n");
    }
}

static Bool ym_shell_run(const char* cmd) {
    if (StrCmp(cmd, "math") == 0) {
        ym_status();
    } else if (StrCmp(cmd, "math test") == 0) {
        ym_status();
        g_nscalar = g_compared = g_mismatch = 0;
        ym_selftest(ym_report);
        if (g_mismatch)
            kprintf("[RESULT] yesmath self-check FAILED: %u vector result(s) differ from the scalar ones\n", (U64)g_mismatch);
        else if (g_compared)
            kprintf("[RESULT] yesmath self-check OK: %u vector results identical to the scalar ones\n", (U64)g_compared);
        else
            kprintf("[RESULT] yesmath self-check OK: scalar versions only\n");
    } else if (StrNCmp(cmd, "math ", 5) == 0) {
        kprintf("Usage: math [test]\n");
    } else {
        return FALSE;
    }
    return TRUE;
}

static U0 ym_shell_help(U0) {
    kprintf("  Math (yesmath)\n");
    kprintf("    math [test]   versions in use; self-check scalar vs vector\n");
}

U0 ym_shell_register(U0) {
    static const ShellExtension ext = { ym_shell_run, ym_shell_help, NULL, NULL };
    shell_register(&ext);
}
