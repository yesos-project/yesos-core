#include "cell.h"
#include "app_registry.h"
#include "ypkg.h"
#include "shell.h"
#include "redsea_eml.h"
#include "ramfs.h"
#include "holyq_jit.h"
#include "kprintf.h"
#include "memory.h"
#include "speaker.h"
#include "vfs.h"

static DynamicApp g_apps[MAX_DYNAMIC_APPS];
static U32        g_app_count = 0;

U0 app_registry_init(U0) {
    MemSet(g_apps, 0, sizeof(g_apps));
    g_app_count = 0;
    app_registry_rescan();
}

Bool app_registry_register(const char* name, const char* bundle_path, const char* exec_entry) {
    if (!name || !bundle_path) return FALSE;

    // Check if already registered
    for (U32 i = 0; i < g_app_count; i++) {
        if (StrCmp(g_apps[i].name, name) == 0) {
            StrNCpy(g_apps[i].bundle_path, bundle_path, sizeof(g_apps[i].bundle_path));
            StrNCpy(g_apps[i].exec_entry, exec_entry ? exec_entry : "MAIN.HQ", sizeof(g_apps[i].exec_entry));
            g_apps[i].is_active = TRUE;
            return TRUE;
        }
    }

    if (g_app_count >= MAX_DYNAMIC_APPS) {
        kprintf("[AppRegistry] Warning: Max dynamic apps (%u) reached.\n", MAX_DYNAMIC_APPS);
        return FALSE;
    }

    DynamicApp* app = &g_apps[g_app_count++];
    MemSet(app, 0, sizeof(DynamicApp));
    StrNCpy(app->name, name, sizeof(app->name));
    StrNCpy(app->bundle_path, bundle_path, sizeof(app->bundle_path));
    StrNCpy(app->exec_entry, exec_entry ? exec_entry : "MAIN.HQ", sizeof(app->exec_entry));
    app->is_active = TRUE;

    kprintf("[AppRegistry] Successfully registered '%s' as an app.\n", name);
    speaker_event(BEEP_SUCCESS);
    return TRUE;
}

U32 app_registry_get_count(U0) {
    return g_app_count;
}

DynamicApp* app_registry_get(U32 index) {
    if (index >= g_app_count) return NULL;
    return &g_apps[index];
}

Bool app_registry_remove(const char* name) {
    if (!name) return FALSE;
    for (U32 i = 0; i < g_app_count; i++) {
        if (StrCmp(g_apps[i].name, name) == 0) {
            for (U32 j = i; j < g_app_count - 1; j++) {
                g_apps[j] = g_apps[j + 1];
            }
            g_app_count--;
            MemSet(&g_apps[g_app_count], 0, sizeof(DynamicApp));
            kprintf("[AppRegistry] Removed app '%s' from launcher.\n", name);
            return TRUE;
        }
    }
    return FALSE;
}

U0 app_registry_launch(U32 index) {
    if (index >= g_app_count) return;
    DynamicApp* app = &g_apps[index];

    kprintf("\n[AppRegistry] Launching Application '%s'...\n", app->name);
    speaker_event(BEEP_CONFIRM);

    // Build full path to entry point: <bundle_path>/<exec_entry>
    char full_path[128];
    if (app->bundle_path[0] != '\0') {
        ksnprintf(full_path, sizeof(full_path), "%s/%s", app->bundle_path, app->exec_entry);
    } else {
        ksnprintf(full_path, sizeof(full_path), "%s", app->exec_entry);
    }

    size_t sz = 0;
    U8* code = vfs_read_file(full_path, &sz);
    if (!code) {
        code = vfs_read_file(app->exec_entry, &sz);
    }

    if (!code) {
        kprintf("[AppRegistry] Error: Entry point '%s' not found on disk or RamFS.\n", full_path);
        speaker_event(BEEP_WARN);
        return;
    }

    // Installed applications are untrusted code: they always run in an
    // isolated PMP cell, never on hart 0. (HolyQ typed at the physical
    // console, e.g. `run <file.HQ>`, still runs with full privileges.)
    kprintf("\n--- [ Running %s (%s) in an isolated PMP cell ] ---\n", app->name, app->exec_entry);
    CellResult r;
    Bool ok = cell_start_app((const char*)code, app->name, 30000, &r);
    Free(code);   // compiled into the cell arena already
    if (!ok) {
        kprintf("--- [ %s stopped: %s ] ---\n", app->name, r.reason);
        speaker_event(BEEP_WARN);
    }
}

U0 app_registry_rescan(U0) {
    if (!redsea_eml_is_mounted()) return;

    RedSeaVolume* vol = redsea_eml_get_volume();
    if (!vol) return;

    // Scan for any directories under APPS/ or ending in .APP
    for (U32 i = 0; i < vol->entry_count; i++) {
        RedSeaFileEntry* fe = &vol->entries[i];
        if (!(fe->flags & REDSEA_FLAG_USED)) continue;

        // Check if entry contains .APP or is in APPS/
        size_t len = StrLen(fe->name);
        int app_idx = -1;
        for (size_t s = 0; s + 4 <= len; s++) {
            if (fe->name[s] == '.' && 
                (fe->name[s+1] == 'A' || fe->name[s+1] == 'a') &&
                (fe->name[s+2] == 'P' || fe->name[s+2] == 'p') &&
                (fe->name[s+3] == 'P' || fe->name[s+3] == 'p') &&
                (fe->name[s+4] == '\0' || fe->name[s+4] == '/')) {
                app_idx = (int)s;
                break;
            }
        }
        if (app_idx > 0) {
            char app_name[32];
            int copy_len = app_idx < 31 ? app_idx : 31;
            for (int c = 0; c < copy_len; c++) {
                app_name[c] = fe->name[c];
            }
            app_name[copy_len] = '\0';
            // Strip any APPS/ prefix
            char* disp = app_name;
            for (int k = 0; app_name[k]; k++) {
                if (app_name[k] == '/') disp = &app_name[k + 1];
            }

            char bundle[64];
            ksnprintf(bundle, sizeof(bundle), "APPS/%s.APP", disp);

            // Avoid duplicate registrations if both directory and files are encountered
            Bool already_registered = FALSE;
            for (U32 a = 0; a < g_app_count; a++) {
                if (StrICmp(g_apps[a].name, disp) == 0 || StrICmp(g_apps[a].bundle_path, bundle) == 0) {
                    already_registered = TRUE;
                    break;
                }
            }
            if (already_registered) continue;

            char exec_name[32];
            StrNCpy(exec_name, "MAIN.HQ", sizeof(exec_name));
            char app_title[32];
            StrNCpy(app_title, disp, sizeof(app_title));

            // Check if APP.INFO exists in bundle
            char info_path[96];
            ksnprintf(info_path, sizeof(info_path), "%s/APP.INFO", bundle);
            size_t isz = 0;
            U8* info_data = redsea_eml_read_file_path(info_path, &isz);
            if (info_data) {
                // Parse simple KEY=VALUE
                char* p = (char*)info_data;
                char* end = p + isz;
                while (p < end) {
                    while (p < end && (*p == ' ' || *p == '\r' || *p == '\n')) p++;
                    if (p >= end) break;
                    if (StrNCmp(p, "NAME=", 5) == 0) {
                        p += 5;
                        int idx = 0;
                        while (p < end && *p != '\r' && *p != '\n' && idx < 31) {
                            app_title[idx++] = *p++;
                        }
                        app_title[idx] = '\0';
                    } else if (StrNCmp(p, "EXEC=", 5) == 0) {
                        p += 5;
                        int idx = 0;
                        while (p < end && *p != '\r' && *p != '\n' && idx < 31) {
                            exec_name[idx++] = *p++;
                        }
                        exec_name[idx] = '\0';
                    } else {
                        while (p < end && *p != '\n') p++;
                    }
                }
                Free(info_data);
            }

            app_registry_register(app_title, bundle, exec_name);

        }
    }
}

// Console: pkg [list | install <file.ypk> | run <app> | remove <app>]
static Bool pkg_shell_run(const char* cmd) {
    if (StrNCmp(cmd, "pkg", 3) != 0 || (cmd[3] != ' ' && cmd[3] != '\0')) return FALSE;
        const char* sub = cmd + 3;
        while (*sub == ' ') sub++;
        if (*sub == '\0' || StrCmp(sub, "list") == 0) {
            ypkg_list();
        } else if (StrNCmp(sub, "install ", 8) == 0) {
            const char* target = sub + 8;
            while (*target == ' ') target++;
            ypkg_install_file(target);
        } else if (StrNCmp(sub, "run ", 4) == 0) {
            ypkg_run(sub + 4);
        } else if (StrNCmp(sub, "remove ", 7) == 0) {
            ypkg_remove(sub + 7);
        } else {
            kprintf("Usage: pkg [list | install <file.ypk> | run <app> | remove <app>]\n");
        }
    return TRUE;
}

static U0 pkg_shell_help(U0) {
    kprintf("  Packages\n");
    kprintf("    pkg [list|install <f.ypk>|run <app>|remove <app>]   (apps run in PMP cells)\n");
}

U0 app_registry_register_shell(U0) {
    static const ShellExtension ext = { pkg_shell_run, pkg_shell_help, NULL, NULL };
    shell_register(&ext);
}
