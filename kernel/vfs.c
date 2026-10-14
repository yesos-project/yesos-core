#include "vault.h"
#include "memory.h"

#ifndef YESOS_WITH_VAULT
// Built without the vault module: /vault stays a forbidden area (never a
// plaintext fallback), every access fails as "not initialized".
static Bool novault_path_is_protected(const char* p) {
    if (!p) return FALSE;
    while (*p == '/') p++;
    if (StrNICmp(p, "vault", 5) != 0) return FALSE;
    return p[5] == '\0' || p[5] == '/';
}
static U8* novault_read(const char* path, size_t* out_size, VaultResult* err) {
    (void)path; (void)out_size;
    if (err) *err = VAULT_ERR_NOT_INITIALIZED;
    return NULL;
}
static VaultResult novault_write(const char* path, const void* data, size_t size) {
    (void)path; (void)data; (void)size;
    return VAULT_ERR_NOT_INITIALIZED;
}
static const char* novault_result_str(VaultResult r) {
    (void)r;
    return "this system has no vault";
}
#define vault_path_is_protected novault_path_is_protected
#define vault_read novault_read
#define vault_write novault_write
#define vault_result_str novault_result_str
#endif
#include "vfs.h"
#include "redsea_eml.h"
#include "ramfs.h"
#include "kprintf.h"
#include "memory.h"
#include "speaker.h"

static char g_vfs_cwd[VFS_MAX_PATH] = "/";

U0 vfs_init(U0) {
    StrCpy(g_vfs_cwd, "/");
}

const char* vfs_get_cwd(U0) {
    return g_vfs_cwd;
}

static Bool is_path_separator(char c) {
    return c == '/' || c == '\\';
}

Bool vfs_resolve_path(const char* input_path, char* out_buf, size_t max_len) {
    if (!out_buf || max_len < 2) return FALSE;

    if (!input_path || input_path[0] == '\0') {
        StrNCpy(out_buf, g_vfs_cwd, max_len);
        return TRUE;
    }

    if (StrCmp(input_path, "~") == 0) {
        StrNCpy(out_buf, "/", max_len);
        return TRUE;
    }

    char stack[16][32];
    int depth = 0;

    // If relative path, seed stack with current directory
    if (!is_path_separator(input_path[0])) {
        const char* c = g_vfs_cwd;
        while (*c) {
            while (*c && is_path_separator(*c)) c++;
            if (!*c) break;
            int idx = 0;
            while (*c && !is_path_separator(*c) && idx < 31) {
                stack[depth][idx++] = *c++;
            }
            stack[depth][idx] = '\0';
            if (depth < 15) depth++;
        }
    }

    // Process components of input_path
    const char* p = input_path;
    while (*p) {
        while (*p && is_path_separator(*p)) p++;
        if (!*p) break;

        char comp[32];
        int idx = 0;
        while (*p && !is_path_separator(*p) && idx < 31) {
            comp[idx++] = *p++;
        }
        comp[idx] = '\0';

        if (StrCmp(comp, ".") == 0) {
            continue;
        } else if (StrCmp(comp, "..") == 0) {
            if (depth > 0) depth--;
        } else {
            if (depth < 16) {
                StrNCpy(stack[depth], comp, 31);
                stack[depth][31] = '\0';
                depth++;
            }
        }
    }

    // Reconstruct canonical absolute path
    if (depth == 0) {
        StrNCpy(out_buf, "/", max_len);
        return TRUE;
    }

    out_buf[0] = '\0';
    for (int i = 0; i < depth; i++) {
        StrNCat(out_buf, "/", max_len);
        StrNCat(out_buf, stack[i], max_len);
    }

    return TRUE;
}

Bool vfs_is_dir(const char* path) {
    char canon[VFS_MAX_PATH];
    if (!vfs_resolve_path(path, canon, sizeof(canon))) return FALSE;

    if (StrCmp(canon, "/") == 0) return TRUE;
    if (StrICmp(canon, "/ram") == 0) return TRUE;

    // Check in RedSea-EML
    const char* clean = canon;
    while (*clean == '/') clean++;

    if (!redsea_eml_is_mounted()) return FALSE;
    RedSeaVolume* vol = redsea_eml_get_volume();
    if (!vol) return FALSE;

    size_t clen = StrLen(clean);

    for (U32 i = 0; i < vol->entry_count; i++) {
        RedSeaFileEntry* fe = &vol->entries[i];
        if (!(fe->flags & REDSEA_FLAG_USED)) continue;

        // Exact match with directory flag
        if (StrICmp(fe->name, clean) == 0 && (fe->flags & REDSEA_FLAG_DIR)) {
            return TRUE;
        }

        // Prefix match: clean/ exists in entries
        if (StrNICmp(fe->name, clean, clen) == 0 && fe->name[clen] == '/') {
            return TRUE;
        }
    }

    U32 ram_cnt = ramfs_get_file_count();
    for (U32 i = 0; i < ram_cnt; i++) {
        RamFile* rf = ramfs_get_file_by_index(i);
        if (rf && rf->is_used) {
            if (StrNICmp(rf->name, clean, clen) == 0 && rf->name[clen] == '/') {
                return TRUE;
            }
        }
    }

    return FALSE;
}

Bool vfs_set_cwd(const char* path) {
    char target[VFS_MAX_PATH];
    if (!vfs_resolve_path(path, target, sizeof(target))) return FALSE;

    if (!vfs_is_dir(target)) {
        kprintf("cd: no such directory: %s\n", path);
        speaker_event(BEEP_WARN);
        return FALSE;
    }

    StrNCpy(g_vfs_cwd, target, sizeof(g_vfs_cwd));
    speaker_event(BEEP_CONFIRM);
    return TRUE;
}

Bool vfs_exists(const char* path) {
    char canon[VFS_MAX_PATH];
    if (!vfs_resolve_path(path, canon, sizeof(canon))) return FALSE;

    if (vfs_is_dir(canon)) return TRUE;

    if (StrNICmp(canon, "/ram/", 5) == 0) {
        return ramfs_exists(canon + 5);
    }

    const char* clean = canon;
    while (*clean == '/') clean++;

    if (redsea_eml_exists_path(clean)) return TRUE;
    if (ramfs_exists(clean)) return TRUE;

    // Standard fallback subdirectories
    const char* const std_dirs[] = { "APPS", "DOCS", "SYS", "PKG", "PKG/GAMES", "MUSIC", "HOME" };
    char subpath[VFS_MAX_PATH];
    for (int d = 0; d < 7; d++) {
        ksnprintf(subpath, sizeof(subpath), "%s/%s", std_dirs[d], clean);
        if (redsea_eml_exists_path(subpath)) return TRUE;
        if (ramfs_exists(subpath)) return TRUE;
    }

    // Basename fallback search
    const char* bname = clean;
    for (int k = 0; clean[k]; k++) {
        if (clean[k] == '/') bname = &clean[k + 1];
    }
    if (bname != clean) {
        if (redsea_eml_exists_path(bname)) return TRUE;
        if (ramfs_exists(bname)) return TRUE;
    }

    return FALSE;
}

U8* vfs_read_file(const char* path, size_t* out_size) {
    char canon[VFS_MAX_PATH];
    if (!vfs_resolve_path(path, canon, sizeof(canon))) return NULL;

    // Encrypted area: decrypt through the vault, never via fallback lookups.
    if (vault_path_is_protected(canon)) {
        VaultResult err = VAULT_OK;
        U8* pt = vault_read(canon, out_size, &err);
        if (!pt && err != VAULT_ERR_IO) {
            kprintf("vfs: %s: %s\n", canon, vault_result_str(err));
        }
        return pt;
    }

    if (StrNICmp(canon, "/ram/", 5) == 0) {
        size_t sz = 0;
        U8* data = ramfs_read(canon + 5, &sz);
        if (!data) return NULL;
        U8* copy = (U8*)Malloc(sz + 1);
        if (!copy) return NULL;
        MemCpy(copy, data, sz);
        copy[sz] = '\0';
        if (out_size) *out_size = sz;
        return copy;
    }

    const char* clean = canon;
    while (*clean == '/') clean++;

    U8* data = redsea_eml_read_file_path(clean, out_size);
    if (!data) {
        data = redsea_eml_read_file(clean, out_size);
    }
    if (!data && ramfs_exists(clean)) {
        size_t sz = 0;
        U8* rdata = ramfs_read(clean, &sz);
        if (rdata) {
            data = (U8*)Malloc(sz + 1);
            if (data) {
                MemCpy(data, rdata, sz);
                data[sz] = '\0';
                if (out_size) *out_size = sz;
            }
        }
    }

    if (!data) {
        // Fallback search across standard directories
        const char* const std_dirs[] = { "APPS", "DOCS", "SYS", "PKG", "PKG/GAMES", "MUSIC", "HOME" };
        char subpath[VFS_MAX_PATH];
        for (int d = 0; d < 7 && !data; d++) {
            ksnprintf(subpath, sizeof(subpath), "%s/%s", std_dirs[d], clean);
            data = redsea_eml_read_file_path(subpath, out_size);
            if (!data) data = redsea_eml_read_file(subpath, out_size);
            if (!data && ramfs_exists(subpath)) {
                size_t sz = 0;
                U8* rdata = ramfs_read(subpath, &sz);
                if (rdata) {
                    data = (U8*)Malloc(sz + 1);
                    if (data) {
                        MemCpy(data, rdata, sz);
                        data[sz] = '\0';
                        if (out_size) *out_size = sz;
                    }
                }
            }
        }
    }

    if (!data) {
        // Fallback: stripped basename search
        const char* bname = clean;
        for (int k = 0; clean[k]; k++) {
            if (clean[k] == '/') bname = &clean[k + 1];
        }
        if (bname != clean) {
            data = redsea_eml_read_file_path(bname, out_size);
            if (!data) data = redsea_eml_read_file(bname, out_size);
            if (!data && ramfs_exists(bname)) {
                size_t sz = 0;
                U8* rdata = ramfs_read(bname, &sz);
                if (rdata) {
                    data = (U8*)Malloc(sz + 1);
                    if (data) {
                        MemCpy(data, rdata, sz);
                        data[sz] = '\0';
                        if (out_size) *out_size = sz;
                    }
                }
            }
        }
    }

    return data;
}

U8* vfs_read_file_exact(const char* abs_path, size_t* out_size) {
    if (!abs_path || abs_path[0] != '/') return NULL;
    char canon[VFS_MAX_PATH];
    if (!vfs_resolve_path(abs_path, canon, sizeof(canon))) return NULL;

    if (vault_path_is_protected(canon)) {
        return vault_read(canon, out_size, NULL);
    }

    if (StrNICmp(canon, "/ram/", 5) == 0) {
        size_t sz = 0;
        U8* data = ramfs_read(canon + 5, &sz);
        if (!data) return NULL;
        U8* copy = (U8*)Malloc(sz + 1);
        if (!copy) return NULL;
        MemCpy(copy, data, sz);
        copy[sz] = '\0';
        if (out_size) *out_size = sz;
        return copy;
    }

    const char* clean = canon;
    while (*clean == '/') clean++;
    return redsea_eml_read_file_path(clean, out_size);
}

Bool vfs_write_file(const char* path, const void* data, size_t size) {
    char canon[VFS_MAX_PATH];
    if (!vfs_resolve_path(path, canon, sizeof(canon))) return FALSE;

    if (StrNICmp(canon, "/ram/", 5) == 0) {
        return ramfs_write_binary(canon + 5, data, size);
    }

    if (vault_path_is_protected(canon)) {
        VaultResult r = vault_write(canon, data, size);
        if (r != VAULT_OK) {
            kprintf("vfs: %s: %s\n", canon, vault_result_str(r));
            return FALSE;
        }
        return TRUE;
    }

    const char* clean = canon;
    while (*clean == '/') clean++;
    return redsea_eml_write_file_path(clean, data, size, 0);
}

Bool vfs_mkdir(const char* path) {
    char canon[VFS_MAX_PATH];
    if (!vfs_resolve_path(path, canon, sizeof(canon))) return FALSE;

    if (StrNICmp(canon, "/ram", 4) == 0) {
        kprintf("mkdir: cannot create subdirectory in volatile RamFS\n");
        return FALSE;
    }

    const char* clean = canon;
    while (*clean == '/') clean++;
    return redsea_eml_mkdir(clean);
}

Bool vfs_remove(const char* path) {
    char canon[VFS_MAX_PATH];
    if (!vfs_resolve_path(path, canon, sizeof(canon))) return FALSE;

    if (StrNICmp(canon, "/ram/", 5) == 0) {
        return ramfs_delete(canon + 5);
    }

    const char* clean = canon;
    while (*clean == '/') clean++;
    return redsea_eml_delete_file(clean);
}

static Bool is_in_entry_list(VFSEntry* entries, U32 count, const char* name) {
    for (U32 i = 0; i < count; i++) {
        if (StrICmp(entries[i].name, name) == 0) return TRUE;
    }
    return FALSE;
}

static int vfs_entry_compare(const VFSEntry* a, const VFSEntry* b) {
    // Category priority:
    // 0: Directory (Folder)
    // 1: Application Bundle (.APP)
    // 2: Regular File
    int cat_a = (a->type == VFS_TYPE_DIR) ? 0 : ((a->type == VFS_TYPE_APP_BUNDLE) ? 1 : 2);
    int cat_b = (b->type == VFS_TYPE_DIR) ? 0 : ((b->type == VFS_TYPE_APP_BUNDLE) ? 1 : 2);

    if (cat_a != cat_b) {
        return cat_a - cat_b;
    }

    int cmp = StrICmp(a->name, b->name);
    if (cmp != 0) return cmp;
    return StrCmp(a->name, b->name);
}

U0 vfs_sort_entries(VFSEntry* entries, U32 count) {
    if (!entries || count < 2) return;
    for (U32 i = 1; i < count; i++) {
        VFSEntry key = entries[i];
        I64 j = (I64)i - 1;
        while (j >= 0 && vfs_entry_compare(&entries[j], &key) > 0) {
            entries[j + 1] = entries[j];
            j--;
        }
        entries[j + 1] = key;
    }
}

U32 vfs_list_dir(const char* dir_path, VFSEntry* entries, U32 max_entries) {
    if (!entries || max_entries == 0) return 0;

    char canon[VFS_MAX_PATH];
    if (!vfs_resolve_path(dir_path, canon, sizeof(canon))) return 0;

    U32 count = 0;

    // 1. If listing /ram
    if (StrICmp(canon, "/ram") == 0) {
        U32 ram_cnt = ramfs_get_file_count();
        for (U32 i = 0; i < ram_cnt && count < max_entries; i++) {
            RamFile* rf = ramfs_get_file_by_index(i);
            if (rf && rf->is_used) {
                StrNCpy(entries[count].name, rf->name, sizeof(entries[count].name));
                entries[count].type = VFS_TYPE_FILE;
                entries[count].size = rf->size;
                entries[count].flags = 0;
                count++;
            }
        }
        vfs_sort_entries(entries, count);
        return count;
    }

    // 2. Listing Root (/)
    Bool is_root = (StrCmp(canon, "/") == 0);

    if (is_root && count < max_entries) {
        // Expose /ram as a virtual directory
        StrNCpy(entries[count].name, "ram", sizeof(entries[count].name));
        entries[count].type = VFS_TYPE_DIR;
        entries[count].size = 0;
        entries[count].flags = 0;
        count++;
    }

    if (!redsea_eml_is_mounted() || !redsea_eml_get_volume()) {
        vfs_sort_entries(entries, count);
        return count;
    }
    RedSeaVolume* vol = redsea_eml_get_volume();

    const char* clean_target = canon;
    while (*clean_target == '/') clean_target++;
    size_t target_len = StrLen(clean_target);

    for (U32 i = 0; i < vol->entry_count && count < max_entries; i++) {
        RedSeaFileEntry* fe = &vol->entries[i];
        if (!(fe->flags & REDSEA_FLAG_USED)) continue;

        if (is_root) {
            // Find root item or top directory
            const char* slash = NULL;
            for (int k = 0; fe->name[k]; k++) {
                if (fe->name[k] == '/') {
                    slash = &fe->name[k];
                    break;
                }
            }

            if (slash) {
                char top_dir[32];
                size_t dlen = (size_t)(slash - fe->name);
                if (dlen >= sizeof(top_dir)) dlen = sizeof(top_dir) - 1;
                StrNCpy(top_dir, fe->name, dlen + 1);
                top_dir[dlen] = '\0';

                if (!is_in_entry_list(entries, count, top_dir)) {
                    StrNCpy(entries[count].name, top_dir, sizeof(entries[count].name));
                    entries[count].type = VFS_TYPE_DIR;
                    entries[count].size = 0;
                    entries[count].flags = REDSEA_FLAG_DIR;
                    count++;
                }
            } else {
                if (fe->flags & REDSEA_FLAG_BOOT_KERNEL) {
                    continue; // Keep KERNEL.BIN cleanly housed under /SYS, not loose in /
                }
                if (!is_in_entry_list(entries, count, fe->name)) {
                    StrNCpy(entries[count].name, fe->name, sizeof(entries[count].name));
                    entries[count].type = (fe->flags & REDSEA_FLAG_DIR) ? VFS_TYPE_DIR : VFS_TYPE_FILE;
                    entries[count].size = fe->byte_size;
                    entries[count].flags = fe->flags;
                    count++;
                }
            }
        } else {
            // Subdirectory listing
            if (StrICmp(clean_target, "SYS") == 0 && (fe->flags & REDSEA_FLAG_BOOT_KERNEL)) {
                if (!is_in_entry_list(entries, count, "KERNEL.BIN")) {
                    StrNCpy(entries[count].name, "KERNEL.BIN", sizeof(entries[count].name));
                    entries[count].type = VFS_TYPE_FILE;
                    entries[count].size = fe->byte_size;
                    entries[count].flags = fe->flags;
                    count++;
                }
            }

            if (StrNICmp(fe->name, clean_target, target_len) == 0 && fe->name[target_len] == '/') {
                const char* sub = fe->name + target_len + 1;
                const char* sub_slash = NULL;
                for (int k = 0; sub[k]; k++) {
                    if (sub[k] == '/') {
                        sub_slash = &sub[k];
                        break;
                    }
                }

                if (sub_slash) {
                    char sub_dir[32];
                    size_t dlen = (size_t)(sub_slash - sub);
                    if (dlen >= sizeof(sub_dir)) dlen = sizeof(sub_dir) - 1;
                    StrNCpy(sub_dir, sub, dlen + 1);
                    sub_dir[dlen] = '\0';

                    if (!is_in_entry_list(entries, count, sub_dir)) {
                        StrNCpy(entries[count].name, sub_dir, sizeof(entries[count].name));
                        size_t slen = StrLen(sub_dir);
                        if (slen > 4 && StrICmp(sub_dir + slen - 4, ".APP") == 0) {
                            entries[count].type = VFS_TYPE_APP_BUNDLE;
                        } else {
                            entries[count].type = VFS_TYPE_DIR;
                        }
                        entries[count].size = 0;
                        entries[count].flags = REDSEA_FLAG_DIR;
                        count++;
                    }
                } else {
                    if (!is_in_entry_list(entries, count, sub)) {
                        StrNCpy(entries[count].name, sub, sizeof(entries[count].name));
                        size_t slen = StrLen(sub);
                        if (slen > 4 && StrICmp(sub + slen - 4, ".APP") == 0) {
                            entries[count].type = VFS_TYPE_APP_BUNDLE;
                        } else if (fe->flags & REDSEA_FLAG_DIR) {
                            entries[count].type = VFS_TYPE_DIR;
                        } else {
                            entries[count].type = VFS_TYPE_FILE;
                        }
                        entries[count].size = fe->byte_size;
                        entries[count].flags = fe->flags;
                        count++;
                    }
            }
        }
    }
    }

    // Also include structured RamFS directories and files
    U32 ram_cnt = ramfs_get_file_count();
    for (U32 i = 0; i < ram_cnt && count < max_entries; i++) {
        RamFile* rf = ramfs_get_file_by_index(i);
        if (!rf || !rf->is_used) continue;

        if (is_root) {
            const char* slash = NULL;
            for (int k = 0; rf->name[k]; k++) {
                if (rf->name[k] == '/') {
                    slash = &rf->name[k];
                    break;
                }
            }
            if (slash) {
                char top_dir[32];
                size_t dlen = (size_t)(slash - rf->name);
                if (dlen >= sizeof(top_dir)) dlen = sizeof(top_dir) - 1;
                StrNCpy(top_dir, rf->name, dlen + 1);
                top_dir[dlen] = '\0';
                if (!is_in_entry_list(entries, count, top_dir)) {
                    StrNCpy(entries[count].name, top_dir, sizeof(entries[count].name));
                    entries[count].type = VFS_TYPE_DIR;
                    entries[count].size = 0;
                    entries[count].flags = 0;
                    count++;
                }
            } else {
                if (!is_in_entry_list(entries, count, rf->name)) {
                    StrNCpy(entries[count].name, rf->name, sizeof(entries[count].name));
                    entries[count].type = VFS_TYPE_FILE;
                    entries[count].size = rf->size;
                    entries[count].flags = 0;
                    count++;
                }
            }
        } else {
            if (StrNICmp(rf->name, clean_target, target_len) == 0 && rf->name[target_len] == '/') {
                const char* sub = rf->name + target_len + 1;
                const char* sub_slash = NULL;
                for (int k = 0; sub[k]; k++) {
                    if (sub[k] == '/') {
                        sub_slash = &sub[k];
                        break;
                    }
                }
                if (sub_slash) {
                    char sub_dir[32];
                    size_t dlen = (size_t)(sub_slash - sub);
                    if (dlen >= sizeof(sub_dir)) dlen = sizeof(sub_dir) - 1;
                    StrNCpy(sub_dir, sub, dlen + 1);
                    sub_dir[dlen] = '\0';
                    if (!is_in_entry_list(entries, count, sub_dir)) {
                        StrNCpy(entries[count].name, sub_dir, sizeof(entries[count].name));
                        entries[count].type = VFS_TYPE_DIR;
                        entries[count].size = 0;
                        entries[count].flags = 0;
                        count++;
                    }
                } else {
                    if (!is_in_entry_list(entries, count, sub)) {
                        StrNCpy(entries[count].name, sub, sizeof(entries[count].name));
                        entries[count].type = VFS_TYPE_FILE;
                        entries[count].size = rf->size;
                        entries[count].flags = 0;
                        count++;
                    }
                }
            }
        }
    }

    vfs_sort_entries(entries, count);
    return count;
}

U0 vfs_cmd_pwd(U0) {
    kprintf("%s\n", g_vfs_cwd);
}

U0 vfs_cmd_cd(const char* path) {
    if (!path || *path == '\0') {
        vfs_set_cwd("/");
        return;
    }
    vfs_set_cwd(path);
}

U0 vfs_cmd_ls(const char* arg) {
    const char* target = (arg && *arg) ? arg : g_vfs_cwd;
    char canon[VFS_MAX_PATH];
    if (!vfs_resolve_path(target, canon, sizeof(canon))) return;

    VFSEntry entries[VFS_MAX_DIR_ENTRIES];
    U32 count = vfs_list_dir(canon, entries, VFS_MAX_DIR_ENTRIES);

    kprintf("\nDirectory listing of %s (%u entries):\n", canon, count);
    kprintf("------------------------------------------------------------------\n");

    if (count == 0) {
        kprintf("  (empty directory)\n");
    } else {
        for (U32 i = 0; i < count; i++) {
            const char* tag = " [FILE] ";
            if (entries[i].type == VFS_TYPE_DIR) {
                tag = " [DIR]  ";
                kprintf("%s \033[36m%s/\033[0m\n", tag, entries[i].name);
            } else if (entries[i].type == VFS_TYPE_APP_BUNDLE) {
                tag = " [APP]  ";
                kprintf("%s \033[32m%s/\033[0m\n", tag, entries[i].name);
            } else {
                size_t nlen = StrLen(entries[i].name);
                if (nlen > 3 && StrICmp(entries[i].name + nlen - 3, ".HQ") == 0) tag = " [HQ]   ";
                else if (nlen > 3 && StrICmp(entries[i].name + nlen - 3, ".DD") == 0) tag = " [DOC]  ";
                else if (nlen > 4 && StrICmp(entries[i].name + nlen - 4, ".YPK") == 0) tag = " [PKG]  ";
                else if (nlen > 4 && StrICmp(entries[i].name + nlen - 4, ".MP3") == 0) tag = " [MP3]  ";

                if (entries[i].size >= 1024 * 1024) {
                    kprintf("%s %s\t\t%u MB\n", tag, entries[i].name, (U32)(entries[i].size / (1024*1024)));
                } else if (entries[i].size >= 1024) {
                    kprintf("%s %s\t\t%u KB\n", tag, entries[i].name, (U32)(entries[i].size / 1024));
                } else {
                    kprintf("%s %s\t\t%u B\n", tag, entries[i].name, (U32)entries[i].size);
                }
            }
        }
    }
    kprintf("------------------------------------------------------------------\n\n");
    speaker_event(BEEP_CONFIRM);
}

U0 vfs_cmd_mkdir(const char* path) {
    if (!path || *path == '\0') {
        kprintf("mkdir: missing operand\n");
        speaker_event(BEEP_WARN);
        return;
    }

    if (vfs_mkdir(path)) {
        kprintf("mkdir: created directory '%s'\n", path);
        speaker_event(BEEP_SUCCESS);
    } else {
        kprintf("mkdir: failed to create directory '%s'\n", path);
        speaker_event(BEEP_WARN);
    }
}

U0 vfs_cmd_cat(const char* path) {
    if (!path || *path == '\0') {
        kprintf("cat: missing operand\n");
        return;
    }

    size_t sz = 0;
    U8* data = vfs_read_file(path, &sz);
    if (!data) {
        kprintf("cat: %s: No such file\n", path);
        speaker_event(BEEP_WARN);
        return;
    }

    kprintf("%s\n", (const char*)data);
    Free(data);
    speaker_event(BEEP_CONFIRM);
}

U0 vfs_cmd_rm(const char* path) {
    if (!path || *path == '\0') {
        kprintf("rm: missing operand\n");
        return;
    }

    if (vfs_remove(path)) {
        kprintf("rm: removed '%s'\n", path);
        speaker_event(BEEP_SUCCESS);
    } else {
        kprintf("rm: cannot remove '%s': No such file\n", path);
        speaker_event(BEEP_WARN);
    }
}

static U0 tree_recursive(const char* dir_path, int depth, int max_depth) {
    if (depth >= max_depth) return;

    // Heap, not stack: this function recurses and each level lists 64 entries.
    VFSEntry* entries = (VFSEntry*)Malloc(sizeof(VFSEntry) * VFS_MAX_DIR_ENTRIES);
    if (!entries) return;
    U32 count = vfs_list_dir(dir_path, entries, VFS_MAX_DIR_ENTRIES);

    for (U32 i = 0; i < count; i++) {
        Bool is_last = (i == count - 1);

        for (int d = 0; d < depth; d++) {
            kprintf("    ");
        }

        if (is_last) {
            kprintf("└── ");
        } else {
            kprintf("├── ");
        }

        if (entries[i].type == VFS_TYPE_DIR || entries[i].type == VFS_TYPE_APP_BUNDLE) {
            kprintf("\033[36m%s/\033[0m\n", entries[i].name);
            char sub_path[VFS_MAX_PATH];
            ksnprintf(sub_path, sizeof(sub_path), "%s/%s", dir_path, entries[i].name);
            tree_recursive(sub_path, depth + 1, max_depth);
        } else {
            kprintf("%s\n", entries[i].name);
        }
    }
    Free(entries);
}

U0 vfs_print_tree(const char* root_path, int max_depth) {
    const char* start = (root_path && *root_path) ? root_path : "/";
    char canon[VFS_MAX_PATH];
    if (!vfs_resolve_path(start, canon, sizeof(canon))) return;

    kprintf("%s\n", canon);
    tree_recursive(canon, 0, max_depth > 0 ? max_depth : 4);
    speaker_event(BEEP_CONFIRM);
}
