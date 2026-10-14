#include "ramfs.h"
#include "memory.h"
#include "kprintf.h"
#include "timer.h"

static RamFS g_ramfs;

static const char* DEFAULT_HELLO_HQ = 
"// HELLO.HQ - HolyQ Script for YesOS M-Mode\n"
"extern U0 kprintf(U8* fmt, ...);\n"
"\n"
"U0 Main() {\n"
"    I64 a = 10;\n"
"    I64 b = 32;\n"
"    I64 sum = a + b;\n"
"    kprintf(\"************************************************\\n\");\n"
"    kprintf(\"* HolyQ JIT Engine Running Live in M-Mode!      *\\n\");\n"
"    kprintf(\"* Result of (%d + %d) = %d                     *\\n\", a, b, sum);\n"
"    kprintf(\"************************************************\\n\");\n"
"}\n"
"\n"
"Main();\n";

Bool ramfs_create_static(const char* name, const void* data, size_t size) {
    if (!name || !data || size == 0) return FALSE;
    for (U32 i = 0; i < RAMFS_MAX_FILES; i++) {
        if (!g_ramfs.files[i].is_used) {
            RamFile* file = &g_ramfs.files[i];
            MemSet(file, 0, sizeof(RamFile));
            StrNCpy(file->name, name, sizeof(file->name));
            file->is_used = TRUE;
            file->is_readonly = TRUE;
            file->data = (U8*)data;
            file->size = size;
            file->capacity = size;
            file->created_tick = timer_get_ticks();
            file->modified_tick = file->created_tick;
            g_ramfs.file_count++;
            g_ramfs.total_bytes_used += size;
            return TRUE;
        }
    }
    return FALSE;
}

static const char* DEFAULT_README_TXT =
"YesOS NAS - secure RISC-V storage appliance (all code in Machine mode)\n"
"\n"
"  vault          encrypted /vault (XChaCha20-Poly1305, key held by the key hart)\n"
"  user, pin      NAS accounts (Argon2id) and console PIN\n"
"  nas, smb       NAS status, device admission, shares, server key\n"
"  pkg            install and run .ypk apps (always in an isolated PMP cell)\n"
"  pmp, cell      locked, Z3-proven memory protection; isolated app cores\n"
"  integrity      runtime check of kernel code and read-only data\n"
"\n"
"Remote access: WebDAV on port 8080, NAS protocol (Noise NK) on UDP 31415.\n"
"Type 'help' for the full command list.\n";

static const char* DEFAULT_NOTES_TXT =
"Your notes. Files under /ram are volatile; /vault and the WebDAV shares live on RedSea.\n";

U0 ramfs_init(U0) {
    MemSet(&g_ramfs, 0, sizeof(RamFS));
    ramfs_create("README.TXT", DEFAULT_README_TXT);
    ramfs_create("APPS/HELLO.HQ", DEFAULT_HELLO_HQ);
    ramfs_create("HOME/NOTES.TXT", DEFAULT_NOTES_TXT);
    kprintf("[RAMFS] Initialized with %u files.\n", g_ramfs.file_count);
}

static inline const char* ramfs_clean_name(const char* name) {
    if (!name) return NULL;
    if (StrNICmp(name, "/ram/", 5) == 0) name += 5;
    while (*name == '/') name++;
    return name;
}

Bool ramfs_create(const char* name, const char* initial_content) {
    const char* clean = ramfs_clean_name(name);
    if (!clean || StrLen(clean) == 0) return FALSE;

    // Check if file already exists
    for (U32 i = 0; i < RAMFS_MAX_FILES; i++) {
        if (g_ramfs.files[i].is_used && (StrNCmp(g_ramfs.files[i].name, clean, sizeof(g_ramfs.files[i].name)) == 0 ||
                                         StrNCmp(g_ramfs.files[i].name, name, sizeof(g_ramfs.files[i].name)) == 0)) {
            // Overwrite existing file
            size_t len = initial_content ? StrLen(initial_content) : 0;
            return ramfs_write(clean, initial_content, len);
        }
    }

    // Find free slot
    for (U32 i = 0; i < RAMFS_MAX_FILES; i++) {
        if (!g_ramfs.files[i].is_used) {
            RamFile* file = &g_ramfs.files[i];
            MemSet(file, 0, sizeof(RamFile));
            StrNCpy(file->name, clean, sizeof(file->name));
            file->is_used = TRUE;
            file->created_tick = timer_get_ticks();
            file->modified_tick = file->created_tick;
            
            size_t len = initial_content ? StrLen(initial_content) : 0;
            file->capacity = (len + 1 > RAMFS_DEFAULT_ALLOC) ? (len + 1024) : RAMFS_DEFAULT_ALLOC;
            file->data = (U8*)Malloc(file->capacity);
            if (!file->data) {
                file->is_used = FALSE;
                return FALSE;
            }
            
            if (initial_content && len > 0) {
                MemCpy(file->data, initial_content, len);
                file->data[len] = '\0';
                file->size = len;
            } else {
                file->data[0] = '\0';
                file->size = 0;
            }

            g_ramfs.file_count++;
            g_ramfs.total_bytes_used += file->size;
            return TRUE;
        }
    }
    return FALSE;
}

Bool ramfs_write(const char* name, const void* data, size_t size) {
    const char* clean = ramfs_clean_name(name);
    if (!clean) return FALSE;

    for (U32 i = 0; i < RAMFS_MAX_FILES; i++) {
        if (g_ramfs.files[i].is_used && (StrNCmp(g_ramfs.files[i].name, clean, sizeof(g_ramfs.files[i].name)) == 0 ||
                                         StrNCmp(g_ramfs.files[i].name, name, sizeof(g_ramfs.files[i].name)) == 0)) {
            RamFile* file = &g_ramfs.files[i];
            if (file->is_readonly) return FALSE;

            g_ramfs.total_bytes_used -= file->size;

            if (size + 1 > file->capacity) {
                size_t new_cap = size + 1024;
                U8* new_data = (U8*)Malloc(new_cap);
                if (!new_data) return FALSE;
                if (file->data) Free(file->data);
                file->data = new_data;
                file->capacity = new_cap;
            }

            if (data && size > 0) {
                MemCpy(file->data, data, size);
                file->data[size] = '\0';
                file->size = size;
            } else {
                if (file->data) file->data[0] = '\0';
                file->size = 0;
            }

            file->modified_tick = timer_get_ticks();
            g_ramfs.total_bytes_used += file->size;
            return TRUE;
        }
    }

    // If not found, create new
    return ramfs_create(clean, (const char*)data);
}

Bool ramfs_write_binary(const char* name, const void* data, size_t size) {
    const char* clean = ramfs_clean_name(name);
    if (!clean) return FALSE;

    for (U32 i = 0; i < RAMFS_MAX_FILES; i++) {
        if (g_ramfs.files[i].is_used && (StrNCmp(g_ramfs.files[i].name, clean, sizeof(g_ramfs.files[i].name)) == 0 ||
                                         StrNCmp(g_ramfs.files[i].name, name, sizeof(g_ramfs.files[i].name)) == 0)) {
            RamFile* file = &g_ramfs.files[i];
            if (file->is_readonly) return FALSE;

            g_ramfs.total_bytes_used -= file->size;

            if (size + 1 > file->capacity) {
                size_t new_cap = size + 1024;
                U8* new_data = (U8*)Malloc(new_cap);
                if (!new_data) return FALSE;
                if (file->data) Free(file->data);
                file->data = new_data;
                file->capacity = new_cap;
            }

            if (data && size > 0) {
                MemCpy(file->data, data, size);
                file->data[size] = '\0';
                file->size = size;
            } else {
                if (file->data) file->data[0] = '\0';
                file->size = 0;
            }

            file->modified_tick = timer_get_ticks();
            g_ramfs.total_bytes_used += file->size;
            return TRUE;
        }
    }

    // Find free slot to create new binary file
    for (U32 i = 0; i < RAMFS_MAX_FILES; i++) {
        if (!g_ramfs.files[i].is_used) {
            RamFile* file = &g_ramfs.files[i];
            MemSet(file, 0, sizeof(RamFile));
            StrNCpy(file->name, clean, sizeof(file->name));
            file->is_used = TRUE;
            file->created_tick = timer_get_ticks();
            file->modified_tick = file->created_tick;

            file->capacity = size + 1024;
            file->data = (U8*)Malloc(file->capacity);
            if (!file->data) {
                file->is_used = FALSE;
                return FALSE;
            }
            if (data && size > 0) {
                MemCpy(file->data, data, size);
                file->data[size] = '\0';
                file->size = size;
            } else {
                file->data[0] = '\0';
                file->size = 0;
            }
            g_ramfs.file_count++;
            g_ramfs.total_bytes_used += file->size;
            return TRUE;
        }
    }
    return FALSE;
}

U8* ramfs_read(const char* name, size_t* out_size) {
    const char* clean = ramfs_clean_name(name);
    if (!clean) return NULL;

    for (U32 i = 0; i < RAMFS_MAX_FILES; i++) {
        if (g_ramfs.files[i].is_used && (StrCmp(g_ramfs.files[i].name, clean) == 0 ||
                                         StrCmp(g_ramfs.files[i].name, name) == 0)) {
            if (out_size) *out_size = g_ramfs.files[i].size;
            return g_ramfs.files[i].data;
        }
    }
    return NULL;
}

const char* ramfs_read_string(const char* name) {
    return (const char*)ramfs_read(name, NULL);
}

Bool ramfs_delete(const char* name) {
    const char* clean = ramfs_clean_name(name);
    if (!clean) return FALSE;

    for (U32 i = 0; i < RAMFS_MAX_FILES; i++) {
        if (g_ramfs.files[i].is_used && (StrCmp(g_ramfs.files[i].name, clean) == 0 ||
                                         StrCmp(g_ramfs.files[i].name, name) == 0)) {
            RamFile* file = &g_ramfs.files[i];
            if (file->is_readonly) return FALSE;

            g_ramfs.total_bytes_used -= file->size;
            if (file->data) {
                Free(file->data);
                file->data = NULL;
            }
            file->is_used = FALSE;
            g_ramfs.file_count--;
            return TRUE;
        }
    }
    return FALSE;
}

Bool ramfs_exists(const char* name) {
    const char* clean = ramfs_clean_name(name);
    if (!clean) return FALSE;
    for (U32 i = 0; i < RAMFS_MAX_FILES; i++) {
        if (g_ramfs.files[i].is_used && (StrCmp(g_ramfs.files[i].name, clean) == 0 ||
                                         StrCmp(g_ramfs.files[i].name, name) == 0)) {
            return TRUE;
        }
    }
    return FALSE;
}

U32 ramfs_get_file_count(U0) {
    return g_ramfs.file_count;
}

U64 ramfs_get_total_bytes(U0) {
    return g_ramfs.total_bytes_used;
}

RamFile* ramfs_get_file_by_index(U32 index) {
    U32 count = 0;
    for (U32 i = 0; i < RAMFS_MAX_FILES; i++) {
        if (g_ramfs.files[i].is_used) {
            if (count == index) return &g_ramfs.files[i];
            count++;
        }
    }
    return NULL;
}

