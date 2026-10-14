#include "ypkg.h"
#include "app_registry.h"
#include "redsea_eml.h"
#include "ramfs.h"
#include "lz4.h"
#include "kprintf.h"
#include "memory.h"
#include "speaker.h"

#define YPKG_MAX_UNCOMPRESSED (16 * 1024 * 1024)

// Package names become RedSea paths: letters, digits, '_', '-', and '.' for
// file names. No '/', so nothing can escape the bundle directory.
static Bool ypkg_name_ok(const char* s, Bool allow_dot) {
    if (!s[0]) return FALSE;
    for (; *s; s++) {
        char c = *s;
        Bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                  c == '_' || c == '-' || (allow_dot && c == '.');
        if (!ok) return FALSE;
    }
    return TRUE;
}

#define YPKG_TERMINATE(field) ((field)[sizeof(field) - 1] = '\0')

Bool ypkg_install_from_memory(const U8* pkg_data, size_t total_size) {
    if (!pkg_data || total_size < sizeof(YPkgHeader)) {
        kprintf("[YPKG] Error: Package data buffer too small or null.\n");
        return FALSE;
    }

    // Work on a private copy: every field below comes from an untrusted file.
    static YPkgHeader hdr_copy;
    MemCpy(&hdr_copy, pkg_data, sizeof(YPkgHeader));
    YPkgHeader* hdr = &hdr_copy;
    if (hdr->magic != YPKG_MAGIC) {
        kprintf("[YPKG] Error: Invalid package magic (got 0x%x, expected 0x%x).\n", hdr->magic, YPKG_MAGIC);
        return FALSE;
    }
    YPKG_TERMINATE(hdr->app_name);
    YPKG_TERMINATE(hdr->bundle_id);
    YPKG_TERMINATE(hdr->exec_entry);
    YPKG_TERMINATE(hdr->icon_name);
    YPKG_TERMINATE(hdr->version_str);
    YPKG_TERMINATE(hdr->author);
    if (hdr->file_count > YPKG_MAX_FILES) hdr->file_count = YPKG_MAX_FILES;
    Bool entry_found = FALSE;
    for (U32 i = 0; i < hdr->file_count; i++) {
        YPKG_TERMINATE(hdr->files[i].name);
        if (!ypkg_name_ok(hdr->files[i].name, TRUE)) {
            kprintf("[YPKG] Error: invalid file name in package.\n");
            return FALSE;
        }
        if (StrCmp(hdr->files[i].name, hdr->exec_entry) == 0) entry_found = TRUE;
    }
    if (!ypkg_name_ok(hdr->app_name, FALSE)) {
        kprintf("[YPKG] Error: invalid application name (letters, digits, '_' or '-').\n");
        return FALSE;
    }
    if (!entry_found) {
        kprintf("[YPKG] Error: entry point is not one of the package files.\n");
        return FALSE;
    }
    if ((U64)hdr->compressed_payload_size > (U64)(total_size - sizeof(YPkgHeader)) ||
        hdr->total_uncompressed_size == 0 || hdr->total_uncompressed_size > YPKG_MAX_UNCOMPRESSED) {
        kprintf("[YPKG] Error: inconsistent payload sizes.\n");
        return FALSE;
    }

    kprintf("\n================ [ YESOS SACRED PACKAGE INSTALLER ] ================\n");
    kprintf("Package Name       : '%s'\n", hdr->app_name);
    kprintf("Bundle ID          : '%s'\n", hdr->bundle_id);
    kprintf("Version            : %s  (by %s)\n", hdr->version_str, hdr->author);
    kprintf("Entry Point        : %s\n", hdr->exec_entry);
    kprintf("File Count         : %u files\n", hdr->file_count);
    kprintf("Uncompressed Size  : %u bytes\n", hdr->total_uncompressed_size);
    kprintf("Compressed Payload : %u bytes (LZ4)\n", hdr->compressed_payload_size);
    kprintf("--------------------------------------------------------------------\n");

    // Decompress payload using in-kernel LZ4
    const U8* compressed_ptr = pkg_data + sizeof(YPkgHeader);
    size_t uncompressed_alloc = hdr->total_uncompressed_size + 512;
    U8* uncompressed_buf = (U8*)Malloc(uncompressed_alloc);
    if (!uncompressed_buf) {
        kprintf("[YPKG] Error: Out of memory allocating decompressed buffer.\n");
        return FALSE;
    }
    MemSet(uncompressed_buf, 0, uncompressed_alloc);

    I64 decomp_res = lz4_decompress(compressed_ptr, (I64)hdr->compressed_payload_size,
                                    uncompressed_buf, (I64)hdr->total_uncompressed_size);
    if (decomp_res <= 0) {
        kprintf("[YPKG] Error: LZ4 decompression failed (code %d).\n", (int)decomp_res);
        Free(uncompressed_buf);
        return FALSE;
    }

    kprintf("[YPKG] LZ4 Streaming Decompressor: %u bytes unpacked into RAM [OK]\n", (U32)decomp_res);

    // Prepare bundle directory path in RedSea-EML
    char bundle_dir[64];
    ksnprintf(bundle_dir, sizeof(bundle_dir), "APPS/%s.APP", hdr->app_name);

    if (redsea_eml_is_mounted()) {
        redsea_eml_mkdir("APPS");
        redsea_eml_mkdir(bundle_dir);
    }

    // Write each file in package to disk and ramfs
    for (U32 i = 0; i < hdr->file_count && i < YPKG_MAX_FILES; i++) {
        const YPkgFileHeader* fh = &hdr->files[i];
        if ((U64)fh->offset + (U64)fh->size > (U64)decomp_res) {
            kprintf("[YPKG] Warning: File '%s' offset out of range, skipping.\n", fh->name);
            continue;
        }

        const U8* f_data = uncompressed_buf + fh->offset;

        // Path inside bundle
        char file_path[128];
        ksnprintf(file_path, sizeof(file_path), "%s/%s", bundle_dir, fh->name);

        if (redsea_eml_is_mounted()) {
            redsea_eml_write_file_path(file_path, f_data, fh->size, 0);
        }
        // (No RamFS copy: bare names there could shadow system files.)

        kprintf("  -> Extracted: '%s'\t\t(%u bytes)\n", fh->name, fh->size);
    }

    Free(uncompressed_buf);

    // Register with AppRegistry (icon fields of the package are ignored: no desktop)
    app_registry_register(hdr->app_name, bundle_dir, hdr->exec_entry);

    kprintf("====================================================================\n");
    kprintf("SUCCESS: '%s.APP' installed into RedSea-EML and registered!\n", hdr->app_name);
    kprintf("====================================================================\n\n");

    speaker_event(BEEP_SUCCESS);
    return TRUE;
}

Bool ypkg_install_file(const char* filepath) {
    if (!filepath) return FALSE;

    size_t sz = 0;
    U8* data = NULL;

    // Check RedSea first
    if (redsea_eml_is_mounted()) {
        data = redsea_eml_read_file_path(filepath, &sz);
    }

    // Check RamFS if not on disk
    if (!data && ramfs_exists(filepath)) {
        data = ramfs_read(filepath, &sz);
    }

    if (!data) {
        kprintf("[YPKG] Error: Package file '%s' not found.\n", filepath);
        return FALSE;
    }

    Bool ok = ypkg_install_from_memory(data, sz);
    Free(data);
    return ok;
}

Bool ypkg_run(const char* app_name) {
    if (!app_name) return FALSE;
    U32 count = app_registry_get_count();
    for (U32 i = 0; i < count; i++) {
        DynamicApp* app = app_registry_get(i);
        if (app && StrCmp(app->name, app_name) == 0) {
            app_registry_launch(i);
            return TRUE;
        }
    }

    kprintf("[YPKG] Application '%s' not found in registry. Type 'pkg list' for installed apps.\n", app_name);
    return FALSE;
}

U0 ypkg_list(U0) {
    U32 count = app_registry_get_count();
    kprintf("\n================ [ INSTALLED YESOS APPLICATIONS ] ================\n");
    kprintf("Index  App Name         Bundle Directory               Entry Point\n");
    kprintf("------------------------------------------------------------------\n");

    if (count == 0) {
        kprintf("  (No dynamic packages installed. Deploy via 'pkg get' or 'deploy')\n");
    } else {
        for (U32 i = 0; i < count; i++) {
            DynamicApp* app = app_registry_get(i);
            if (!app) continue;
            kprintf("  [%u]   %s\t\t%s\t\t%s\n", i + 1, app->name, app->bundle_path, app->exec_entry);
        }
    }
    kprintf("------------------------------------------------------------------\n\n");
}

Bool ypkg_remove(const char* app_name) {
    if (!app_name) return FALSE;
    return app_registry_remove(app_name);
}
