#ifndef YPKG_H
#define YPKG_H

#include "types.h"

#define YPKG_MAGIC       0x59504B47  // "YPKG" (YesOS Sacred Package)
#define YPKG_VERSION     1

#define YPKG_MAX_FILES   32
#define YPKG_NAME_MAX    32

typedef struct {
    char name[YPKG_NAME_MAX]; // e.g. "MAIN.HQ", "APP.INFO"
    U32  offset;               // Offset within uncompressed payload
    U32  size;                 // Uncompressed file size
    U32  flags;
} __attribute__((packed)) YPkgFileHeader;

typedef struct {
    U32 magic;                 // YPKG_MAGIC
    U32 version;               // 1
    char app_name[YPKG_NAME_MAX];   // e.g. "HolySynth"
    char bundle_id[YPKG_NAME_MAX];  // e.g. "org.yesos.synth"
    char exec_entry[YPKG_NAME_MAX]; // e.g. "MAIN.HQ"
    char icon_name[YPKG_NAME_MAX];  // e.g. "PKG", "PIANO", "GAMES"
    char version_str[16];           // e.g. "1.0.0"
    char author[32];                // e.g. "YesOS Community"
    U32 file_count;
    U32 total_uncompressed_size;
    U32 compressed_payload_size;
    U32 crc32;
    YPkgFileHeader files[YPKG_MAX_FILES];
} __attribute__((packed)) YPkgHeader;

// Public YPkg Core API
Bool ypkg_install_from_memory(const U8* pkg_data, size_t total_size);
Bool ypkg_install_file(const char* filepath);
Bool ypkg_run(const char* app_name);
U0   ypkg_list(U0);
Bool ypkg_remove(const char* app_name);

#endif // YPKG_H
