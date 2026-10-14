#ifndef RAMFS_H
#define RAMFS_H

#include "types.h"

#define RAMFS_MAX_FILES     64
#define RAMFS_NAME_MAX      32
#define RAMFS_DEFAULT_ALLOC 4096

typedef struct {
    char name[RAMFS_NAME_MAX];
    U8* data;
    size_t size;
    size_t capacity;
    U64 created_tick;
    U64 modified_tick;
    Bool is_readonly;
    Bool is_used;
} RamFile;

typedef struct {
    RamFile files[RAMFS_MAX_FILES];
    U32 file_count;
    U64 total_bytes_used;
} RamFS;

// RamFS Core API
U0      ramfs_init(U0);
Bool    ramfs_create(const char* name, const char* initial_content);
Bool    ramfs_create_static(const char* name, const void* data, size_t size);
Bool    ramfs_write(const char* name, const void* data, size_t size);
Bool    ramfs_write_binary(const char* name, const void* data, size_t size);
U8*     ramfs_read(const char* name, size_t* out_size);
const char* ramfs_read_string(const char* name);
Bool    ramfs_delete(const char* name);
Bool    ramfs_exists(const char* name);
U32     ramfs_get_file_count(U0);
U64     ramfs_get_total_bytes(U0);
RamFile* ramfs_get_file_by_index(U32 index);

// Shell commands

#endif // RAMFS_H
