#ifndef VFS_H
#define VFS_H

#include "types.h"

#define VFS_MAX_PATH        256
#define VFS_MAX_FILENAME    128   // one path component in listings
#define VFS_MAX_DIR_ENTRIES 64

typedef enum {
    VFS_TYPE_FILE = 0,
    VFS_TYPE_DIR,
    VFS_TYPE_APP_BUNDLE,
} VFSEntryType;

typedef struct {
    char         name[VFS_MAX_FILENAME];
    VFSEntryType type;
    U64          size;
    U32          flags;
} VFSEntry;

// Lifecycle & Current Working Directory
U0          vfs_init(U0);
const char* vfs_get_cwd(U0);
Bool        vfs_set_cwd(const char* path);
Bool        vfs_resolve_path(const char* input_path, char* out_buf, size_t max_len);

// Inspections & Queries
Bool        vfs_is_dir(const char* path);
Bool        vfs_exists(const char* path);
U8*         vfs_read_file(const char* path, size_t* out_size);
// Exact lookup for untrusted (network) callers: absolute path only, no
// cwd-relative resolution and no fallback search across other directories.
U8*         vfs_read_file_exact(const char* abs_path, size_t* out_size);
Bool        vfs_write_file(const char* path, const void* data, size_t size);
Bool        vfs_mkdir(const char* path);
Bool        vfs_remove(const char* path);

// Directory Listing & Hierarchy
U32         vfs_list_dir(const char* dir_path, VFSEntry* entries, U32 max_entries);
U0          vfs_sort_entries(VFSEntry* entries, U32 count);
U0          vfs_print_tree(const char* root_path, int max_depth);

// Shell Command Implementations
U0          vfs_cmd_ls(const char* arg);
U0          vfs_cmd_cd(const char* path);
U0          vfs_cmd_pwd(U0);
U0          vfs_cmd_mkdir(const char* path);
U0          vfs_cmd_cat(const char* path);
U0          vfs_cmd_rm(const char* path);

#endif // VFS_H
