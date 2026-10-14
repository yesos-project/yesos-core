#ifndef REDSEA_EML_H
#define REDSEA_EML_H

#include "types.h"

#define REDSEA_MAGIC_1           0x52454453 // "REDS"
#define REDSEA_MAGIC_2           0x454D4C32 // "EML2"
#define REDSEA_VERSION           4
#define REDSEA_MAX_FILENAME      224   // bytes incl. NUL: full paths up to 223 characters
#define REDSEA_DIR_ENTRIES_MAX   16384 // v4 (v3: 1024)
#define REDSEA_DIR_SECTORS       8192  // 16384 entries x 256 bytes = 4 MiB
#define REDSEA_V3_DIR_SECTORS    512   // 1024 entries (read only for migration)

#define REDSEA_FLAG_USED         0x0001
#define REDSEA_FLAG_READONLY     0x0002
#define REDSEA_FLAG_BOOT_KERNEL  0x0004
#define REDSEA_FLAG_DIR          0x0008
#define REDSEA_FLAG_SECURE_WIPE  0x0010
#define REDSEA_FLAG_ENCRYPTED    0x0020 // Vault ciphertext (see kernel/vault.c)

#define REDSEA_MAX_FREE_EXTENTS  4096

// 256-byte file descriptor (2 entries per 512-byte sector), formats v3 and v4
typedef struct {
    char name[REDSEA_MAX_FILENAME];
    U64  start_lba;
    U64  sector_count;
    U64  byte_size;
    U32  flags;
    U32  crc_euler;
} __attribute__((packed)) RedSeaFileEntry;

_Static_assert(sizeof(RedSeaFileEntry) == 256, "RedSea v3 entry must be 256 bytes");
_Static_assert(REDSEA_DIR_ENTRIES_MAX * sizeof(RedSeaFileEntry) == REDSEA_DIR_SECTORS * 512, "dir size");

// Legacy 64-byte descriptor of format v2 (32-byte names), read only for migration
#define REDSEA_V2_NAME 32
typedef struct {
    char name[REDSEA_V2_NAME];
    U64  start_lba;
    U64  sector_count;
    U64  byte_size;
    U32  flags;
    U32  crc_euler;
} __attribute__((packed)) RedSeaFileEntryV2;

// RedSea-EML Volume Superblock (Sector 1..15)
typedef struct {
    U32 magic1;                  // "REDS"
    U32 magic2;                  // "EML2"
    U32 version;                 // 2
    U32 sector_size;             // 512
    U64 total_sectors;           // Total partition sectors
    U64 root_dir_lba;            // Sector 16
    U64 root_dir_sectors;        // 48 sectors (384 entries)
    U64 data_area_lba;           // Sector 64
    U64 free_lba_ptr;            // Next available contiguous LBA / Watermark
    U64 total_files;             // Active files count
    char volume_label[32];       // "YESOS_EML_ROOT"
    U8   reserved[416];
} __attribute__((packed)) RedSeaSuperblock;

// Free-Extent Range Descriptor
typedef struct {
    U64 start_lba;
    U64 sector_count;
} RedSeaExtent;

typedef struct {
    Bool is_mounted;
    U8   drive;
    RedSeaSuperblock sb;
    RedSeaFileEntry entries[REDSEA_DIR_ENTRIES_MAX];
    U32  entry_count;            // slots in use range: [0, entry_count) - may contain free slots
    U32  used_count;             // entries actually in use
    RedSeaExtent free_extents[REDSEA_MAX_FREE_EXTENTS];
    U32  free_extent_count;
    U64  total_free_sectors;
} RedSeaVolume;

// RedSea-EML Core API
U0   redsea_eml_init(U0);
Bool redsea_eml_format(U8 drive, const char* label);
Bool redsea_eml_mount(U8 drive);
Bool redsea_eml_is_mounted(U0);
Bool redsea_eml_write_file(const char* name, const void* data, size_t size, U32 flags);
U8*  redsea_eml_read_file(const char* name, size_t* out_size);
Bool redsea_eml_delete_file(const char* name);
Bool redsea_eml_exists(const char* name);
U0   redsea_eml_list_files(U0);

// Snapshots (kernel/snapshot.c): entries may share extents; shared extents
// are never freed, wiped or overwritten in place. Entries under backup/ can
// only be created or removed while the snapshot module holds the writer flag.
Bool redsea_eml_link(const char* src, const char* dst, U32 set_flags, U32 clear_flags);
U0   redsea_eml_set_backup_writer(Bool on);
U32  redsea_eml_free_entries(U0);

// Consistency check (fsck). Structural checks always; with `check_data`
// every file is read and its CRC compared (the kernel's Barrett CRC64, or the
// legacy checksum of files injected by older host tools).
typedef struct {
    U32  errors;
    U32  warnings;
    U32  entries;
    U32  files;
    U32  dirs;
    U32  shared_extents;      // extents referenced by more than one entry (snapshots)
    U32  crc_ok;
    U32  crc_legacy;
    U32  crc_bad;
    U32  unreadable;
    U32  legacy_backup_files; // files in backup/ outside any snapshot
    U64  used_sectors;        // union of all used extents
    U64  free_sectors;
    U64  lost_sectors;        // neither used nor in the free map
    Bool data_checked;
    U64  duration_ms;
    char first_problem[160];
} RedSeaFsckReport;

Bool redsea_eml_fsck(Bool check_data, Bool verbose, RedSeaFsckReport* out);
const RedSeaFsckReport* redsea_eml_last_fsck(U0);
U0   redsea_eml_extent_refcounts(U16* refs);   // refs[i] = entries sharing entry i's extent
// Bulk operations for snapshots: link by source index without a barrier
// (the caller issues redsea_eml_barrier() once), and delete every entry whose
// name starts with `prefix`, freeing an extent only when no remaining entry
// references it, with one barrier at the end.
Bool redsea_eml_link_new(U32 src_idx, const char* dst, U32 set_flags, U32 clear_flags);
U32  redsea_eml_delete_prefix(const char* prefix);
U0   redsea_eml_barrier(U0);
RedSeaVolume* redsea_eml_get_volume(U0);

// Free-Extent Management & Coalescing API
U64  redsea_extent_alloc(U64 sec_count);
Bool redsea_extent_free(U64 start_lba, U64 sec_count);
Bool redsea_extent_free_secure(U64 start_lba, U64 sec_count, Bool wipe);
U0   redsea_eml_rebuild_free_extents(U0);
U0   redsea_eml_list_free_extents(U0);
U64  redsea_eml_get_free_sectors(U0);
U64  redsea_eml_get_largest_free_extent(U0);
Bool redsea_eml_test_free_extent(U0);

// Hierarchical Directory & Path-based API (TempleOS-style subdirectories)
Bool redsea_eml_mkdir(const char* dir_path);
Bool redsea_eml_write_file_path(const char* path, const void* data, size_t size, U32 flags);
U8*  redsea_eml_read_file_path(const char* path, size_t* out_size);
Bool redsea_eml_exists_path(const char* path);

// Persistence & RamFS Integration
Bool redsea_eml_sync_from_ramfs(U0);
Bool redsea_eml_load_to_ramfs(const char* name);
Bool redsea_eml_verify_barrett(const char* name, U64* crc_out);
U0   redsea_eml_benchmark(U0);

#endif // REDSEA_EML_H
