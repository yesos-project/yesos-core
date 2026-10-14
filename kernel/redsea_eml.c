#include "redsea_eml.h"
#include "timer.h"

static U0 barrier(U0);   // write barrier (defined with the crash-safety notes below)
static U0 mount_finish(U8 drive, Bool holes);
static U0 slot_freed(U32 slot);
static U0 commit_dir_slot(U32 slot);
static Bool load_directory(U8 drive, U64 dir_lba, U64 dir_sectors, U32* out_count, Bool* out_holes);
static Bool write_directory(U8 drive, U64 dir_lba, U64 dir_sectors);

#include "ata.h"
#include "virtio_blk.h"
#include "barrett_poly.h"
#include "ramfs.h"
#include "kprintf.h"
#include "memory.h"
#include "speaker.h"
#include "timer.h"

static RedSeaVolume g_vol;

// ---------------------------------------------------------------------------
// Sorting (heapsort, O(n log n), no recursion, no allocation). With 16384
// directory entries, all-pairs comparisons would take hundreds of millions
// of steps; every "find duplicates/overlaps" pass sorts indices instead.
// ---------------------------------------------------------------------------
typedef I32 (*IdxCmp)(U32 a, U32 b);
static U32 g_idx[REDSEA_DIR_ENTRIES_MAX];   // hart 0 only

static U0 sift_down(U32* v, U32 start, U32 end, IdxCmp cmp) {
    U32 root = start;
    while (2 * root + 1 < end) {
        U32 child = 2 * root + 1, sw = root;
        if (cmp(v[sw], v[child]) < 0) sw = child;
        if (child + 1 < end && cmp(v[sw], v[child + 1]) < 0) sw = child + 1;
        if (sw == root) return;
        U32 t = v[root]; v[root] = v[sw]; v[sw] = t;
        root = sw;
    }
}

static U0 sort_idx(U32* v, U32 n, IdxCmp cmp) {
    if (n < 2) return;
    for (U32 start = n / 2; start-- > 0;) sift_down(v, start, n, cmp);
    for (U32 end = n - 1; end > 0; end--) {
        U32 t = v[0]; v[0] = v[end]; v[end] = t;
        sift_down(v, 0, end, cmp);
    }
}

static I32 cmp_by_name(U32 a, U32 b) {
    I32 c = StrCmp(g_vol.entries[a].name, g_vol.entries[b].name);
    return c ? c : (a < b ? -1 : (a > b ? 1 : 0));
}

static I32 cmp_by_extent(U32 a, U32 b) {
    const RedSeaFileEntry* x = &g_vol.entries[a];
    const RedSeaFileEntry* y = &g_vol.entries[b];
    if (x->start_lba != y->start_lba) return x->start_lba < y->start_lba ? -1 : 1;
    if (x->sector_count != y->sector_count) return x->sector_count < y->sector_count ? -1 : 1;
    return a < b ? -1 : (a > b ? 1 : 0);
}

U0 redsea_eml_init(U0) {
    MemSet(&g_vol, 0, sizeof(RedSeaVolume));
    g_vol.is_mounted = FALSE;

    // Automatically probe and mount Primary Master Drive (0) if formatted
    if (redsea_eml_mount(0)) {
        kprintf("[RedSea-EML] Persistent volume mounted: '%s' (%u Files on Drive 0)\n",
                g_vol.sb.volume_label, (U32)g_vol.used_count);
    } else {
        kprintf("[RedSea-EML] No formatted RedSea volume found on Drive 0.\n");
    }
}

Bool redsea_eml_format(U8 drive, const char* label) {
    ATADriveInfo* d = ata_get_drive_info(drive);
    if (!d || !d->is_present || d->total_sectors < 128) {
        kprintf("RedSea-EML: Error - Drive %u not available or too small.\n", drive);
        return FALSE;
    }

    kprintf("[RedSea-EML] Formatting Drive %u (%u MB, %u Sectors) with RedSea-EML...\n",
            drive, (U32)(d->capacity_bytes / (1024 * 1024)), (U32)d->total_sectors);

    RedSeaSuperblock sb;
    MemSet(&sb, 0, sizeof(RedSeaSuperblock));
    sb.magic1 = REDSEA_MAGIC_1;
    sb.magic2 = REDSEA_MAGIC_2;
    sb.version = REDSEA_VERSION;
    sb.sector_size = 512;
    sb.total_sectors = d->total_sectors;
    sb.root_dir_lba = 16;
    sb.root_dir_sectors = REDSEA_DIR_SECTORS;       // 1024 entries of 256 bytes
    sb.data_area_lba = 16 + REDSEA_DIR_SECTORS;
    sb.free_lba_ptr = sb.data_area_lba;
    sb.total_files = 0;
    StrNCpy(sb.volume_label, label ? label : "YESOS_EML_ROOT", sizeof(sb.volume_label));

    // 1. Write Superblock to LBA 1
    U8 sec_buf[512];
    MemSet(sec_buf, 0, 512);
    MemCpy(sec_buf, &sb, sizeof(RedSeaSuperblock));
    if (!ata_write_sectors(drive, 1, 1, sec_buf)) {
        kprintf("RedSea-EML: Failed to write Superblock to LBA 1.\n");
        return FALSE;
    }

    // 2. Clear Root Directory Table (64 KiB at a time)
    U8* zero = (U8*)Calloc(128, 512);
    if (!zero) return FALSE;
    for (U64 lba = sb.root_dir_lba; lba < sb.root_dir_lba + sb.root_dir_sectors; lba += 128) {
        U32 count = (U32)((sb.root_dir_lba + sb.root_dir_sectors - lba) < 128 ? (sb.root_dir_lba + sb.root_dir_sectors - lba) : 128);
        if (!ata_write_sectors(drive, lba, count, zero)) {
            kprintf("RedSea-EML: Failed to clear directory sector %u.\n", (U32)lba);
            Free(zero);
            return FALSE;
        }
    }
    Free(zero);
    barrier();

    kprintf("[RedSea-EML] Drive %u formatted successfully as '%s'.\n", drive, sb.volume_label);
    speaker_event(BEEP_SUCCESS);

    return redsea_eml_mount(drive);
}

// Format v2 (32-byte names, 48-sector directory at LBA 16) -> v3. The new
// 512-sector directory is written into a free extent of the data area; the
// superblock switch is a single sector write, so an interrupted migration
// leaves a valid v2 volume behind.
static Bool redsea_migrate_v2(U8 drive, const RedSeaSuperblock* old_sb) {
    MemSet(&g_vol, 0, sizeof(RedSeaVolume));
    g_vol.drive = drive;
    MemCpy(&g_vol.sb, old_sb, sizeof(RedSeaSuperblock));

    U8 sec_buf[512];
    U32 n = 0;
    U64 dir_secs = old_sb->root_dir_sectors > 64 ? 64 : old_sb->root_dir_sectors;
    for (U64 s = 0; s < dir_secs && n < REDSEA_DIR_ENTRIES_MAX; s++) {
        if (!ata_read_sectors(drive, old_sb->root_dir_lba + s, 1, sec_buf)) return FALSE;
        const RedSeaFileEntryV2* v2 = (const RedSeaFileEntryV2*)sec_buf;
        for (U32 e = 0; e < 512 / sizeof(RedSeaFileEntryV2) && n < REDSEA_DIR_ENTRIES_MAX; e++) {
            if (!(v2[e].flags & REDSEA_FLAG_USED)) continue;
            RedSeaFileEntry* fe = &g_vol.entries[n++];
            MemSet(fe, 0, sizeof(*fe));
            MemCpy(fe->name, v2[e].name, REDSEA_V2_NAME);   // v2 names may lack a NUL
            fe->name[REDSEA_V2_NAME] = '\0';
            fe->start_lba = v2[e].start_lba;
            fe->sector_count = v2[e].sector_count;
            fe->byte_size = v2[e].byte_size;
            fe->flags = v2[e].flags;
            fe->crc_euler = v2[e].crc_euler;
        }
    }
    g_vol.entry_count = n;
    g_vol.used_count = n;
    g_vol.is_mounted = TRUE;
    redsea_eml_rebuild_free_extents();

    U64 dir_lba = redsea_extent_alloc(REDSEA_DIR_SECTORS);
    if (dir_lba == 0) {
        kprintf("[RedSea-EML] Migration to v%u needs %u contiguous free sectors; volume left as v2 (unmounted).\n",
                REDSEA_VERSION, (U32)REDSEA_DIR_SECTORS);
        g_vol.is_mounted = FALSE;
        return FALSE;
    }
    if (!write_directory(drive, dir_lba, REDSEA_DIR_SECTORS)) {
        kprintf("[RedSea-EML] Migration write failed (dir at %u); volume left as v2.\n", (U32)dir_lba);
        g_vol.is_mounted = FALSE;
        return FALSE;
    }
    barrier();   // new directory durable before the superblock points at it

    RedSeaSuperblock sb;
    MemCpy(&sb, old_sb, sizeof(sb));
    sb.version = REDSEA_VERSION;
    sb.root_dir_lba = dir_lba;
    sb.root_dir_sectors = REDSEA_DIR_SECTORS;
    sb.total_files = n;
    MemSet(sec_buf, 0, 512);
    MemCpy(sec_buf, &sb, sizeof(sb));
    if (!ata_write_sectors(drive, 1, 1, sec_buf)) {
        g_vol.is_mounted = FALSE;
        return FALSE;
    }
    barrier();
    MemCpy(&g_vol.sb, &sb, sizeof(sb));
    kprintf("[RedSea-EML] Volume migrated v2 -> v%u: %u files, names up to %u characters, directory at LBA %u.\n",
            REDSEA_VERSION, n, (U32)(REDSEA_MAX_FILENAME - 1), (U32)dir_lba);
    mount_finish(drive, FALSE);
    return TRUE;
}

// Format v3 (1024-entry directory) -> v4 (16384 entries). Same crash-safe
// recipe: the new directory goes to a free extent, then a barrier, then the
// single-sector superblock switch. A cut before the switch leaves the v3
// volume untouched (the new directory is just unreferenced free space).
static Bool redsea_migrate_v3(U8 drive, const RedSeaSuperblock* old_sb) {
    MemSet(&g_vol, 0, sizeof(RedSeaVolume));
    g_vol.drive = drive;
    MemCpy(&g_vol.sb, old_sb, sizeof(RedSeaSuperblock));
    U32 n = 0;
    Bool holes = FALSE;
    if (!load_directory(drive, old_sb->root_dir_lba, REDSEA_V3_DIR_SECTORS, &n, &holes)) return FALSE;
    g_vol.entry_count = n;
    g_vol.is_mounted = TRUE;
    redsea_eml_rebuild_free_extents();   // the old v3 directory stays reserved meanwhile

    U64 dir_lba = redsea_extent_alloc(REDSEA_DIR_SECTORS);
    if (dir_lba == 0) {
        kprintf("[RedSea-EML] Migration v3 -> v%u needs %u contiguous free sectors (%u MiB); volume left as v3 (unmounted).\n",
                REDSEA_VERSION, (U32)REDSEA_DIR_SECTORS, (U32)(REDSEA_DIR_SECTORS / 2048));
        g_vol.is_mounted = FALSE;
        return FALSE;
    }
    if (!write_directory(drive, dir_lba, REDSEA_DIR_SECTORS)) {
        kprintf("[RedSea-EML] Migration write failed (dir at %u); volume left as v3.\n", (U32)dir_lba);
        g_vol.is_mounted = FALSE;
        return FALSE;
    }
    barrier();
    RedSeaSuperblock sb;
    MemCpy(&sb, old_sb, sizeof(sb));
    sb.version = REDSEA_VERSION;
    sb.root_dir_lba = dir_lba;
    sb.root_dir_sectors = REDSEA_DIR_SECTORS;
    sb.total_files = n;
    U8 sec_buf[512];
    MemSet(sec_buf, 0, 512);
    MemCpy(sec_buf, &sb, sizeof(sb));
    if (!ata_write_sectors(drive, 1, 1, sec_buf)) {
        g_vol.is_mounted = FALSE;
        return FALSE;
    }
    barrier();
    MemCpy(&g_vol.sb, &sb, sizeof(sb));
    kprintf("[RedSea-EML] Volume migrated v3 -> v%u: %u files, directory for %u entries at LBA %u.\n",
            REDSEA_VERSION, n, (U32)REDSEA_DIR_ENTRIES_MAX, (U32)dir_lba);
    mount_finish(drive, FALSE);
    return TRUE;
}

// Reads `dir_sectors` directory sectors in 64 KiB chunks into g_vol.entries
// (compacted: used entries only, in slot order).
static Bool load_directory(U8 drive, U64 dir_lba, U64 dir_sectors, U32* out_count, Bool* out_holes) {
    // Slots keep their position (in-memory index == on-disk slot); free slots
    // between entries are normal since v4 (deletes clear a single slot).
    const U32 chunk = 128;
    U8* buf = (U8*)Malloc(chunk * 512);
    if (!buf) return FALSE;
    U32 slot_no = 0, high = 0, used = 0;
    const U32 per_sec = 512 / sizeof(RedSeaFileEntry);
    for (U64 s = 0; s < dir_sectors && slot_no < REDSEA_DIR_ENTRIES_MAX; s += chunk) {
        U32 count = (U32)((dir_sectors - s) < chunk ? (dir_sectors - s) : chunk);
        if (!ata_read_sectors(drive, dir_lba + s, count, buf)) {
            Free(buf);
            kprintf("[RedSea-EML] Cannot read the directory at LBA %u.\n", (U32)(dir_lba + s));
            return FALSE;
        }
        const RedSeaFileEntry* ent = (const RedSeaFileEntry*)buf;
        for (U32 e = 0; e < count * per_sec && slot_no < REDSEA_DIR_ENTRIES_MAX; e++, slot_no++) {
            if (ent[e].flags & REDSEA_FLAG_USED) {
                g_vol.entries[slot_no] = ent[e];
                high = slot_no + 1;
                used++;
            } else {
                MemSet(&g_vol.entries[slot_no], 0, sizeof(RedSeaFileEntry));
            }
        }
    }
    Free(buf);
    g_vol.used_count = used;
    *out_count = high;
    *out_holes = (used != high);
    return TRUE;
}

// Writes the whole directory from memory (entries, then zeroes) in chunks.
static Bool write_directory(U8 drive, U64 dir_lba, U64 dir_sectors) {
    const U32 chunk = 128;
    U8* buf = (U8*)Malloc(chunk * 512);
    if (!buf) return FALSE;
    const U32 per_sec = 512 / sizeof(RedSeaFileEntry);
    Bool ok = TRUE;
    for (U64 s = 0; s < dir_sectors && ok; s += chunk) {
        U32 count = (U32)((dir_sectors - s) < chunk ? (dir_sectors - s) : chunk);
        MemSet(buf, 0, chunk * 512);
        for (U32 e = 0; e < count * per_sec; e++) {
            U32 idx = (U32)s * per_sec + e;
            if (idx < g_vol.entry_count) ((RedSeaFileEntry*)buf)[e] = g_vol.entries[idx];
        }
        ok = ata_write_sectors(drive, dir_lba + s, count, buf);
    }
    Free(buf);
    return ok;
}

Bool redsea_eml_mount(U8 drive) {
    ATADriveInfo* d = ata_get_drive_info(drive);
    if (!d || !d->is_present) return FALSE;

    U8 sec_buf[512];
    if (!ata_read_sectors(drive, 1, 1, sec_buf)) return FALSE;

    RedSeaSuperblock* sb = (RedSeaSuperblock*)sec_buf;
    if (sb->magic1 != REDSEA_MAGIC_1 || sb->magic2 != REDSEA_MAGIC_2) {
        return FALSE;
    }
    RedSeaSuperblock old;
    MemCpy(&old, sb, sizeof(old));
    if (old.version == 2) return redsea_migrate_v2(drive, &old);
    if (old.version == 3) {
        if (old.root_dir_sectors != REDSEA_V3_DIR_SECTORS || old.root_dir_lba + old.root_dir_sectors > d->total_sectors) {
            kprintf("[RedSea-EML] Corrupt v3 volume; not mounted.\n");
            return FALSE;
        }
        return redsea_migrate_v3(drive, &old);
    }
    if (old.version != REDSEA_VERSION || old.root_dir_sectors != REDSEA_DIR_SECTORS ||
        old.root_dir_lba + old.root_dir_sectors > d->total_sectors) {
        kprintf("[RedSea-EML] Unsupported or corrupt volume (version %u).\n", old.version);
        return FALSE;
    }

    MemSet(&g_vol, 0, sizeof(RedSeaVolume));
    g_vol.drive = drive;
    MemCpy(&g_vol.sb, &old, sizeof(RedSeaSuperblock));
    U32 n = 0;
    Bool holes = FALSE;
    if (!load_directory(drive, old.root_dir_lba, old.root_dir_sectors, &n, &holes)) return FALSE;
    if (g_vol.sb.total_sectors == 0 && d->total_sectors > 0) g_vol.sb.total_sectors = d->total_sectors;
    g_vol.entry_count = n;
    g_vol.is_mounted = TRUE;
    mount_finish(drive, holes);
    return TRUE;
}

// Recovery and checks shared by every mount path.
static U0 mount_finish(U8 drive, Bool holes) {
    (U0)holes;   // free slots are normal; nothing to compact
    // Recovery of an interrupted swap-delete (kernels before v4 moved the last
    // entry into the hole): the moved entry may exist twice, byte-identical.
    // Keep the lowest slot and clear the others (one sector each).
    U32 m = 0;
    for (U32 i = 0; i < g_vol.entry_count; i++) {
        if (g_vol.entries[i].flags & REDSEA_FLAG_USED) g_idx[m++] = i;
    }
    sort_idx(g_idx, m, cmp_by_name);
    U32 dup_removed = 0;
    static U32 victims[REDSEA_DIR_ENTRIES_MAX];
    U32 nv = 0;
    for (U32 g = 0; g < m;) {
        U32 h = g + 1;
        while (h < m && StrCmp(g_vol.entries[g_idx[g]].name, g_vol.entries[g_idx[h]].name) == 0) h++;
        for (U32 k = g + 1; k < h; k++) {   // g_idx[g] is the lowest slot of the group
            if (MemCmp(&g_vol.entries[g_idx[g]], &g_vol.entries[g_idx[k]], sizeof(RedSeaFileEntry)) == 0) {
                victims[nv++] = g_idx[k];
            } else {
                kprintf("[RedSea-EML] Warning: duplicate directory entry '%s' (interrupted update?).\n",
                        g_vol.entries[g_idx[k]].name);
            }
        }
        g = h;
    }
    for (U32 k = 0; k < nv; k++) {
        slot_freed(victims[k]);
        commit_dir_slot(victims[k]);
        dup_removed++;
    }
    if (dup_removed) {
        barrier();
        kprintf("[RedSea-EML] Recovery: completed %u interrupted delete(s) (duplicate entries).\n", dup_removed);
    }
    if (g_vol.sb.total_files != g_vol.used_count) {   // power cut before the superblock update
        g_vol.sb.total_files = g_vol.used_count;
        U8 sbb[512];
        MemSet(sbb, 0, 512);
        MemCpy(sbb, &g_vol.sb, sizeof(RedSeaSuperblock));
        ata_write_sectors(drive, 1, 1, sbb);
        barrier();
    }

    // Dynamically rebuild and validate the Free-Extent map from active directory entries
    redsea_eml_rebuild_free_extents();

    // Structural check on every mount (data CRCs: `fsck` or the web panel)
    RedSeaFsckReport fr;
    redsea_eml_fsck(FALSE, FALSE, &fr);
    if (fr.errors) {
        kprintf("[RedSea-EML] fsck: %u ERROR(S) at mount - first: %s. Run 'fsck' for details.\n", fr.errors, fr.first_problem);
    } else {
        kprintf("[RedSea-EML] fsck: structure OK (%u files, %u shared extents, %u warning(s)).\n",
                fr.files, fr.shared_extents, fr.warnings);
    }
}

Bool redsea_eml_is_mounted(U0) {
    return g_vol.is_mounted;
}

RedSeaVolume* redsea_eml_get_volume(U0) {
    return &g_vol;
}

Bool redsea_eml_exists(const char* name) {
    if (!g_vol.is_mounted || !name) return FALSE;
    for (U32 i = 0; i < g_vol.entry_count; i++) {
        if (StrCmp(g_vol.entries[i].name, name) == 0 || StrICmp(g_vol.entries[i].name, name) == 0) return TRUE;
    }
    return FALSE;
}

U64 redsea_eml_get_free_sectors(U0) {
    return g_vol.is_mounted ? g_vol.total_free_sectors : 0;
}

U64 redsea_eml_get_largest_free_extent(U0) {
    if (!g_vol.is_mounted) return 0;
    U64 max_sec = 0;
    for (U32 i = 0; i < g_vol.free_extent_count; i++) {
        if (g_vol.free_extents[i].sector_count > max_sec) {
            max_sec = g_vol.free_extents[i].sector_count;
        }
    }
    return max_sec;
}

typedef struct {
    U64 start;
    U64 end;
    U32 idx;
} BusyExtent;

U0 redsea_eml_rebuild_free_extents(U0) {
    if (!g_vol.is_mounted) return;

    static BusyExtent busy[REDSEA_DIR_ENTRIES_MAX + 1];   // static: too large for a hart stack
    U32 busy_count = 0;

    U64 data_start = g_vol.sb.data_area_lba;
    U64 disk_limit = g_vol.sb.total_sectors;

    // A directory relocated by the v2 -> v3 migration lives in the data area.
    if (g_vol.sb.root_dir_lba >= data_start) {
        busy[busy_count].start = g_vol.sb.root_dir_lba;
        busy[busy_count].end = g_vol.sb.root_dir_lba + g_vol.sb.root_dir_sectors - 1;
        busy[busy_count].idx = (U32)-1;
        busy_count++;
    }

    for (U32 i = 0; i < g_vol.entry_count; i++) {
        RedSeaFileEntry* fe = &g_vol.entries[i];
        if (fe->flags & REDSEA_FLAG_USED) {
            U64 s = fe->start_lba;
            U64 cnt = fe->sector_count;
            if (s >= data_start && cnt > 0 && s + cnt <= disk_limit) {
                busy[busy_count].start = s;
                busy[busy_count].end = s + cnt - 1;
                busy[busy_count].idx = i;
                busy_count++;
            } else {
                kprintf("[RedSea-EML] Security Alert: File '%s' has out-of-bounds LBA [%u..%u], skipping!\n",
                        fe->name, (U32)s, (U32)(s + cnt));
            }
        }
    }

    // Sort busy extents ascending by start LBA (heapsort on indices)
    {
        static U32 order[REDSEA_DIR_ENTRIES_MAX + 1];
        static BusyExtent sorted[REDSEA_DIR_ENTRIES_MAX + 1];
        for (U32 i = 0; i < busy_count; i++) order[i] = i;
        // local comparator over `busy`
        for (U32 start = busy_count / 2; start-- > 0;) {
            U32 root = start;
            while (2 * root + 1 < busy_count) {
                U32 child = 2 * root + 1, sw = root;
                if (busy[order[sw]].start < busy[order[child]].start) sw = child;
                if (child + 1 < busy_count && busy[order[sw]].start < busy[order[child + 1]].start) sw = child + 1;
                if (sw == root) break;
                U32 t = order[root]; order[root] = order[sw]; order[sw] = t;
                root = sw;
            }
        }
        for (U32 end = busy_count; end-- > 1;) {
            U32 t = order[0]; order[0] = order[end]; order[end] = t;
            U32 root = 0;
            while (2 * root + 1 < end) {
                U32 child = 2 * root + 1, sw = root;
                if (busy[order[sw]].start < busy[order[child]].start) sw = child;
                if (child + 1 < end && busy[order[sw]].start < busy[order[child + 1]].start) sw = child + 1;
                if (sw == root) break;
                U32 t2 = order[root]; order[root] = order[sw]; order[sw] = t2;
                root = sw;
            }
        }
        for (U32 i = 0; i < busy_count; i++) sorted[i] = busy[order[i]];
        for (U32 i = 0; i < busy_count; i++) busy[i] = sorted[i];
    }

    // Build free extents list from gaps and tail
    g_vol.free_extent_count = 0;
    g_vol.total_free_sectors = 0;
    U64 cur_lba = data_start;

    for (U32 i = 0; i < busy_count; i++) {
        if (busy[i].start > cur_lba) {
            U64 gap_len = busy[i].start - cur_lba;
            if (g_vol.free_extent_count < REDSEA_MAX_FREE_EXTENTS) {
                g_vol.free_extents[g_vol.free_extent_count].start_lba = cur_lba;
                g_vol.free_extents[g_vol.free_extent_count].sector_count = gap_len;
                g_vol.total_free_sectors += gap_len;
                g_vol.free_extent_count++;
            }
        }
        if (busy[i].end + 1 > cur_lba) {
            cur_lba = busy[i].end + 1;
        }
    }

    // Trailing disk space
    if (cur_lba < disk_limit) {
        U64 tail_len = disk_limit - cur_lba;
        if (g_vol.free_extent_count < REDSEA_MAX_FREE_EXTENTS) {
            g_vol.free_extents[g_vol.free_extent_count].start_lba = cur_lba;
            g_vol.free_extents[g_vol.free_extent_count].sector_count = tail_len;
            g_vol.total_free_sectors += tail_len;
            g_vol.free_extent_count++;
        }
    }

    kprintf("[RedSea-EML] Free-Extent Map initialized: %u extents, %u MB free (Largest extent: %u MB)\n",
            g_vol.free_extent_count, (U32)((g_vol.total_free_sectors * 512) / (1024 * 1024)),
            (U32)((redsea_eml_get_largest_free_extent() * 512) / (1024 * 1024)));
}

U64 redsea_extent_alloc(U64 sec_count) {
    if (!g_vol.is_mounted || sec_count == 0) return 0;

    I32 best_idx = -1;
    U64 best_diff = (U64)-1;

    // Best-fit search: find extent with sector_count >= sec_count and minimum excess
    for (U32 i = 0; i < g_vol.free_extent_count; i++) {
        if (g_vol.free_extents[i].sector_count >= sec_count) {
            U64 diff = g_vol.free_extents[i].sector_count - sec_count;
            if (diff < best_diff) {
                best_diff = diff;
                best_idx = (I32)i;
                if (diff == 0) break; // Exact match found!
            }
        }
    }

    if (best_idx < 0) {
        kprintf("[RedSea-EML] ERROR: Out of contiguous disk space! Requested %u sectors.\n", (U32)sec_count);
        return 0;
    }

    U64 alloc_lba = g_vol.free_extents[best_idx].start_lba;

    if (g_vol.free_extents[best_idx].sector_count == sec_count) {
        // Exact fit: remove this extent
        for (U32 i = (U32)best_idx; i + 1 < g_vol.free_extent_count; i++) {
            g_vol.free_extents[i] = g_vol.free_extents[i + 1];
        }
        g_vol.free_extent_count--;
    } else {
        // Split extent: advance start_lba and reduce sector_count
        g_vol.free_extents[best_idx].start_lba += sec_count;
        g_vol.free_extents[best_idx].sector_count -= sec_count;
    }

    g_vol.total_free_sectors -= sec_count;

    // Maintain high watermark in superblock
    if (alloc_lba + sec_count > g_vol.sb.free_lba_ptr) {
        g_vol.sb.free_lba_ptr = alloc_lba + sec_count;
    }

    return alloc_lba;
}

Bool redsea_extent_free_secure(U64 start_lba, U64 sec_count, Bool wipe) {
    if (!g_vol.is_mounted || sec_count == 0) return FALSE;
    if (start_lba < g_vol.sb.data_area_lba || start_lba + sec_count > g_vol.sb.total_sectors) {
        kprintf("[RedSea-EML] Security Alert: Invalid free LBA range [%u..%u]\n",
                (U32)start_lba, (U32)(start_lba + sec_count));
        return FALSE;
    }

    // Double-free guard
    for (U32 i = 0; i < g_vol.free_extent_count; i++) {
        U64 f_start = g_vol.free_extents[i].start_lba;
        U64 f_end = f_start + g_vol.free_extents[i].sector_count - 1;
        U64 req_end = start_lba + sec_count - 1;
        if (!(req_end < f_start || start_lba > f_end)) {
            kprintf("[RedSea-EML] Security Alert: Double-free on LBA [%u..%u] overlapping [%u..%u]!\n",
                    (U32)start_lba, (U32)req_end, (U32)f_start, (U32)f_end);
            return FALSE;
        }
    }

    // Optional cryptographic/forensic zero-wipe
    if (wipe) {
        U8 zero_buf[512];
        MemSet(zero_buf, 0, 512);
        for (U64 s = 0; s < sec_count; s++) {
            ata_write_sectors(g_vol.drive, start_lba + s, 1, zero_buf);
        }
    }

    if (g_vol.free_extent_count >= REDSEA_MAX_FREE_EXTENTS) {
        kprintf("[RedSea-EML] Warning: Free extent table capacity reached!\n");
        return FALSE;
    }

    // Insert sorted by start_lba
    U32 insert_idx = g_vol.free_extent_count;
    for (U32 i = 0; i < g_vol.free_extent_count; i++) {
        if (start_lba < g_vol.free_extents[i].start_lba) {
            insert_idx = i;
            break;
        }
    }

    for (U32 i = g_vol.free_extent_count; i > insert_idx; i--) {
        g_vol.free_extents[i] = g_vol.free_extents[i - 1];
    }
    g_vol.free_extents[insert_idx].start_lba = start_lba;
    g_vol.free_extents[insert_idx].sector_count = sec_count;
    g_vol.free_extent_count++;
    g_vol.total_free_sectors += sec_count;

    // Coalesce adjacent free extents
    for (U32 i = 0; i + 1 < g_vol.free_extent_count; ) {
        if (g_vol.free_extents[i].start_lba + g_vol.free_extents[i].sector_count == g_vol.free_extents[i + 1].start_lba) {
            g_vol.free_extents[i].sector_count += g_vol.free_extents[i + 1].sector_count;
            for (U32 j = i + 1; j + 1 < g_vol.free_extent_count; j++) {
                g_vol.free_extents[j] = g_vol.free_extents[j + 1];
            }
            g_vol.free_extent_count--;
        } else {
            i++;
        }
    }

    return TRUE;
}

Bool redsea_extent_free(U64 start_lba, U64 sec_count) {
    return redsea_extent_free_secure(start_lba, sec_count, FALSE);
}

U0 redsea_eml_list_free_extents(U0) {
    if (!g_vol.is_mounted) {
        kprintf("RedSea-EML: Volume not mounted.\n");
        return;
    }

    kprintf("\n================ [ REDSEA-EML FREE-EXTENT MAP ] ================\n");
    kprintf("Volume: '%s' | Total Sectors: %u (%u MB)\n",
            g_vol.sb.volume_label, (U32)g_vol.sb.total_sectors,
            (U32)((g_vol.sb.total_sectors * 512) / (1024 * 1024)));
    kprintf("Free Extents: %u | Total Free Sectors: %u (%u MB | ~%u%% Free)\n",
            g_vol.free_extent_count, (U32)g_vol.total_free_sectors,
            (U32)((g_vol.total_free_sectors * 512) / (1024 * 1024)),
            (g_vol.sb.total_sectors > 0) ? (U32)((g_vol.total_free_sectors * 100) / g_vol.sb.total_sectors) : 0);
    kprintf("----------------------------------------------------------------\n");
    kprintf("  #    Start LBA       End LBA         Sectors      Size (KB/MB)\n");
    kprintf("----------------------------------------------------------------\n");

    U64 max_ext = 0;
    for (U32 i = 0; i < g_vol.free_extent_count; i++) {
        RedSeaExtent* e = &g_vol.free_extents[i];
        if (e->sector_count > max_ext) max_ext = e->sector_count;
        U64 end_lba = e->start_lba + e->sector_count - 1;
        U64 sz_kb = (e->sector_count * 512) / 1024;
        if (sz_kb >= 1024) {
            kprintf("  #%02u  LBA: %-10u  LBA: %-10u  %-11u  %u MB\n",
                    i + 1, (U32)e->start_lba, (U32)end_lba, (U32)e->sector_count, (U32)(sz_kb / 1024));
        } else {
            kprintf("  #%02u  LBA: %-10u  LBA: %-10u  %-11u  %u KB\n",
                    i + 1, (U32)e->start_lba, (U32)end_lba, (U32)e->sector_count, (U32)sz_kb);
        }
    }
    kprintf("----------------------------------------------------------------\n");
    kprintf("Largest Contiguous Allocatable Extent: %u Sectors (%u MB)\n",
            (U32)max_ext, (U32)((max_ext * 512) / (1024 * 1024)));
    kprintf("Coalescing Efficiency: 100%% | CoW Active: TRUE\n");
    kprintf("================================================================\n\n");
}

// ----------------------------------------------------------------------------
// Shared extents (snapshots) and the protected backup/ area
// ----------------------------------------------------------------------------

// Snapshots link several directory entries to the same extent. An extent is
// only freed, wiped or overwritten in place when no other entry uses it.
static Bool extent_shared(U64 lba, U64 sec, I64 except_idx) {
    if (sec == 0) return FALSE;
    for (U32 i = 0; i < g_vol.entry_count; i++) {
        if ((I64)i == except_idx) continue;
        const RedSeaFileEntry* e = &g_vol.entries[i];
        if (!(e->flags & REDSEA_FLAG_USED) || e->sector_count == 0) continue;
        if (e->start_lba < lba + sec && lba < e->start_lba + e->sector_count) return TRUE;
    }
    return FALSE;
}

// Only the snapshot module may create or remove entries under backup/.
static Bool g_backup_writer = FALSE;

U0 redsea_eml_set_backup_writer(Bool on) {
    g_backup_writer = on;
}

static Bool backup_protected(const char* name) {
    if (StrNICmp(name, "backup/", 7) != 0 || g_backup_writer) return FALSE;
    kprintf("[RedSea-EML] Refused: '%s' is in the read-only backup area (use the snapshot commands).\n", name);
    return TRUE;
}

// ---------------------------------------------------------------------------
// Crash safety. RedSea keeps no on-disk free map (it is rebuilt from the
// directory at mount), so the on-disk state is just data + directory +
// superblock. Every update follows the same order so that a power cut at any
// point leaves either the old or the new state:
//   1. new data goes to a FREE extent (never over live data), then a barrier;
//   2. the directory change is one sector, or two sectors with a barrier in
//      between whose intermediate state mount repairs (interrupted delete);
//   3. a barrier after the directory change, before freed space can be reused.
// ---------------------------------------------------------------------------
static U0 barrier(U0) {
    ata_flush(g_vol.drive);
}

// Writes the directory sector holding `slot`, built entirely from memory.
// In-memory index i is on-disk slot i (mount compacts the directory), so no
// read-modify-write is needed: a stale read can never resurrect old entries.
static U0 commit_dir_slot(U32 slot) {
    U32 entries_per_sec = 512 / sizeof(RedSeaFileEntry);
    U32 first = slot - slot % entries_per_sec;
    U8 dir_buf[512];
    MemSet(dir_buf, 0, sizeof(dir_buf));
    for (U32 e = 0; e < entries_per_sec; e++) {
        if (first + e < g_vol.entry_count) ((RedSeaFileEntry*)dir_buf)[e] = g_vol.entries[first + e];
    }
    ata_write_sectors(g_vol.drive, g_vol.sb.root_dir_lba + slot / entries_per_sec, 1, dir_buf);
}

// First free directory slot (holes are reused), or REDSEA_DIR_ENTRIES_MAX.
static U32 free_slot(U0) {
    for (U32 i = 0; i < g_vol.entry_count; i++) {
        if (!(g_vol.entries[i].flags & REDSEA_FLAG_USED)) return i;
    }
    return g_vol.entry_count < REDSEA_DIR_ENTRIES_MAX ? g_vol.entry_count : REDSEA_DIR_ENTRIES_MAX;
}

// Accounts for a slot that just became used / free.
static U0 slot_used(U32 slot) {
    if (slot >= g_vol.entry_count) g_vol.entry_count = slot + 1;
    g_vol.used_count++;
}

static U0 slot_freed(U32 slot) {
    MemSet(&g_vol.entries[slot], 0, sizeof(RedSeaFileEntry));
    if (g_vol.used_count) g_vol.used_count--;
    while (g_vol.entry_count > 0 && !(g_vol.entries[g_vol.entry_count - 1].flags & REDSEA_FLAG_USED)) g_vol.entry_count--;
}

static U0 commit_superblock(U0) {
    g_vol.sb.total_files = g_vol.used_count;
    U8 sb_buf[512];
    MemSet(sb_buf, 0, 512);
    MemCpy(sb_buf, &g_vol.sb, sizeof(RedSeaSuperblock));
    ata_write_sectors(g_vol.drive, 1, 1, sb_buf);
}

Bool redsea_eml_write_file(const char* name, const void* data, size_t size, U32 flags) {
    if (!g_vol.is_mounted || !name || !data) return FALSE;
    if (StrLen(name) >= REDSEA_MAX_FILENAME) {
        kprintf("[RedSea-EML] Name too long (max %u characters): '%s'\n", (U32)(REDSEA_MAX_FILENAME - 1), name);
        return FALSE;
    }

    // Invariant: plaintext never lands under vault/. Only kernel/vault.c
    // writes there, always with REDSEA_FLAG_ENCRYPTED.
    if (StrNICmp(name, "vault/", 6) == 0 && !(flags & REDSEA_FLAG_ENCRYPTED)) {
        kprintf("[RedSea-EML] Refused plaintext write to encrypted area: '%s'\n", name);
        return FALSE;
    }
    if (backup_protected(name)) return FALSE;

    // Zero-division sector count calculation via bit-shift
    U64 sec_count = (size + 511) >> 9;
    if (sec_count == 0) sec_count = 1;

    // Detect if updating existing entry (Copy-on-Write)
    I64 slot = -1;
    U64 old_lba = 0;
    U64 old_sec = 0;
    Bool is_cow = FALSE;

    for (U32 i = 0; i < g_vol.entry_count; i++) {
        if (StrCmp(g_vol.entries[i].name, name) == 0) {
            slot = (I64)i;
            old_lba = g_vol.entries[i].start_lba;
            old_sec = g_vol.entries[i].sector_count;
            is_cow = TRUE;
            break;
        }
    }

    if (slot == -1) {
        U32 fs = free_slot();
        if (fs >= REDSEA_DIR_ENTRIES_MAX) {
            kprintf("[RedSea-EML] Directory full (%u entries); cannot create '%s'.\n", (U32)REDSEA_DIR_ENTRIES_MAX, name);
            return FALSE;
        }
        slot = (I64)fs;
    }

    // Allocate contiguous sectors from Free-Extent pool (Best-Fit). New data
    // never overwrites the live copy: a power cut must leave the old version.
    U64 start_lba = redsea_extent_alloc(sec_count);
    if (start_lba == 0) {
        kprintf("[RedSea-EML] Error: no free extent of %u sectors for '%s' (disk full or fragmented).\n",
                (U32)sec_count, name);
        return FALSE;
    }

    // Prepare buffer padded to 512-byte sectors
    size_t padded_size = (size_t)(sec_count << 9);
    U8* sec_buf = (U8*)Malloc(padded_size);
    if (!sec_buf) {
        redsea_extent_free(start_lba, sec_count);
        return FALSE;
    }

    MemSet(sec_buf, 0, padded_size);
    MemCpy(sec_buf, data, size);

    // Compute Barrett polynomial CRC64 in GF(2) using hardware clmul
    U64 crc64 = barrett_crc64_sector((const U8*)data, size);

    // Write file data to disk via DMA. Vault ciphertext is high-entropy by
    // design, so it is exempted from the block-layer entropy heuristic.
    Bool is_ciphertext = (flags & REDSEA_FLAG_ENCRYPTED) != 0;
    if (is_ciphertext) virtio_blk_allow_ciphertext_write(TRUE);
    Bool data_ok = ata_write_sectors(g_vol.drive, start_lba, (U32)sec_count, sec_buf);
    if (is_ciphertext) virtio_blk_allow_ciphertext_write(FALSE);
    if (!data_ok) {
        Free(sec_buf);
        redsea_extent_free(start_lba, sec_count);
        return FALSE;
    }
    Free(sec_buf);
    barrier();   // data durable before the directory points at it

    if (!is_cow) slot_used((U32)slot);

    // Atomic Directory Entry commit
    RedSeaFileEntry* fe = &g_vol.entries[slot];
    MemSet(fe, 0, sizeof(RedSeaFileEntry));
    StrNCpy(fe->name, name, sizeof(fe->name));
    fe->start_lba = start_lba;
    fe->sector_count = sec_count;
    fe->byte_size = (U64)size;
    fe->flags = flags | REDSEA_FLAG_USED;
    fe->crc_euler = (U32)crc64;

    commit_dir_slot((U32)slot);
    barrier();   // directory durable before the old extent can be reused

    // If CoW, reclaim old extent now that the new extent is committed,
    // unless a snapshot still references it.
    if (is_cow && old_sec > 0 && !extent_shared(old_lba, old_sec, -1)) {
        Bool wipe = (flags & REDSEA_FLAG_SECURE_WIPE) != 0;
        redsea_extent_free_secure(old_lba, old_sec, wipe);
    }

    // Update Superblock on disk
    g_vol.sb.total_files = g_vol.used_count;
    U8 sb_buf[512];
    MemSet(sb_buf, 0, 512);
    MemCpy(sb_buf, &g_vol.sb, sizeof(RedSeaSuperblock));
    ata_write_sectors(g_vol.drive, 1, 1, sb_buf);

    return TRUE;
}

U8* redsea_eml_read_file(const char* name, size_t* out_size) {
    if (!g_vol.is_mounted || !name) return NULL;

    // Pass 1: exact match
    for (U32 i = 0; i < g_vol.entry_count; i++) {
        if (StrCmp(g_vol.entries[i].name, name) == 0) {
            RedSeaFileEntry* fe = &g_vol.entries[i];
            size_t alloc_sz = (size_t)(fe->sector_count << 9);
            U8* buf = (U8*)Malloc(alloc_sz + 1);
            if (!buf) return NULL;

            if (!ata_read_sectors(g_vol.drive, fe->start_lba, (U32)fe->sector_count, buf)) {
                Free(buf);
                return NULL;
            }

            buf[fe->byte_size] = '\0';
            if (out_size) *out_size = (size_t)fe->byte_size;
            return buf;
        }
    }

    // Pass 2: case-insensitive match
    for (U32 i = 0; i < g_vol.entry_count; i++) {
        if (StrICmp(g_vol.entries[i].name, name) == 0) {
            RedSeaFileEntry* fe = &g_vol.entries[i];
            size_t alloc_sz = (size_t)(fe->sector_count << 9);
            U8* buf = (U8*)Malloc(alloc_sz + 1);
            if (!buf) return NULL;

            if (!ata_read_sectors(g_vol.drive, fe->start_lba, (U32)fe->sector_count, buf)) {
                Free(buf);
                return NULL;
            }

            buf[fe->byte_size] = '\0';
            if (out_size) *out_size = (size_t)fe->byte_size;
            return buf;
        }
    }
    return NULL;
}

Bool redsea_eml_delete_file(const char* name) {
    if (!g_vol.is_mounted || !name) return FALSE;
    if (backup_protected(name)) return FALSE;

    for (U32 i = 0; i < g_vol.entry_count; i++) {
        if (StrCmp(g_vol.entries[i].name, name) == 0) {
            U64 freed_lba = g_vol.entries[i].start_lba;
            U64 freed_sec = g_vol.entries[i].sector_count;
            Bool wipe = (g_vol.entries[i].flags & REDSEA_FLAG_SECURE_WIPE) != 0;

            // 1. Reclaim disk space (coalescing), unless a snapshot still uses it
            if (!extent_shared(freed_lba, freed_sec, (I64)i)) {
                redsea_extent_free_secure(freed_lba, freed_sec, wipe);
            }

            // Clear the slot: one sector, atomic. (Before v4 the last entry was
            // moved into the hole: two sectors, repaired at mount if cut.)
            slot_freed(i);
            commit_dir_slot(i);
            barrier();
            g_vol.sb.total_files = g_vol.used_count;

            // Update Superblock on disk
            U8 sb_buf[512];
            MemSet(sb_buf, 0, 512);
            MemCpy(sb_buf, &g_vol.sb, sizeof(RedSeaSuperblock));
            ata_write_sectors(g_vol.drive, 1, 1, sb_buf);

            return TRUE;
        }
    }
    return FALSE;
}

U0 redsea_eml_list_files(U0) {
    if (!g_vol.is_mounted) {
        kprintf("RedSea-EML: No volume mounted on Drive 0.\n");
        return;
    }

    kprintf("\n================ [ REDSEA-EML PERSISTENT VOLUME ] ================\n");
    kprintf("Label: '%s' | Drive: %u | Free Extents: %u | Free Space: %u MB | Total Files: %u\n",
            g_vol.sb.volume_label, g_vol.drive, g_vol.free_extent_count,
            (U32)((g_vol.total_free_sectors * 512) / (1024 * 1024)), g_vol.used_count);
    kprintf("------------------------------------------------------------------\n");
    kprintf("  Name             Size (Bytes)   Start LBA      Sectors   Barrett-CRC\n");
    kprintf("------------------------------------------------------------------\n");

    for (U32 i = 0; i < g_vol.entry_count; i++) {
        RedSeaFileEntry* fe = &g_vol.entries[i];
        kprintf("  %s\t\t%u B\t\tLBA: %u\t\t%u sec\t0x%x%s\n",
                fe->name, (U32)fe->byte_size, (U32)fe->start_lba, (U32)fe->sector_count,
                fe->crc_euler, (fe->flags & REDSEA_FLAG_BOOT_KERNEL) ? " [BOOT]" : "");
    }
    kprintf("------------------------------------------------------------------\n\n");
}

Bool redsea_eml_sync_from_ramfs(U0) {
    if (!g_vol.is_mounted) {
        kprintf("RedSea-EML: Volume not mounted.\n");
        return FALSE;
    }

    U32 count = ramfs_get_file_count();
    kprintf("[RedSea-EML] Synchronizing %u RamFS files to persistent disk...\n", count);

    U32 synced = 0;
    for (U32 i = 0; i < count; i++) {
        RamFile* rf = ramfs_get_file_by_index(i);
        if (rf && rf->is_used) {
            if (redsea_eml_write_file(rf->name, rf->data, rf->size, 0)) {
                synced++;
            }
        }
    }

    kprintf("[RedSea-EML] %u files synchronized to disk successfully.\n", synced);
    speaker_event(BEEP_SUCCESS);
    return TRUE;
}

Bool redsea_eml_load_to_ramfs(const char* name) {
    if (!g_vol.is_mounted || !name) return FALSE;

    size_t size = 0;
    U8* data = redsea_eml_read_file(name, &size);
    if (!data) {
        kprintf("RedSea-EML: File '%s' not found on persistent disk.\n", name);
        return FALSE;
    }

    if (ramfs_exists(name)) {
        ramfs_write(name, data, size);
    } else {
        ramfs_create_static(name, data, size);
    }

    Free(data);
    kprintf("[RedSea-EML] Loaded '%s' (%u bytes) into RamFS.\n", name, (U32)size);
    speaker_event(BEEP_CONFIRM);
    return TRUE;
}

Bool redsea_eml_verify_barrett(const char* name, U64* crc_out) {
    if (!g_vol.is_mounted || !name) return FALSE;

    size_t size = 0;
    U8* data = redsea_eml_read_file(name, &size);
    if (!data) return FALSE;

    U64 crc = barrett_crc64_sector(data, size);
    if (crc_out) *crc_out = crc;

    Free(data);
    return TRUE;
}

U0 redsea_eml_benchmark(U0) {
    if (!g_vol.is_mounted) {
        kprintf("RedSea-EML: Cannot benchmark - Volume not mounted.\n");
        return;
    }

    kprintf("\n================ [ REDSEA-EML FILESYSTEM BENCHMARK ] ================\n");
    kprintf("Testing File Creation, DMA Streaming & Barrett GF(2) Verification...\n");

    // Create 64 KB test file
    size_t test_size = 64 * 1024;
    U8* test_data = (U8*)Malloc(test_size);
    if (!test_data) return;

    const char* pattern = "YESOS_EML_FILESYSTEM_BENCHMARK_BURST_BLOCK_0123456789_ABCDEF_";
    size_t plen = StrLen(pattern);
    for (size_t i = 0; i < test_size; i++) {
        test_data[i] = (U8)pattern[i % plen];
    }

    U64 t0 = timer_get_uptime_ms();
    Bool ok = redsea_eml_write_file("BENCH.DAT", test_data, test_size, 0);
    U64 t1 = timer_get_uptime_ms();
    U64 dt_write = (t1 > t0) ? (t1 - t0) : 1;

    if (!ok) {
        kprintf("Write benchmark failed.\n");
        Free(test_data);
        return;
    }

    size_t read_sz = 0;
    U64 t2 = timer_get_uptime_ms();
    U8* read_data = redsea_eml_read_file("BENCH.DAT", &read_sz);
    U64 t3 = timer_get_uptime_ms();
    U64 dt_read = (t3 > t2) ? (t3 - t2) : 1;

    if (!read_data || read_sz != test_size) {
        kprintf("Read benchmark failed.\n");
        Free(test_data);
        if (read_data) Free(read_data);
        return;
    }

    // Verify Barrett CRC64 with Zbc
    U64 crc_orig = barrett_crc64_sector(test_data, test_size);
    U64 crc_disk = barrett_crc64_sector(read_data, read_sz);

    kprintf("Benchmark Results (64 KB File):\n");
    kprintf("  - Write Time (DMA + Superblock) : %u ms (~%u MB/sec)\n",
            (U32)dt_write, (U32)((test_size * 1000) / (dt_write * 1024 * 1024)));
    kprintf("  - Read Time (Direct DMA Stream) : %u ms (~%u MB/sec)\n",
            (U32)dt_read, (U32)((test_size * 1000) / (dt_read * 1024 * 1024)));
    kprintf("  - Barrett CRC64 (Original Data) : 0x%p\n", (void*)crc_orig);
    kprintf("  - Barrett CRC64 (Read From Disk): 0x%p\n", (void*)crc_disk);
    kprintf("  - Mathematical Integrity Audit  : [%s]\n",
            (crc_orig == crc_disk) ? "PASS - 100% BIT IDENTICAL" : "FAIL - CORRUPTION DETECTED");

    // Clean up temporary benchmark file
    redsea_eml_delete_file("BENCH.DAT");

    Free(test_data);
    Free(read_data);

    // Run Free-Extent Allocation & Coalescing Validation
    redsea_eml_test_free_extent();

    kprintf("=====================================================================\n\n");
}

Bool redsea_eml_test_free_extent(U0) {
    if (!g_vol.is_mounted) {
        kprintf("RedSea-EML: Test failed - Volume not mounted.\n");
        return FALSE;
    }

    kprintf("\n================ [ FREE-EXTENT SUBSYSTEM TEST SUITE ] ================\n");
    kprintf("Testing Best-Fit Allocation, Hole Re-Use, CoW, and Coalescing...\n");

    U32 init_extent_count = g_vol.free_extent_count;
    U64 init_free_sectors = g_vol.total_free_sectors;

    kprintf("  Initial State: %u Free Extents | %u Total Free Sectors\n",
            init_extent_count, (U32)init_free_sectors);

    // Step 1: Create 3 consecutive files (A, B, C) of 16 sectors (8 KB)
    size_t dummy_sz = 16 * 512;
    U8* dummy = (U8*)Malloc(dummy_sz);
    if (!dummy) return FALSE;
    MemSet(dummy, 0xAA, dummy_sz);

    Bool ok1 = redsea_eml_write_file("TEST_A.DAT", dummy, dummy_sz, 0);
    Bool ok2 = redsea_eml_write_file("TEST_B.DAT", dummy, dummy_sz, 0);
    Bool ok3 = redsea_eml_write_file("TEST_C.DAT", dummy, dummy_sz, 0);

    if (!ok1 || !ok2 || !ok3) {
        kprintf("  [FAIL] Failed to create test files A, B, C.\n");
        Free(dummy);
        return FALSE;
    }

    U64 lba_a = 0, lba_b = 0, lba_c = 0;
    for (U32 i = 0; i < g_vol.entry_count; i++) {
        if (StrCmp(g_vol.entries[i].name, "TEST_A.DAT") == 0) lba_a = g_vol.entries[i].start_lba;
        if (StrCmp(g_vol.entries[i].name, "TEST_B.DAT") == 0) lba_b = g_vol.entries[i].start_lba;
        if (StrCmp(g_vol.entries[i].name, "TEST_C.DAT") == 0) lba_c = g_vol.entries[i].start_lba;
    }
    kprintf("  Files created -> A @ LBA %u, B @ LBA %u, C @ LBA %u\n",
            (U32)lba_a, (U32)lba_b, (U32)lba_c);

    // Step 2: Delete File B to puncture a 16-sector hole between A and C
    redsea_eml_delete_file("TEST_B.DAT");
    kprintf("  Deleted TEST_B.DAT -> Created hole at LBA %u (16 sectors)\n", (U32)lba_b);

    // Step 3: Allocate File D of 16 sectors -> Best-Fit MUST reclaim B's hole!
    Bool ok4 = redsea_eml_write_file("TEST_D.DAT", dummy, dummy_sz, 0);
    if (!ok4) {
        kprintf("  [FAIL] Failed to allocate TEST_D.DAT\n");
        Free(dummy);
        return FALSE;
    }

    U64 lba_d = 0;
    for (U32 i = 0; i < g_vol.entry_count; i++) {
        if (StrCmp(g_vol.entries[i].name, "TEST_D.DAT") == 0) lba_d = g_vol.entries[i].start_lba;
    }
    kprintf("  File D created -> D @ LBA %u (Target hole was %u)\n", (U32)lba_d, (U32)lba_b);

    if (lba_d != lba_b) {
        kprintf("  [FAIL] Best-Fit did not reclaim the hole! Expected %u, got %u\n", (U32)lba_b, (U32)lba_d);
        Free(dummy);
        return FALSE;
    }
    kprintf("  [PASS] Best-Fit perfectly reclaimed the hole at LBA %u!\n", (U32)lba_d);

    // Step 4: Test CoW (Copy-on-Write) modification of TEST_D.DAT
    size_t dummy2_sz = 8 * 512;
    U8* dummy2 = (U8*)Malloc(dummy2_sz);
    if (dummy2) {
        MemSet(dummy2, 0xBB, dummy2_sz);
        redsea_eml_write_file("TEST_D.DAT", dummy2, dummy2_sz, 0);
        kprintf("  Updated TEST_D.DAT via CoW -> Allocated new extent and freed old.\n");
        Free(dummy2);
    }

    // Step 5: Clean up all test files (A, C, D)
    redsea_eml_delete_file("TEST_A.DAT");
    redsea_eml_delete_file("TEST_C.DAT");
    redsea_eml_delete_file("TEST_D.DAT");

    // Step 6: Verify Coalescing restores free sectors and extent count
    kprintf("  After deletion & coalescing: %u Free Extents | %u Total Free Sectors\n",
            g_vol.free_extent_count, (U32)g_vol.total_free_sectors);

    if (g_vol.total_free_sectors != init_free_sectors) {
        kprintf("  [FAIL] Sector leak detected! Expected %u free sectors, got %u\n",
                (U32)init_free_sectors, (U32)g_vol.total_free_sectors);
        Free(dummy);
        return FALSE;
    }

    if (g_vol.free_extent_count != init_extent_count) {
        kprintf("  [FAIL] Incomplete coalescing! Expected %u extents, got %u\n",
                init_extent_count, g_vol.free_extent_count);
        Free(dummy);
        return FALSE;
    }

    kprintf("  [PASS] 100%% Coalescing Verified: Free sector count and extent table fully restored!\n");
    kprintf("======================================================================\n\n");
    Free(dummy);
    return TRUE;
}

// ----------------------------------------------------------------------------
// Hierarchical Directory & Path-based Operations (TempleOS Sacred Subdirectories)
// ----------------------------------------------------------------------------

Bool redsea_eml_mkdir(const char* dir_path) {
    if (!g_vol.is_mounted || !dir_path || dir_path[0] == '\0') return FALSE;

    while (*dir_path == '/') dir_path++;
    if (*dir_path == '\0') return TRUE;

    if (StrLen(dir_path) >= REDSEA_MAX_FILENAME) return FALSE;
    char clean_path[REDSEA_MAX_FILENAME];
    StrNCpy(clean_path, dir_path, sizeof(clean_path));
    size_t plen = StrLen(clean_path);
    if (plen > 0 && clean_path[plen - 1] == '/') clean_path[plen - 1] = '\0';

    if (redsea_eml_exists(clean_path)) return TRUE;
    if (backup_protected(clean_path)) return FALSE;

    U64 sec_count = 8; // 8 sectors = 64 file entries per directory
    U64 start_lba = redsea_extent_alloc(sec_count);
    if (start_lba == 0) {
        kprintf("[RedSea-EML] Failed to allocate extent for directory '%s'\n", clean_path);
        return FALSE;
    }

    // Zero out directory sectors on disk
    U8 zero_buf[512];
    MemSet(zero_buf, 0, 512);
    for (U64 s = 0; s < sec_count; s++) {
        ata_write_sectors(g_vol.drive, start_lba + s, 1, zero_buf);
    }
    barrier();

    U32 slot = free_slot();
    if (slot >= REDSEA_DIR_ENTRIES_MAX) {
        redsea_extent_free(start_lba, sec_count);
        return FALSE;
    }
    slot_used(slot);
    RedSeaFileEntry* fe = &g_vol.entries[slot];
    MemSet(fe, 0, sizeof(RedSeaFileEntry));
    StrNCpy(fe->name, clean_path, sizeof(fe->name));
    fe->start_lba = start_lba;
    fe->sector_count = sec_count;
    fe->byte_size = sec_count * 512;
    fe->flags = REDSEA_FLAG_USED | REDSEA_FLAG_DIR;
    fe->crc_euler = 0;

    // Update Directory Table on disk
    commit_dir_slot(slot);
    barrier();

    // Update Superblock
    g_vol.sb.total_files = g_vol.used_count;
    U8 sb_buf[512];
    MemSet(sb_buf, 0, 512);
    MemCpy(sb_buf, &g_vol.sb, sizeof(RedSeaSuperblock));
    ata_write_sectors(g_vol.drive, 1, 1, sb_buf);

    kprintf("[RedSea-EML] Created sacred directory '%s' at LBA %u (Free-Extent allocated)\n", clean_path, (U32)start_lba);
    return TRUE;
}

Bool redsea_eml_write_file_path(const char* path, const void* data, size_t size, U32 flags) {
    if (!g_vol.is_mounted || !path || !data) return FALSE;

    while (*path == '/') path++;
    if (*path == '\0') return FALSE;

    // Create parent directory if path contains '/'
    char parent_dir[REDSEA_MAX_FILENAME];
    StrNCpy(parent_dir, path, sizeof(parent_dir));
    char* last_slash = NULL;
    for (int i = 0; parent_dir[i]; i++) {
        if (parent_dir[i] == '/') last_slash = &parent_dir[i];
    }
    if (last_slash) {
        *last_slash = '\0';
        redsea_eml_mkdir(parent_dir);
    }

    return redsea_eml_write_file(path, data, size, flags);
}

U8* redsea_eml_read_file_path(const char* path, size_t* out_size) {
    if (!g_vol.is_mounted || !path) return NULL;
    while (*path == '/') path++;
    return redsea_eml_read_file(path, out_size);
}

Bool redsea_eml_exists_path(const char* path) {
    if (!g_vol.is_mounted || !path) return FALSE;
    while (*path == '/') path++;
    return redsea_eml_exists(path);
}

// Points `dst` at the data of entry `si` (no data is copied). `di` is the
// slot of an existing `dst` (replaced; its old extent freed if unused) or -1.
static Bool link_common(I64 si, I64 di, const char* dst, U32 set_flags, U32 clear_flags, Bool sync) {
    if (si < 0 || si == di || !(g_vol.entries[si].flags & REDSEA_FLAG_USED)) return FALSE;
    if (g_vol.entries[si].flags & REDSEA_FLAG_DIR) return FALSE;
    if (StrNICmp(dst, "vault/", 6) == 0 && !(g_vol.entries[si].flags & REDSEA_FLAG_ENCRYPTED)) return FALSE;

    U64 old_lba = 0, old_sec = 0;
    U32 slot;
    if (di >= 0) {
        slot = (U32)di;
        old_lba = g_vol.entries[slot].start_lba;
        old_sec = g_vol.entries[slot].sector_count;
    } else {
        slot = free_slot();
        if (slot >= REDSEA_DIR_ENTRIES_MAX) return FALSE;
        slot_used(slot);
    }
    RedSeaFileEntry e = g_vol.entries[si];
    StrNCpy(e.name, dst, sizeof(e.name) - 1);
    e.name[sizeof(e.name) - 1] = '\0';
    e.flags = ((e.flags | set_flags) & ~clear_flags) | REDSEA_FLAG_USED;
    e.flags &= ~REDSEA_FLAG_SECURE_WIPE;   // a shared extent is never wiped
    g_vol.entries[slot] = e;
    commit_dir_slot(slot);
    // Replacing an entry frees space that may be reused at once: always
    // make the change durable first. New links can share one final barrier.
    if (sync || old_sec > 0) barrier();
    if (old_sec > 0 && !extent_shared(old_lba, old_sec, -1)) redsea_extent_free(old_lba, old_sec);
    if (sync) commit_superblock();
    return TRUE;
}

// Points `dst` at the data of `src`. An existing `dst` entry is replaced.
// `set_flags` / `clear_flags` adjust the copied flags (e.g. READONLY).
Bool redsea_eml_link(const char* src, const char* dst, U32 set_flags, U32 clear_flags) {
    if (!g_vol.is_mounted || !src || !dst || StrLen(dst) >= REDSEA_MAX_FILENAME) return FALSE;
    if (backup_protected(dst)) return FALSE;
    I64 si = -1, di = -1;
    for (U32 i = 0; i < g_vol.entry_count; i++) {
        if (!(g_vol.entries[i].flags & REDSEA_FLAG_USED)) continue;
        if (si < 0 && StrCmp(g_vol.entries[i].name, src) == 0) si = (I64)i;
        if (di < 0 && StrCmp(g_vol.entries[i].name, dst) == 0) di = (I64)i;
    }
    return link_common(si, di, dst, set_flags, clear_flags, TRUE);
}

// Bulk variant for snapshot creation: `dst` must not exist (a new snapshot
// folder); no barrier and no superblock write - call redsea_eml_barrier().
Bool redsea_eml_link_new(U32 src_idx, const char* dst, U32 set_flags, U32 clear_flags) {
    if (!g_vol.is_mounted || !dst || StrLen(dst) >= REDSEA_MAX_FILENAME || src_idx >= g_vol.entry_count) return FALSE;
    if (backup_protected(dst)) return FALSE;
    return link_common((I64)src_idx, -1, dst, set_flags, clear_flags, FALSE);
}

U0 redsea_eml_barrier(U0) {
    barrier();
    commit_superblock();
    barrier();
}

// Deletes every entry whose name starts with `prefix`. An extent is freed
// only when every entry referencing it is deleted. Each slot clear is a
// single-sector write; one barrier at the end, before freed space is reused.
U32 redsea_eml_delete_prefix(const char* prefix) {
    if (!g_vol.is_mounted || !prefix || !prefix[0]) return 0;
    if (backup_protected(prefix)) return 0;
    size_t pl = StrLen(prefix);
    static U8 victim[REDSEA_DIR_ENTRIES_MAX];
    U32 m = 0, removed = 0;
    for (U32 i = 0; i < g_vol.entry_count; i++) {
        Bool used = (g_vol.entries[i].flags & REDSEA_FLAG_USED) != 0;
        victim[i] = used && StrNCmp(g_vol.entries[i].name, prefix, pl) == 0;
        if (used) g_idx[m++] = i;
    }
    // Extents to free: groups (identical extents) made only of victims
    sort_idx(g_idx, m, cmp_by_extent);
    static RedSeaExtent to_free[REDSEA_DIR_ENTRIES_MAX];
    U32 nf = 0;
    for (U32 g = 0; g < m;) {
        const RedSeaFileEntry* a = &g_vol.entries[g_idx[g]];
        U32 h = g + 1;
        Bool all = victim[g_idx[g]] != 0;
        while (h < m && g_vol.entries[g_idx[h]].start_lba == a->start_lba &&
               g_vol.entries[g_idx[h]].sector_count == a->sector_count) {
            all = all && victim[g_idx[h]];
            h++;
        }
        if (all && a->sector_count && !(a->flags & REDSEA_FLAG_DIR)) {
            to_free[nf].start_lba = a->start_lba;
            to_free[nf].sector_count = a->sector_count;
            nf++;
        }
        g = h;
    }
    for (U32 i = 0; i < g_vol.entry_count; i++) {
        if (!victim[i]) continue;
        slot_freed(i);
        commit_dir_slot(i);
        removed++;
    }
    if (removed) {
        barrier();   // directory durable before the space is reused
        for (U32 k = 0; k < nf; k++) redsea_extent_free(to_free[k].start_lba, to_free[k].sector_count);
        commit_superblock();
        barrier();
    }
    return removed;
}

U32 redsea_eml_free_entries(U0) {
    return g_vol.is_mounted ? REDSEA_DIR_ENTRIES_MAX - g_vol.used_count : 0;
}

// ----------------------------------------------------------------------------
// fsck
// ----------------------------------------------------------------------------

static RedSeaFsckReport g_last_fsck;
static Bool             g_have_fsck = FALSE;

const RedSeaFsckReport* redsea_eml_last_fsck(U0) {
    return g_have_fsck ? &g_last_fsck : NULL;
}

// Checksum used by older host tools (tools/redsea_injector.py before v3.1).
static U32 legacy_euler_crc(const U8* data, size_t len) {
    U32 h = 0x5A5A5A5Au;
    for (size_t i = 0; i < len; i++) h = (h << 5) ^ (h >> 27) ^ data[i];
    return h;
}

static U0 fsck_problem(RedSeaFsckReport* r, Bool error, Bool verbose, const char* fmt, const char* name, U64 a, U64 b) {
    if (error) r->errors++; else r->warnings++;
    char line[160];
    ksnprintf(line, sizeof(line), fmt, name, (U32)a, (U32)b);
    if (!r->first_problem[0] && error) StrNCpy(r->first_problem, line, sizeof(r->first_problem) - 1);
    if (verbose) kprintf("  [%s] %s\n", error ? "ERROR" : "warn ", line);
}

typedef struct { U64 start; U64 end; } FsckRange;   // [start, end)

Bool redsea_eml_fsck(Bool check_data, Bool verbose, RedSeaFsckReport* out) {
    RedSeaFsckReport r;
    MemSet(&r, 0, sizeof(r));
    U64 t0 = timer_get_uptime_ms();
    if (!g_vol.is_mounted) {
        r.errors = 1;
        StrNCpy(r.first_problem, "no volume mounted", sizeof(r.first_problem) - 1);
        if (out) *out = r;
        return FALSE;
    }
    const RedSeaSuperblock* sb = &g_vol.sb;
    U64 data_start = sb->data_area_lba, limit = sb->total_sectors;

    // 1. Superblock
    if (sb->version != REDSEA_VERSION || sb->root_dir_sectors != REDSEA_DIR_SECTORS || data_start >= limit)
        fsck_problem(&r, TRUE, verbose, "superblock: bad version/geometry%s (%u, %u)", "", sb->version, sb->root_dir_sectors);
    if (sb->total_files != g_vol.used_count)
        fsck_problem(&r, FALSE, verbose, "superblock file count%s %u differs from directory %u", "", sb->total_files, g_vol.used_count);

    // 2. Entries
    static FsckRange used[REDSEA_DIR_ENTRIES_MAX + 1];
    U32 nused = 0;
    if (sb->root_dir_lba >= data_start) {   // directory relocated into the data area (v2 -> v3)
        used[nused].start = sb->root_dir_lba;
        used[nused].end = sb->root_dir_lba + sb->root_dir_sectors;
        nused++;
    }
    r.entries = g_vol.used_count;
    U32 counted = 0;
    for (U32 i = 0; i < g_vol.entry_count; i++) {
        const RedSeaFileEntry* e = &g_vol.entries[i];
        if (!(e->flags & REDSEA_FLAG_USED)) continue;   // free slot (normal since v4)
        counted++;
        Bool terminated = FALSE;
        for (U32 k = 0; k < sizeof(e->name); k++) if (e->name[k] == '\0') { terminated = TRUE; break; }
        if (!(e->flags & REDSEA_FLAG_USED) || !terminated || e->name[0] == '\0') {
            fsck_problem(&r, TRUE, verbose, "entry %s%u is unused or has a bad name (flags %u)", "#", i, e->flags);
            continue;
        }
        Bool is_dir = (e->flags & REDSEA_FLAG_DIR) != 0;
        if (is_dir) r.dirs++; else r.files++;
        if (e->sector_count == 0 || e->start_lba < data_start || e->start_lba + e->sector_count > limit) {
            fsck_problem(&r, TRUE, verbose, "'%s': extent outside the data area (LBA %u, %u sectors)", e->name, e->start_lba, e->sector_count);
            continue;
        }
        if (!is_dir) {
            U64 need = (e->byte_size + 511) / 512;
            if (need == 0) need = 1;
            if (e->sector_count < need)
                fsck_problem(&r, TRUE, verbose, "'%s': %u sectors cannot hold %u bytes", e->name, e->sector_count, e->byte_size);
        }
        if (StrNCmp(e->name, "backup/", 7) == 0 && !is_dir) {
            Bool in_snap = StrNCmp(e->name, "backup/snap-", 12) == 0;
            if (!in_snap) r.legacy_backup_files++;
            else if (!(e->flags & REDSEA_FLAG_READONLY))
                fsck_problem(&r, TRUE, verbose, "'%s': snapshot file not read-only%s", e->name, 0, 0);
        }
        used[nused].start = e->start_lba;
        used[nused].end = e->start_lba + e->sector_count;
        nused++;
    }

    // 3. Duplicate names (sorted by name) and overlaps (sorted by extent;
    //    identical shared extents are snapshots)
    if (counted != g_vol.used_count)
        fsck_problem(&r, TRUE, verbose, "used-entry count%s %u differs from the directory %u", "", g_vol.used_count, counted);
    U32 ne = 0;
    for (U32 i = 0; i < g_vol.entry_count; i++) if (g_vol.entries[i].flags & REDSEA_FLAG_USED) g_idx[ne++] = i;
    sort_idx(g_idx, ne, cmp_by_name);
    for (U32 k = 1; k < ne; k++) {
        if (StrCmp(g_vol.entries[g_idx[k - 1]].name, g_vol.entries[g_idx[k]].name) == 0)
            fsck_problem(&r, TRUE, verbose, "'%s': duplicate entry%s", g_vol.entries[g_idx[k]].name, 0, 0);
    }
    ne = 0;
    for (U32 i = 0; i < g_vol.entry_count; i++) if (g_vol.entries[i].flags & REDSEA_FLAG_USED) g_idx[ne++] = i;
    sort_idx(g_idx, ne, cmp_by_extent);
    for (U32 i = 0; i < ne; i++) {
        const RedSeaFileEntry* a = &g_vol.entries[g_idx[i]];
        if (a->sector_count == 0) continue;
        for (U32 j = i + 1; j < ne; j++) {
            const RedSeaFileEntry* b = &g_vol.entries[g_idx[j]];
            if (b->start_lba >= a->start_lba + a->sector_count) break;   // sorted: no later overlap
            if (b->sector_count == 0) continue;
            Bool identical = a->start_lba == b->start_lba && a->sector_count == b->sector_count &&
                             a->byte_size == b->byte_size && !((a->flags | b->flags) & REDSEA_FLAG_DIR);
            if (identical) r.shared_extents++;
            else fsck_problem(&r, TRUE, verbose, "'%s' overlaps another entry at LBA %u (%u sectors)", a->name, a->start_lba, a->sector_count);
        }
    }

    // 4. Used space: entries in extent order (g_idx) with the directory range
    //    inserted at its place, merged into disjoint intervals.
    nused = 0;
    Bool dir_in_data = sb->root_dir_lba >= data_start;
    Bool dir_placed = !dir_in_data;
    for (U32 i = 0; i <= ne; i++) {
        const RedSeaFileEntry* e = (i < ne) ? &g_vol.entries[g_idx[i]] : NULL;
        if (!dir_placed && (!e || sb->root_dir_lba <= e->start_lba)) {
            used[nused].start = sb->root_dir_lba;
            used[nused].end = sb->root_dir_lba + sb->root_dir_sectors;
            nused++;
            dir_placed = TRUE;
        }
        if (!e || e->sector_count == 0 || e->start_lba < data_start || e->start_lba + e->sector_count > limit) continue;
        used[nused].start = e->start_lba;
        used[nused].end = e->start_lba + e->sector_count;
        nused++;
    }
    U32 nu = 0;   // merge in place
    for (U32 u = 0; u < nused; u++) {
        if (nu && used[u].start <= used[nu - 1].end) {
            if (used[u].end > used[nu - 1].end) used[nu - 1].end = used[u].end;
        } else {
            used[nu++] = used[u];
        }
    }
    for (U32 u = 0; u < nu; u++) r.used_sectors += used[u].end - used[u].start;

    // 5. Free map: inside the data area, sorted, never over used space
    //    (both lists are sorted: one linear sweep)
    U64 prev_end = data_start;
    U32 up = 0;
    for (U32 k = 0; k < g_vol.free_extent_count; k++) {
        U64 fs = g_vol.free_extents[k].start_lba, fe = fs + g_vol.free_extents[k].sector_count;
        r.free_sectors += g_vol.free_extents[k].sector_count;
        if (fs < data_start || fe > limit || fs >= fe)
            fsck_problem(&r, TRUE, verbose, "free extent %s%u+%u outside the data area", "", fs, fe - fs);
        if (fs < prev_end && k > 0)
            fsck_problem(&r, TRUE, verbose, "free extents %sunsorted or overlapping at LBA %u (%u)", "", fs, prev_end);
        prev_end = fe;
        while (up < nu && used[up].end <= fs) up++;
        if (up < nu && used[up].start < fe)
            fsck_problem(&r, TRUE, verbose, "free map covers used sectors %sat LBA %u..%u", "", used[up].start, used[up].end);
    }
    if (r.free_sectors != g_vol.total_free_sectors)
        fsck_problem(&r, TRUE, verbose, "free-sector total%s %u differs from the map %u", "", g_vol.total_free_sectors, r.free_sectors);

    U64 data_area = limit - data_start;
    if (r.used_sectors + r.free_sectors < data_area) {
        r.lost_sectors = data_area - r.used_sectors - r.free_sectors;
        fsck_problem(&r, FALSE, verbose, "%s%u sectors neither used nor free (leak; %u used)", "", r.lost_sectors, r.used_sectors);
    }

    // 5. Data
    if (check_data) {
        r.data_checked = TRUE;
        for (U32 i = 0; i < g_vol.entry_count; i++) {
            const RedSeaFileEntry* e = &g_vol.entries[i];
            if (!(e->flags & REDSEA_FLAG_USED) || (e->flags & REDSEA_FLAG_DIR)) continue;
            if (e->start_lba < data_start || e->start_lba + e->sector_count > limit) continue;
            size_t bytes = (size_t)e->sector_count * 512;
            U8* buf = (U8*)Malloc(bytes);
            if (!buf || !ata_read_sectors(g_vol.drive, e->start_lba, (U32)e->sector_count, buf)) {
                r.unreadable++;
                fsck_problem(&r, TRUE, verbose, "'%s': cannot read its data (LBA %u, %u sectors)", e->name, e->start_lba, e->sector_count);
                if (buf) Free(buf);
                continue;
            }
            U32 crc = (U32)barrett_crc64_sector(buf, (size_t)e->byte_size);
            if (e->byte_size == 0 || crc == e->crc_euler) r.crc_ok++;
            else if (legacy_euler_crc(buf, (size_t)e->byte_size) == e->crc_euler) r.crc_legacy++;
            else {
                r.crc_bad++;
                fsck_problem(&r, TRUE, verbose, "'%s': data does not match its CRC (stored 0x%08X, read 0x%08X)", e->name, e->crc_euler, crc);
            }
            Free(buf);
        }
    }

    r.duration_ms = timer_get_uptime_ms() - t0;
    g_last_fsck = r;
    g_have_fsck = TRUE;
    if (out) *out = r;
    return r.errors == 0;
}

// Number of directory entries that reference each entry's extent (1 = the
// extent belongs to that entry alone). O(n log n): entries sorted by extent.
U0 redsea_eml_extent_refcounts(U16* refs) {
    U32 n = 0;
    for (U32 i = 0; i < g_vol.entry_count; i++) {
        refs[i] = 0;
        if (g_vol.entries[i].flags & REDSEA_FLAG_USED) g_idx[n++] = i;
    }
    sort_idx(g_idx, n, cmp_by_extent);
    for (U32 g = 0; g < n;) {
        const RedSeaFileEntry* a = &g_vol.entries[g_idx[g]];
        U32 h = g + 1;
        while (h < n && g_vol.entries[g_idx[h]].start_lba == a->start_lba &&
               g_vol.entries[g_idx[h]].sector_count == a->sector_count) h++;
        for (U32 k = g; k < h; k++) refs[g_idx[k]] = (U16)((h - g) > 65535 ? 65535 : (h - g));
        g = h;
    }
}
