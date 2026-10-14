// Block device front end used by RedSea. Drive 0 is the virtio-blk disk, the
// only storage YesOS supports; the "ata" names stay so callers keep one API.
#include "ata.h"
#include "virtio_blk.h"
#include "kprintf.h"
#include "memory.h"

static ATADriveInfo g_drives[ATA_MAX_DRIVES];

U0 ata_init(U0) {
    MemSet(g_drives, 0, sizeof(g_drives));

    if (virtio_blk_init() && virtio_blk_is_present()) {
        VirtIOBlkInfo* vinfo = virtio_blk_get_info();
        g_drives[0].is_present = TRUE;
        g_drives[0].total_sectors = vinfo->total_sectors;
        g_drives[0].capacity_bytes = vinfo->capacity_bytes;
        StrNCpy(g_drives[0].model, vinfo->model, sizeof(g_drives[0].model));
        StrNCpy(g_drives[0].serial, vinfo->serial, sizeof(g_drives[0].serial));
    }
}

ATADriveInfo* ata_get_drive_info(U8 drive) {
    if (drive >= ATA_MAX_DRIVES) return NULL;
    return &g_drives[drive];
}

Bool ata_read_sectors(U8 drive, U64 lba, U32 count, U8* buffer) {
    if (drive != 0 || !g_drives[0].is_present || !buffer || count == 0) return FALSE;
    return virtio_blk_read_sectors(lba, count, buffer);
}

Bool ata_write_sectors(U8 drive, U64 lba, U32 count, const U8* buffer) {
    if (drive != 0 || !g_drives[0].is_present || !buffer || count == 0) return FALSE;
    return virtio_blk_write_sectors(lba, count, buffer);
}

U0 ata_dump_telemetry(U0) {
    if (virtio_blk_is_present()) {
        virtio_blk_dump_telemetry();
        return;
    }
    kprintf("No disk: virtio-blk device not present\n");
}

// Write barrier: returns once every completed write is on stable storage.
Bool ata_flush(U8 drive) {
    if (drive == 0 && virtio_blk_is_present()) return virtio_blk_flush();
    return TRUE;   // no disk, nothing to flush
}
