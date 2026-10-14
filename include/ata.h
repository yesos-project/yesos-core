#ifndef ATA_H
#define ATA_H

#include "types.h"

#define ATA_SECTOR_SIZE           512
#define ATA_MAX_DRIVES            4

typedef struct {
    Bool is_present;
    U64  total_sectors;
    U64  capacity_bytes;
    char model[41];
    char serial[21];
} ATADriveInfo;

// Block device API (drive 0 = the virtio-blk disk)
U0           ata_init(U0);
ATADriveInfo* ata_get_drive_info(U8 drive);
Bool         ata_read_sectors(U8 drive, U64 lba, U32 count, U8* buffer);
Bool         ata_write_sectors(U8 drive, U64 lba, U32 count, const U8* buffer);
U0           ata_dump_telemetry(U0);

Bool ata_flush(U8 drive);   // write barrier

#endif // ATA_H
