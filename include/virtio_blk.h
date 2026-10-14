#ifndef VIRTIO_BLK_H
#define VIRTIO_BLK_H

#include "types.h"

// ----------------------------------------------------------------------------
// YesOS Modern VirtIO-Block 1.0 Subsystem (RISC-V Bare-Metal M-Mode)
// ----------------------------------------------------------------------------

#define VIRTIO_BLK_SECTOR_SIZE   512
#define VIRTIO_BLK_MAX_SECTORS   128  // 64 KB per DMA segment

typedef struct {
    Bool is_present;
    U64  total_sectors;
    U64  capacity_bytes;
    U32  blk_size;
    U32  queue_size;
    char model[41];
    char serial[21];
} VirtIOBlkInfo;

// VirtIO Block Driver API
Bool           virtio_blk_init(U0);
Bool           virtio_blk_is_present(U0);
VirtIOBlkInfo* virtio_blk_get_info(U0);
Bool           virtio_blk_read_sectors(U64 lba, U32 count, U8* buffer);
Bool           virtio_blk_write_sectors(U64 lba, U32 count, const U8* buffer);
Bool           virtio_blk_flush(U0);          // barrier: earlier writes are durable
U0             virtio_blk_dump_telemetry(U0);
Bool           virtio_blk_benchmark(U0);

// Exempts the next writes from the entropy heuristic. Only RedSea sets this,
// and only around writes of vault ciphertext (REDSEA_FLAG_ENCRYPTED).
U0 virtio_blk_allow_ciphertext_write(Bool allow);

#endif // VIRTIO_BLK_H
