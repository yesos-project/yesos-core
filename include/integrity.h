#ifndef INTEGRITY_H
#define INTEGRITY_H

#include "types.h"

// Kernel image hash written post-link by tools/image_hash.py (64 bytes).
#define IMAGE_HASH_MAGIC 0x48474D49u   // "IMGH"

typedef struct __attribute__((packed)) {
    U32 magic;
    U32 version;
    U64 text_len;
    U64 rodata_len;
    U8  hash[32];
    U8  pad[8];
} KernelImageHash;

// Runtime integrity monitor (runs on the key hart, see kernel/keyhart.c).
// The status is not secret: hart 0 reads it directly.
typedef enum {
    IMG_UNKNOWN = 0,
    IMG_OK,
    IMG_MISMATCH,
    IMG_NO_HASH,
} ImageState;

typedef struct {
    volatile U32 image_state;     // ImageState, checked at key hart boot
    volatile U32 armed;           // keyed baseline taken
    volatile U32 chunks;          // 64 KiB chunks covered (.text .. end of read-only data)
    volatile U64 chunks_checked;
    volatile U64 full_passes;
    volatile U32 alarm;           // a chunk changed after the baseline
    volatile U64 alarm_addr;      // start of the first changed chunk
    volatile U32 vault_locked_by_alarm;
} IntegrityStatus;

const IntegrityStatus* integrity_status(U0);
Bool integrity_arm(U0);          // hart 0, after the entropy pool is seeded
U0   integrity_poll(U0);         // hart 0: report alarms once
U0   integrity_print_status(U0);

#endif // INTEGRITY_H
