#ifndef CLINT_H
#define CLINT_H

#include "types.h"

// CLINT (Core Local Interruptor) of QEMU virt: per-hart software interrupt
// (MSIP), per-hart timer compare (MTIMECMP) and the free-running mtime counter.
#define CLINT_BASE          0x02000000ULL
#define CLINT_MSIP(h)       ((volatile U32*)(CLINT_BASE + ((h) * 4)))
#define CLINT_MTIMECMP(h)   ((volatile U64*)(CLINT_BASE + 0x4000 + ((h) * 8)))
#define CLINT_MTIME         ((volatile U64*)(CLINT_BASE + 0xBFF8))

// mtime rate on QEMU virt. The boards' CLINT address and timebase differ and
// are not handled yet (see DEPLOY_SBC.md).
#define CLINT_TIMEBASE_HZ   10000000ULL
#define CLINT_TICKS_PER_MS  (CLINT_TIMEBASE_HZ / 1000)

#endif // CLINT_H
