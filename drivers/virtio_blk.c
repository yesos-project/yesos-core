#include "virtio_blk.h"
#include "ports.h"
#include "kprintf.h"
#include "memory.h"
#include "timer.h"
#include "speaker.h"
#include "rust_security.h"

// ----------------------------------------------------------------------------
// YesOS VirtIO Modern 1.0 Block Driver for RISC-V Bare-Metal M-Mode
// PCI Base: RV_PCI_ECAM_BASE (0x30000000)
// Supports: virtio-blk-pci (Vendor 0x1AF4, Device 0x1042 or 0x1001)
// ----------------------------------------------------------------------------

#define RV_PCI_ECAM_BASE       0x30000000ULL
#define RV_PCI_SLOT_COUNT      32

#define VIRTIO_PCI_VENDOR      0x1AF4
#define VIRTIO_PCI_DEV_BLK_MOD 0x1042 // Modern VirtIO Block (0x1040 + 2)
#define VIRTIO_PCI_DEV_BLK_LEG 0x1001 // Transitional VirtIO Block

// PCI Configuration Registers
#define PCI_REG_VENDOR_ID      0x00
#define PCI_REG_DEVICE_ID      0x02
#define PCI_REG_COMMAND        0x04
#define PCI_REG_STATUS         0x06
#define PCI_REG_BAR0           0x10
#define PCI_REG_CAP_PTR        0x34

#define PCI_STATUS_CAP_LIST    0x10
#define PCI_CAP_ID_VNDR        0x09

// VirtIO Modern PCI Capability Types
#define VIRTIO_PCI_CAP_COMMON_CFG 1
#define VIRTIO_PCI_CAP_NOTIFY_CFG 2
#define VIRTIO_PCI_CAP_ISR_CFG    3
#define VIRTIO_PCI_CAP_DEVICE_CFG 4

// VirtIO Common Configuration Offsets
#define VIRTIO_COMMON_DFSELECT   0x00
#define VIRTIO_COMMON_DF         0x04
#define VIRTIO_COMMON_GFSELECT   0x08
#define VIRTIO_COMMON_GF         0x0C
#define VIRTIO_COMMON_MSIX       0x10
#define VIRTIO_COMMON_NUMQ       0x12
#define VIRTIO_COMMON_STATUS     0x14
#define VIRTIO_COMMON_CFGGEN     0x15
#define VIRTIO_COMMON_Q_SELECT   0x16
#define VIRTIO_COMMON_Q_SIZE     0x18
#define VIRTIO_COMMON_Q_MSIX     0x1A
#define VIRTIO_COMMON_Q_ENABLE   0x1C
#define VIRTIO_COMMON_Q_NOFF     0x1E
#define VIRTIO_COMMON_Q_DESCLO   0x20
#define VIRTIO_COMMON_Q_DESCHI   0x24
#define VIRTIO_COMMON_Q_AVAILLO  0x28
#define VIRTIO_COMMON_Q_AVAILHI  0x2C
#define VIRTIO_COMMON_Q_USEDLO   0x30
#define VIRTIO_COMMON_Q_USEDHI   0x34

// VirtIO Device Status Bits
#define VIRTIO_STATUS_ACKNOWLEDGE 1
#define VIRTIO_STATUS_DRIVER      2
#define VIRTIO_STATUS_DRIVER_OK   4
#define VIRTIO_STATUS_FEATURES_OK 8

// Split VirtQueue Descriptor Flags
#define VRING_DESC_F_NEXT         1
#define VRING_DESC_F_WRITE        2

// VirtIO Block Request Types
#define VIRTIO_BLK_T_IN           0 // Read
#define VIRTIO_BLK_T_OUT          1 // Write
#define VIRTIO_BLK_T_FLUSH        4 // Cache Flush

// VirtIO Block Status Codes
#define VIRTIO_BLK_S_OK           0
#define VIRTIO_BLK_S_IOERR        1
#define VIRTIO_BLK_S_UNSUPP       2

// Split VirtQueue Ring Structures
struct vring_desc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
};

struct vring_avail {
    uint16_t flags;
    volatile uint16_t idx;
    uint16_t ring[];
};

struct vring_used_elem {
    uint32_t id;
    uint32_t len;
};

struct vring_used {
    uint16_t flags;
    volatile uint16_t idx;
    struct vring_used_elem ring[];
};

// The rings are shared with the device, which updates them concurrently:
// they must NOT be packed. Packing made the compiler read used->idx with two
// byte loads, and a torn read (old high byte + new low byte, at every 256th
// request) let the driver treat unfinished requests as complete. The natural
// layout already matches the virtio 1.0 specification exactly.
_Static_assert(sizeof(struct vring_desc) == 16, "virtq descriptor is 16 bytes");
_Static_assert(sizeof(struct vring_used_elem) == 8, "used element is 8 bytes");
_Static_assert(__builtin_offsetof(struct vring_avail, ring) == 4, "avail ring at offset 4");
_Static_assert(__builtin_offsetof(struct vring_used, ring) == 4, "used ring at offset 4");

// Block Request Header (16 bytes packed)
struct virtio_blk_req {
    uint32_t type;
    uint32_t reserved;
    uint64_t sector;
} __attribute__((packed));

typedef struct {
    Bool is_initialized;
    uintptr_t dev_ecam;
    uintptr_t common_cfg;
    uintptr_t notify_base;
    uint32_t  notify_off_multiplier;
    uintptr_t isr_cfg;
    uintptr_t device_cfg;
    uintptr_t notify_addr;

    uint16_t queue_size;
    uint16_t last_used_idx;
    Bool     has_flush;

    struct vring_desc*  desc;
    struct vring_avail* avail;
    struct vring_used*  used;

    VirtIOBlkInfo info;
} VirtIOBlkDev;

static VirtIOBlkDev g_blk_dev;
static uintptr_t s_next_pci_blk_mmio = 0x46000000ULL;

// Pre-allocated static request header and status byte (aligned)
static volatile struct virtio_blk_req s_req __attribute__((aligned(16)));
static volatile uint8_t s_status __attribute__((aligned(16)));

static inline U0 io_barrier(U0) {
    asm volatile("fence rw,rw" ::: "memory");
}

// ----------------------------------------------------------------------------
// PCI BAR Allocation & Bus Configuration
// ----------------------------------------------------------------------------

static U0 pci_assign_bars_blk(uintptr_t dev_ecam, uintptr_t bar_addrs[6]) {
    for (int i = 0; i < 6; i++) {
        uintptr_t bar_reg = dev_ecam + PCI_REG_BAR0 + (i * 4);
        U32 orig = mmio_read32(bar_reg);
        mmio_write32(bar_reg, 0xFFFFFFFF);
        U32 probed = mmio_read32(bar_reg);
        mmio_write32(bar_reg, orig);

        if (probed == 0 || probed == 0xFFFFFFFF) {
            bar_addrs[i] = 0;
            continue;
        }

        if ((probed & 0x01) == 0) { // Memory BAR
            U32 type = (probed >> 1) & 0x03; // 0 = 32-bit, 2 = 64-bit
            U32 mask = probed & ~0x0F;
            U32 size = ~mask + 1;
            if (size < 0x1000) size = 0x1000;

            s_next_pci_blk_mmio = (s_next_pci_blk_mmio + size - 1) & ~(uintptr_t)(size - 1);
            bar_addrs[i] = s_next_pci_blk_mmio;
            mmio_write32(bar_reg, (U32)s_next_pci_blk_mmio);

            if (type == 2 && i < 5) {
                i++;
                uintptr_t bar_reg_high = dev_ecam + PCI_REG_BAR0 + (i * 4);
                mmio_write32(bar_reg_high, (U32)(s_next_pci_blk_mmio >> 32));
                bar_addrs[i] = 0;
            }
            s_next_pci_blk_mmio += size;
        } else {
            bar_addrs[i] = 0;
        }
    }

    // Enable Memory Space (bit 1) and Bus Master DMA (bit 2)
    U16 cmd = mmio_read16(dev_ecam + PCI_REG_COMMAND);
    cmd |= 0x07;
    mmio_write16(dev_ecam + PCI_REG_COMMAND, cmd);
}

// ----------------------------------------------------------------------------
// Device Initialization
// ----------------------------------------------------------------------------

static Bool virtio_blk_init_device(uintptr_t dev_ecam, U32 slot) {
    VirtIOBlkDev* dev = &g_blk_dev;
    MemSet(dev, 0, sizeof(VirtIOBlkDev));
    dev->dev_ecam = dev_ecam;

    // 1. Assign PCI BARs
    uintptr_t bar_addrs[6] = {0};
    pci_assign_bars_blk(dev_ecam, bar_addrs);

    // 2. Parse PCI Capabilities for Modern VirtIO structures
    U16 status = mmio_read16(dev_ecam + PCI_REG_STATUS);
    if (!(status & PCI_STATUS_CAP_LIST)) {
        return FALSE;
    }

    U8 cap_ptr = mmio_read8(dev_ecam + PCI_REG_CAP_PTR) & ~3;
    while (cap_ptr != 0 && cap_ptr < 0xFF) {
        U8 cap_vndr = mmio_read8(dev_ecam + cap_ptr + 0);
        U8 cap_next = mmio_read8(dev_ecam + cap_ptr + 1);

        if (cap_vndr == PCI_CAP_ID_VNDR) {
            U8 cfg_type = mmio_read8(dev_ecam + cap_ptr + 3);
            U8 bar      = mmio_read8(dev_ecam + cap_ptr + 4);
            U32 offset  = mmio_read32(dev_ecam + cap_ptr + 8);
            uintptr_t bar_base = (bar < 6) ? bar_addrs[bar] : 0;

            if (bar_base != 0) {
                if (cfg_type == VIRTIO_PCI_CAP_COMMON_CFG) {
                    dev->common_cfg = bar_base + offset;
                } else if (cfg_type == VIRTIO_PCI_CAP_NOTIFY_CFG) {
                    dev->notify_base = bar_base + offset;
                    dev->notify_off_multiplier = mmio_read32(dev_ecam + cap_ptr + 16);
                } else if (cfg_type == VIRTIO_PCI_CAP_ISR_CFG) {
                    dev->isr_cfg = bar_base + offset;
                } else if (cfg_type == VIRTIO_PCI_CAP_DEVICE_CFG) {
                    dev->device_cfg = bar_base + offset;
                }
            }
        }
        cap_ptr = cap_next & ~3;
    }

    if (dev->common_cfg == 0 || dev->notify_base == 0) {
        kprintf("[VIRTIO-BLK] Slot %u: missing Modern VirtIO capabilities\n", slot);
        return FALSE;
    }

    // 3. Status Handshake: Reset
    uintptr_t common = dev->common_cfg;
    mmio_write8(common + VIRTIO_COMMON_STATUS, 0);
    io_barrier();

    // 4. Set ACKNOWLEDGE and DRIVER bits
    mmio_write8(common + VIRTIO_COMMON_STATUS, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);

    // 5. Negotiate Features (Accept VIRTIO_F_VERSION_1)
    mmio_write32(common + VIRTIO_COMMON_DFSELECT, 1);
    U32 f1 = mmio_read32(common + VIRTIO_COMMON_DF);
    mmio_write32(common + VIRTIO_COMMON_GFSELECT, 1);
    mmio_write32(common + VIRTIO_COMMON_GF, f1 & 1);

    // Low features: accept VIRTIO_BLK_F_FLUSH (bit 9) when offered, so the
    // device may cache writes and RedSea orders them with explicit barriers.
    mmio_write32(common + VIRTIO_COMMON_DFSELECT, 0);
    U32 f0 = mmio_read32(common + VIRTIO_COMMON_DF);
    dev->has_flush = (f0 & (1u << 9)) != 0;
    mmio_write32(common + VIRTIO_COMMON_GFSELECT, 0);
    mmio_write32(common + VIRTIO_COMMON_GF, f0 & (1u << 9));

    mmio_write8(common + VIRTIO_COMMON_STATUS,
                VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK);
    U8 ok = mmio_read8(common + VIRTIO_COMMON_STATUS);
    if (!(ok & VIRTIO_STATUS_FEATURES_OK)) {
        kprintf("[VIRTIO-BLK] Slot %u: FEATURES_OK rejected\n", slot);
        return FALSE;
    }

    // 6. Read Device Specific Configuration (Capacity & Sector Size)
    if (dev->device_cfg != 0) {
        U32 cap_lo = mmio_read32(dev->device_cfg + 0);
        U32 cap_hi = mmio_read32(dev->device_cfg + 4);
        dev->info.total_sectors = ((U64)cap_hi << 32) | cap_lo;
        dev->info.capacity_bytes = dev->info.total_sectors * VIRTIO_BLK_SECTOR_SIZE;
        dev->info.blk_size = VIRTIO_BLK_SECTOR_SIZE;
    }

    StrNCpy(dev->info.model, "QEMU VirtIO-Block PCI SSD", sizeof(dev->info.model));
    StrNCpy(dev->info.serial, "VIRTIO-BLK-RV64-001", sizeof(dev->info.serial));

    // 7. Configure VirtQueue 0 (Request Queue)
    mmio_write16(common + VIRTIO_COMMON_Q_SELECT, 0);
    U16 q_max = mmio_read16(common + VIRTIO_COMMON_Q_SIZE);
    if (q_max == 0) {
        kprintf("[VIRTIO-BLK] Slot %u: Queue 0 has size 0\n", slot);
        return FALSE;
    }

    U16 q_size = (q_max < 64) ? q_max : 64;
    mmio_write16(common + VIRTIO_COMMON_Q_SIZE, q_size);
    dev->queue_size = q_size;
    dev->info.queue_size = q_size;

    // Allocate queue memory
    dev->desc  = (struct vring_desc*)Calloc(q_size, sizeof(struct vring_desc));
    size_t avail_sz = sizeof(uint16_t) * (4 + q_size);
    dev->avail = (struct vring_avail*)Calloc(1, (avail_sz + 15) & ~15);
    size_t used_sz = sizeof(uint16_t) * 4 + sizeof(struct vring_used_elem) * q_size;
    dev->used  = (struct vring_used*)Calloc(1, (used_sz + 15) & ~15);

    // Write queue addresses
    mmio_write32(common + VIRTIO_COMMON_Q_DESCLO, (U32)(uintptr_t)dev->desc);
    mmio_write32(common + VIRTIO_COMMON_Q_DESCHI, (U32)((uintptr_t)dev->desc >> 32));
    mmio_write32(common + VIRTIO_COMMON_Q_AVAILLO, (U32)(uintptr_t)dev->avail);
    mmio_write32(common + VIRTIO_COMMON_Q_AVAILHI, (U32)((uintptr_t)dev->avail >> 32));
    mmio_write32(common + VIRTIO_COMMON_Q_USEDLO, (U32)(uintptr_t)dev->used);
    mmio_write32(common + VIRTIO_COMMON_Q_USEDHI, (U32)((uintptr_t)dev->used >> 32));

    // Calculate queue notify address
    U16 q_noff = mmio_read16(common + VIRTIO_COMMON_Q_NOFF);
    dev->notify_addr = dev->notify_base + ((uintptr_t)q_noff * dev->notify_off_multiplier);

    dev->avail->flags = 0;
    dev->avail->idx = 0;
    dev->last_used_idx = 0;

    // Enable Queue 0
    mmio_write16(common + VIRTIO_COMMON_Q_ENABLE, 1);

    // Set DRIVER_OK
    mmio_write8(common + VIRTIO_COMMON_STATUS,
                VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK);

    io_barrier();

    dev->info.is_present = TRUE;
    dev->is_initialized = TRUE;

    kprintf(" [ OK ] VIRTIO-BLOCK PCI : %s (Slot %u | %u MB | %u Sectors | %s)\n",
            dev->info.model, slot, (U32)(dev->info.capacity_bytes / (1024 * 1024)),
            (U32)dev->info.total_sectors, dev->has_flush ? "write cache + FLUSH barriers" : "write-through");
    return TRUE;
}

// ----------------------------------------------------------------------------
// Bus Probing & Driver Initialization
// ----------------------------------------------------------------------------

Bool virtio_blk_init(U0) {
    MemSet(&g_blk_dev, 0, sizeof(VirtIOBlkDev));

    // Scan PCI Bus 0 for VirtIO Block Devices
    for (U32 slot = 0; slot < RV_PCI_SLOT_COUNT; slot++) {
        uintptr_t dev_ecam = RV_PCI_ECAM_BASE + (slot << 15);
        U32 vendor_dev = mmio_read32(dev_ecam + PCI_REG_VENDOR_ID);
        U16 vendor = (U16)(vendor_dev & 0xFFFF);
        U16 device = (U16)(vendor_dev >> 16);

        if (vendor == VIRTIO_PCI_VENDOR &&
            (device == VIRTIO_PCI_DEV_BLK_MOD || device == VIRTIO_PCI_DEV_BLK_LEG)) {
            if (virtio_blk_init_device(dev_ecam, slot)) {
                return TRUE;
            }
        }
    }

    return FALSE;
}

Bool virtio_blk_is_present(U0) {
    return g_blk_dev.is_initialized && g_blk_dev.info.is_present;
}

VirtIOBlkInfo* virtio_blk_get_info(U0) {
    return &g_blk_dev.info;
}

// ----------------------------------------------------------------------------
// Synchronous Sector I/O Implementation (Split-Ring DMA)
// ----------------------------------------------------------------------------

static Bool s_allow_ciphertext_write = FALSE;

U0 virtio_blk_allow_ciphertext_write(Bool allow) {
    s_allow_ciphertext_write = allow;
}

static Bool virtio_blk_request(U32 type, U64 lba, U32 count, U8* buffer);

static Bool virtio_blk_transfer_sync(U64 lba, U32 count, U8* buffer, Bool is_write) {
    return virtio_blk_request(is_write ? VIRTIO_BLK_T_OUT : VIRTIO_BLK_T_IN, lba, count, buffer);
}

// Completes when every previously completed write is on stable storage.
// Without VIRTIO_BLK_F_FLUSH the device runs write-through, so nothing to do.
Bool virtio_blk_flush(U0) {
    if (!g_blk_dev.is_initialized) return FALSE;
    if (!g_blk_dev.has_flush) return TRUE;
    return virtio_blk_request(VIRTIO_BLK_T_FLUSH, 0, 0, NULL);
}

static Bool virtio_blk_request(U32 type, U64 lba, U32 count, U8* buffer) {
    Bool is_write = (type == VIRTIO_BLK_T_OUT);
    VirtIOBlkDev* dev = &g_blk_dev;
    if (!dev->is_initialized) return FALSE;

    // The block layer no longer rejects high-entropy writes: compressed media
    // and encrypted data are legitimate (no content-entropy guard on the NAS).
    (U0)s_allow_ciphertext_write;

    // Prepare Request Header
    s_req.type     = type;
    s_req.reserved = 0;
    s_req.sector   = lba;
    s_status       = 0xFF; // Sentinelle

    // Descriptor 0: Request Header (Device reads)
    dev->desc[0].addr  = (uint64_t)(uintptr_t)&s_req;
    dev->desc[0].len   = sizeof(struct virtio_blk_req);
    dev->desc[0].flags = VRING_DESC_F_NEXT;
    dev->desc[0].next  = 1;

    if (type == VIRTIO_BLK_T_FLUSH) {
        // Header + status only
        dev->desc[0].next  = 2;
    } else {
        // Descriptor 1: Data Buffer
        dev->desc[1].addr  = (uint64_t)(uintptr_t)buffer;
        dev->desc[1].len   = count * VIRTIO_BLK_SECTOR_SIZE;
        dev->desc[1].flags = VRING_DESC_F_NEXT | (is_write ? 0 : VRING_DESC_F_WRITE);
        dev->desc[1].next  = 2;
    }

    // Descriptor 2: Status Byte (Device writes)
    dev->desc[2].addr  = (uint64_t)(uintptr_t)&s_status;
    dev->desc[2].len   = 1;
    dev->desc[2].flags = VRING_DESC_F_WRITE;
    dev->desc[2].next  = 0;

    io_barrier();

    // Place chain head (0) on Available Ring
    U16 head = 0;
    dev->avail->ring[dev->avail->idx % dev->queue_size] = head;
    io_barrier();
    dev->avail->idx++;
    io_barrier();

    // Notify Device of ready descriptor
    mmio_write16(dev->notify_addr, 0);

    // Poll Used Ring for Request Completion. The wait is bounded by wall
    // time, not loop iterations: host I/O can legitimately take milliseconds.
    // (The former `while (... && timeout--)` wrapped to UINT32_MAX on expiry,
    // so timeouts went undetected and the late completion was consumed by the
    // NEXT request, desynchronising the queue.)
    U64 t0 = timer_get_uptime_ms();
    U32 spins = 0;
    while (dev->used->idx == dev->last_used_idx) {
        io_barrier();
        if (++spins >= 4096) {
            spins = 0;
            if (timer_get_uptime_ms() - t0 > 10000) break;
        }
    }

    if (dev->used->idx == dev->last_used_idx) {
        // The device still owns the descriptors: reusing them could corrupt
        // data, so the disk is taken offline.
        kprintf("[VIRTIO-BLK] Error: no completion for LBA %u (%s) after 10 s; disabling the device.\n",
                (U32)lba, type == VIRTIO_BLK_T_FLUSH ? "FLUSH" : (is_write ? "WRITE" : "READ"));
        dev->is_initialized = FALSE;
        return FALSE;
    }

    U16 done = (U16)(dev->used->idx - dev->last_used_idx);
    U32 used_id = dev->used->ring[dev->last_used_idx % dev->queue_size].id;
    dev->last_used_idx = dev->used->idx;
    io_barrier();

    if (done != 1 || used_id != head) {
        kprintf("[VIRTIO-BLK] Queue desync on LBA %u (%s): %u completions, id %u\n",
                (U32)lba, type == VIRTIO_BLK_T_FLUSH ? "FLUSH" : (is_write ? "WRITE" : "READ"), (U32)done, used_id);
    }
    if (s_status != VIRTIO_BLK_S_OK) {
        kprintf("[VIRTIO-BLK] %s of LBA %u failed (status %u)\n",
                type == VIRTIO_BLK_T_FLUSH ? "FLUSH" : (is_write ? "WRITE" : "READ"), (U32)lba, (U32)s_status);
        return FALSE;
    }
    return TRUE;
}

Bool virtio_blk_read_sectors(U64 lba, U32 count, U8* buffer) {
    if (!virtio_blk_is_present() || !buffer || count == 0) return FALSE;

    while (count > 0) {
        U32 chunk = (count > VIRTIO_BLK_MAX_SECTORS) ? VIRTIO_BLK_MAX_SECTORS : count;
        if (!virtio_blk_transfer_sync(lba, chunk, buffer, FALSE)) {
            return FALSE;
        }
        lba += chunk;
        buffer += chunk * VIRTIO_BLK_SECTOR_SIZE;
        count -= chunk;
    }
    return TRUE;
}

Bool virtio_blk_write_sectors(U64 lba, U32 count, const U8* buffer) {
    if (!virtio_blk_is_present() || !buffer || count == 0) return FALSE;

    while (count > 0) {
        U32 chunk = (count > VIRTIO_BLK_MAX_SECTORS) ? VIRTIO_BLK_MAX_SECTORS : count;
        if (!virtio_blk_transfer_sync(lba, chunk, (U8*)buffer, TRUE)) {
            return FALSE;
        }
        lba += chunk;
        buffer += chunk * VIRTIO_BLK_SECTOR_SIZE;
        count -= chunk;
    }
    return TRUE;
}

// ----------------------------------------------------------------------------
// Telemetry & Hardware Benchmarks
// ----------------------------------------------------------------------------

U0 virtio_blk_dump_telemetry(U0) {
    kprintf("\n================ [ VIRTIO-BLOCK STORAGE CONTROLLER ] ================\n");
    if (!virtio_blk_is_present()) {
        kprintf("Status          : NOT DETECTED (No VirtIO-Block device on PCI Bus)\n");
        kprintf("====================================================================\n\n");
        return;
    }

    VirtIOBlkInfo* info = virtio_blk_get_info();
    kprintf("Device Model    : %s\n", info->model);
    kprintf("Serial Number   : %s\n", info->serial);
    kprintf("Total Capacity  : %u MB (%u Sectors)\n",
            (U32)(info->capacity_bytes / (1024 * 1024)), (U32)info->total_sectors);
    kprintf("Sector Size     : %u Bytes\n", info->blk_size);
    kprintf("VirtQueue Size  : %u Descriptors (Split Ring)\n", info->queue_size);
    kprintf("DMA Mode        : 64-Bit Bus Mastering Physical DMA\n");
    kprintf("PCI ECAM Base   : 0x%p\n", (void*)g_blk_dev.dev_ecam);
    kprintf("Common CFG MMIO : 0x%p\n", (void*)g_blk_dev.common_cfg);
    kprintf("Notify MMIO     : 0x%p (mult=%u)\n",
            (void*)g_blk_dev.notify_base, g_blk_dev.notify_off_multiplier);
    kprintf("====================================================================\n\n");
}

Bool virtio_blk_benchmark(U0) {
    if (!virtio_blk_is_present()) {
        kprintf("[VIRTIO-BLK] Cannot run benchmark: Device not present.\n");
        return FALSE;
    }

    kprintf("\n================ [ VIRTIO-BLOCK HARDWARE DMA BENCHMARK ] ================\n");
    kprintf("Testing Real-Time DMA Throughput on VirtIO-Block Device...\n");

    // Allocate 32 KB scratch buffer (64 sectors)
    U32 test_sectors = 64;
    U32 buf_size = test_sectors * VIRTIO_BLK_SECTOR_SIZE;
    U8* test_buf = (U8*)Malloc(buf_size);
    if (!test_buf) {
        kprintf("Error: Failed to allocate test buffer.\n");
        return FALSE;
    }

    // 1. Benchmark Sequential Read (1000 transfers of 32 KB = 32 MB)
    U32 iterations = 500;
    U64 start_time = timer_get_uptime_ms();

    for (U32 i = 0; i < iterations; i++) {
        // Read from different sectors within first 4096 LBAs
        U64 lba = (i * test_sectors) % 4096;
        if (!virtio_blk_read_sectors(lba, test_sectors, test_buf)) {
            kprintf("Error during benchmark read at LBA %u.\n", (U32)lba);
            Free(test_buf);
            return FALSE;
        }
    }

    U64 elapsed_ms = timer_get_uptime_ms() - start_time;
    if (elapsed_ms == 0) elapsed_ms = 1;

    U64 total_kb = (iterations * buf_size) / 1024;
    U32 mb_sec = (U32)((total_kb * 1000) / (elapsed_ms * 1024));
    U32 iops = (U32)((iterations * 1000) / elapsed_ms);

    kprintf("Sequential Read Performance:\n");
    kprintf("  - Data Transferred   : %u MB (%u Requests of 32 KB)\n", (U32)(total_kb / 1024), iterations);
    kprintf("  - Elapsed Time       : %u ms\n", (U32)elapsed_ms);
    kprintf("  - DMA Throughput     : %u MB/sec\n", mb_sec);
    kprintf("  - Transfer IOPS      : %u IOPS\n", iops);
    kprintf("  - Latency per 32KB   : %u microseconds\n", (U32)((elapsed_ms * 1000) / iterations));

    Free(test_buf);
    kprintf("=========================================================================\n\n");
    return TRUE;
}
