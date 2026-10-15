// PCI Express enumeration and BAR assignment (QEMU virt ECAM, bus 0).
// One allocator for every driver, so devices never get overlapping BARs.
#include "pci.h"
#include "ports.h"
#include "kprintf.h"
#include "memory.h"

// QEMU virt 32-bit PCI MMIO window: [0x40000000, 0x80000000).
#define PCI_MMIO_START  0x40000000ULL
#define PCI_MMIO_END    0x80000000ULL
#define PCI_MAX_ENABLED 32

static uintptr_t s_next_mmio = PCI_MMIO_START;
static PciDevice s_enabled[PCI_MAX_ENABLED];
static U32 s_enabled_count = 0;

uintptr_t pci_ecam(U32 slot, U32 func) {
    return PCI_ECAM_BASE + ((uintptr_t)slot << 15) + ((uintptr_t)func << 12);
}

static Bool read_function(U32 slot, U32 func, PciDevice* d) {
    uintptr_t ecam = pci_ecam(slot, func);
    U32 id = mmio_read32(ecam + PCI_REG_VENDOR_ID);
    if ((id & 0xFFFF) == 0xFFFF || (id & 0xFFFF) == 0) return FALSE;
    MemSet(d, 0, sizeof(*d));
    U32 cr = mmio_read32(ecam + PCI_REG_CLASS_REV);
    d->ecam = ecam;
    d->slot = (U8)slot;
    d->func = (U8)func;
    d->vendor = (U16)(id & 0xFFFF);
    d->device = (U16)(id >> 16);
    d->class_code = (U8)(cr >> 24);
    d->subclass = (U8)(cr >> 16);
    d->prog_if = (U8)(cr >> 8);
    for (U32 i = 0; i < s_enabled_count; i++) {
        if (s_enabled[i].ecam == ecam) {
            MemCpy(d->bar, s_enabled[i].bar, sizeof(d->bar));
            MemCpy(d->bar_size, s_enabled[i].bar_size, sizeof(d->bar_size));
            d->enabled = TRUE;
            break;
        }
    }
    return TRUE;
}

U32 pci_scan(PciDevice* out, U32 max) {
    U32 n = 0;
    for (U32 slot = 0; slot < PCI_SLOT_COUNT; slot++) {
        for (U32 func = 0; func < PCI_FUNC_COUNT; func++) {
            PciDevice d;
            if (!read_function(slot, func, &d)) {
                if (func == 0) break;
                continue;
            }
            if (out && n < max) out[n] = d;
            n++;
            if (func == 0 && !(mmio_read8(d.ecam + PCI_REG_HEADER_TYPE) & 0x80)) break;   // single-function
        }
    }
    return n < max ? n : max;
}

static Bool find(Bool by_class, U16 a, U16 b, U32 index, PciDevice* out) {
    PciDevice list[PCI_SLOT_COUNT];
    U32 n = pci_scan(list, PCI_SLOT_COUNT);
    for (U32 i = 0; i < n; i++) {
        Bool match = by_class ? (list[i].class_code == a && list[i].subclass == b)
                              : (list[i].vendor == a && list[i].device == b);
        if (match && index-- == 0) {
            if (out) *out = list[i];
            return TRUE;
        }
    }
    return FALSE;
}

Bool pci_find_class(U8 class_code, U8 subclass, U32 index, PciDevice* out) {
    return find(TRUE, class_code, subclass, index, out);
}

Bool pci_find_id(U16 vendor, U16 device, U32 index, PciDevice* out) {
    return find(FALSE, vendor, device, index, out);
}

Bool pci_enable(PciDevice* dev) {
    if (!dev || !dev->ecam) return FALSE;
    for (U32 i = 0; i < s_enabled_count; i++) {
        if (s_enabled[i].ecam == dev->ecam) {
            MemCpy(dev->bar, s_enabled[i].bar, sizeof(dev->bar));
            MemCpy(dev->bar_size, s_enabled[i].bar_size, sizeof(dev->bar_size));
            dev->enabled = TRUE;
            return TRUE;
        }
    }
    if (s_enabled_count >= PCI_MAX_ENABLED) return FALSE;

    uintptr_t ecam = dev->ecam;
    U16 cmd = mmio_read16(ecam + PCI_REG_COMMAND);
    mmio_write16(ecam + PCI_REG_COMMAND, cmd & ~(PCI_CMD_MEMORY | PCI_CMD_BUS_MASTER));   // no decoding while sizing

    for (U32 i = 0; i < 6; i++) {
        dev->bar[i] = 0;
        dev->bar_size[i] = 0;
        uintptr_t reg = ecam + PCI_REG_BAR0 + i * 4;
        U32 orig = mmio_read32(reg);
        mmio_write32(reg, 0xFFFFFFFF);
        U32 probed = mmio_read32(reg);
        mmio_write32(reg, orig);
        if (probed == 0 || probed == 0xFFFFFFFF || (probed & 1)) continue;   // absent or I/O BAR

        Bool is64 = ((probed >> 1) & 3) == 2 && i < 5;
        U64 mask = probed & ~0xFULL;
        if (is64) {
            uintptr_t hreg = reg + 4;
            U32 horig = mmio_read32(hreg);
            mmio_write32(hreg, 0xFFFFFFFF);
            mask |= (U64)mmio_read32(hreg) << 32;
            mmio_write32(hreg, horig);
        } else {
            mask |= 0xFFFFFFFF00000000ULL;
        }
        U64 size = ~mask + 1;
        if (size < 0x1000) size = 0x1000;

        uintptr_t base = (s_next_mmio + size - 1) & ~(uintptr_t)(size - 1);
        if (base + size > PCI_MMIO_END) {
            kprintf("[PCI] %02x.%u: no room for a %u KiB BAR %u\n", dev->slot, dev->func, (U32)(size >> 10), i);
            mmio_write16(ecam + PCI_REG_COMMAND, cmd);
            return FALSE;
        }
        mmio_write32(reg, (U32)base);
        if (is64) mmio_write32(reg + 4, (U32)((U64)base >> 32));
        dev->bar[i] = base;
        dev->bar_size[i] = size;
        s_next_mmio = base + size;
        if (is64) i++;
    }

    mmio_write16(ecam + PCI_REG_COMMAND, cmd | PCI_CMD_MEMORY | PCI_CMD_BUS_MASTER);
    dev->enabled = TRUE;
    s_enabled[s_enabled_count++] = *dev;
    return TRUE;
}

static const char* kind(const PciDevice* d) {
    if (d->vendor == 0x1AF4) {
        switch (d->device) {
            case 0x1000: case 0x1041: return "virtio-net";
            case 0x1001: case 0x1042: return "virtio-blk";
            case 0x1050: return "virtio-gpu";
            case 0x1052: return "virtio-input";
            default: return "virtio";
        }
    }
    if (d->class_code == 0x04 && d->subclass == 0x03) return "HD Audio controller";
    if (d->class_code == 0x06 && d->subclass == 0x00) return "host bridge";
    if (d->class_code == 0x03) return "display";
    return "";
}

U0 pci_print(U0) {
    PciDevice list[PCI_SLOT_COUNT];
    U32 n = pci_scan(list, PCI_SLOT_COUNT);
    kprintf("PCI bus 0 (ECAM 0x%p): %u function(s)\n", (void*)PCI_ECAM_BASE, n);
    for (U32 i = 0; i < n; i++) {
        PciDevice* d = &list[i];
        kprintf("  %02x.%u  %04x:%04x  class %02x.%02x  %s\n", d->slot, d->func, d->vendor, d->device,
                d->class_code, d->subclass, kind(d));
        for (U32 b = 0; b < 6; b++) {
            if (d->bar[b]) kprintf("        BAR%u 0x%p (%u KiB)\n", b, (void*)d->bar[b], (U32)(d->bar_size[b] >> 10));
        }
    }
}
