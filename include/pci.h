#ifndef PCI_H
#define PCI_H

#include "types.h"

// PCI Express on QEMU virt: ECAM configuration space, bus 0. Devices get
// their memory BARs from one shared allocator in the 32-bit MMIO window.
// The boards' PCIe controllers differ and are not handled yet.
#define PCI_ECAM_BASE          0x30000000ULL
#define PCI_SLOT_COUNT         32
#define PCI_FUNC_COUNT         8

#define PCI_REG_VENDOR_ID      0x00
#define PCI_REG_DEVICE_ID      0x02
#define PCI_REG_COMMAND        0x04
#define PCI_REG_STATUS         0x06
#define PCI_REG_CLASS_REV      0x08
#define PCI_REG_HEADER_TYPE    0x0E
#define PCI_REG_BAR0           0x10
#define PCI_REG_CAP_PTR        0x34

#define PCI_STATUS_CAP_LIST    0x10
#define PCI_CAP_ID_VNDR        0x09
#define PCI_CMD_MEMORY         0x02
#define PCI_CMD_BUS_MASTER     0x04

typedef struct {
    uintptr_t ecam;         // configuration space of this function
    U8  slot, func;
    U16 vendor, device;
    U8  class_code, subclass, prog_if;
    uintptr_t bar[6];       // assigned memory BAR addresses (0: none or I/O)
    U64 bar_size[6];
    Bool enabled;           // BARs assigned, memory decoding and bus mastering on
} PciDevice;

uintptr_t pci_ecam(U32 slot, U32 func);

// Enumerate bus 0. Returns how many functions were found (at most max).
U32  pci_scan(PciDevice* out, U32 max);
// The index-th function (0-based) with this class/subclass, or with this
// vendor/device. FALSE if there is none.
Bool pci_find_class(U8 class_code, U8 subclass, U32 index, PciDevice* out);
Bool pci_find_id(U16 vendor, U16 device, U32 index, PciDevice* out);

// Assign the memory BARs (shared allocator), then enable memory decoding and
// bus mastering. Calling it again for the same function keeps its BARs.
Bool pci_enable(PciDevice* dev);

U0   pci_print(U0);        // console: `pci`

#endif // PCI_H
