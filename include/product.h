#ifndef PRODUCT_H
#define PRODUCT_H

#include "types.h"

// Each YesOS product (NAS, Security, Desktop) implements these; the core
// (kernel/main.c) calls them at fixed points of the boot and main loop.

extern const char* const PRODUCT_NAME;   // e.g. "YesOS NAS"

U0 product_early_init(U0);    // after the network drivers, before file systems
U0 product_init(U0);          // after file systems, entropy and vault: services
U0 product_boot_summary(U0);  // product lines of the boot summary
U0 product_poll(U0);          // once per main-loop iteration

#endif // PRODUCT_H
