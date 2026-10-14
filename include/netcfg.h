#ifndef NETCFG_H
#define NETCFG_H

#include "types.h"

// Static IPv4 address of the NAS's own stack: "a.b.c.d/nn [gw a.b.c.d]" in
// SYS/NET.CFG, set from the console with `net ip`. Without it the driver's
// default applies (QEMU user network).
typedef U0 (*NetcfgHook)(U0);
U0 netcfg_load(U0);                  // after the volume is mounted
U0 netcfg_shell(const char* args);   // "net ip ..."
U0 netcfg_on_change(NetcfgHook fn);  // called after the address changes (up to 4)

#endif // NETCFG_H
