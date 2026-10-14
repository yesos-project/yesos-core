#ifndef DNSBLOCK_H
#define DNSBLOCK_H

#include "types.h"

// DNS filter for the LAN (Pi-hole style): the engine is rust_core/src/dns.rs;
// this glue keeps its configuration (SYS/DNS.CFG) and lists
// (SYS/DNSLIST/<name>.txt) on disk and connects it to the network, the web
// panel and the console.

U0   dnsblock_init(U0);
U0   dnsblock_poll(U0);
U0   dnsblock_refresh_upstream(U0);   // after the NAS's address changes
// Every received UDP datagram (addresses in host byte order). TRUE if it was DNS.
Bool dnsblock_udp(U32 src_ip, const U8* src_mac, U16 src_port, U16 dst_port, const U8* data, size_t len);
// Panel actions "dns_*" (HTTP-like status, message in msg).
I32  dnsblock_action(const char* action, const char* name, const char* value, char* msg, size_t msg_max);
// Uploaded list (hosts file or one domain per line).
I32  dnsblock_list_store(const char* name, const U8* data, size_t len, char* msg, size_t msg_max);
U0   dnsblock_shell(const char* args);

#endif // DNSBLOCK_H
