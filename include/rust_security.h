#ifndef RUST_SECURITY_H
#define RUST_SECURITY_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

// Returns 1 if frame is clean / permitted; 0 if Ring -3 threat detected (Intel ME / AMD PSP / NC-SI)
I32 rust_filter_packet(const U8* buf, size_t len);

// Native Bare-Metal Micro-TCP & WebUI Server Handler
I32 rust_handle_tcp(const U8* buf, size_t len, size_t ip_hdr_len);
// Retransmissions and idle-connection cleanup for the HTTP/WebDAV TCP layer
U0  rust_tcp_tick(U0);

#ifdef __cplusplus
}
#endif

#endif // RUST_SECURITY_H
