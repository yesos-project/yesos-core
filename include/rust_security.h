#ifndef RUST_SECURITY_H
#define RUST_SECURITY_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

// Returns 1 if frame is clean / permitted; 0 if Ring -3 threat detected (Intel ME / AMD PSP / NC-SI)
I32 rust_filter_packet(const U8* buf, size_t len);

// Returns Shannon entropy in fixed-point (scaled by 1000, e.g. 7850 = 7.850 bits/byte)
U32 rust_shannon_entropy(const U8* buf, size_t len);

// Returns Shannon entropy as float [0.0f .. 8.0f]
float rust_shannon_entropy_float(const U8* buf, size_t len);

// Native Bare-Metal Micro-TCP & WebUI Server Handler
I32 rust_handle_tcp(const U8* buf, size_t len, size_t ip_hdr_len);
// Retransmissions and idle-connection cleanup for the HTTP/WebDAV TCP layer
U0  rust_tcp_tick(U0);

#define RUST_RANSOMWARE_ENTROPY_THRESH_FP 7800

#ifdef __cplusplus
}
#endif

#endif // RUST_SECURITY_H
