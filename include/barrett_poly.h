#ifndef BARRETT_POLY_H
#define BARRETT_POLY_H

#include "types.h"

// RedSea's checksum, computed with the RISC-V Zbc carry-less multiply.
//
// For each little-endian 64-bit word w of the data (a short last word is
// zero-padded): crc = (crc ^ w) * x^64 mod P, with P the CRC-64-ECMA
// polynomial taken most significant bit first; crc starts at all ones and is
// inverted at the end. The reduction mod P is Barrett's, with mu =
// floor(x^128 / P). It is a polynomial code, but NOT one of the standard
// CRC-64 variants (CRC-64/XZ, CRC-64/ECMA-182): the words' bits are taken in
// another order. RedSea stores its low 32 bits per file; tools/redsea_fsck.py
// computes the same function on the host.

#define BARRETT_POLY_LO   0x42F0E1EBA9EA3693ULL
#define BARRETT_MU_LO     0x578D29D06CC4F872ULL

U64  barrett_poly_reduce_128(U64 t_hi, U64 t_lo);
U64  barrett_crc64_sector(const U8* data, size_t len);
U0   barrett_poly_benchmark(U0);         // console: `barrett`, checks against a bit-by-bit reference

#endif // BARRETT_POLY_H
