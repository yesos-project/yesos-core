#ifndef BARRETT_POLY_H
#define BARRETT_POLY_H

#include "types.h"

// ----------------------------------------------------------------------------
// YesOS Barrett Polynomial Reduction in GF(2) with RISC-V Zbc (clmul/clmulh)
// Irreducible Polynomial: CRC-64-ECMA (P(x) = x^64 + x^62 + x^57 + ... + 1)
// ----------------------------------------------------------------------------

#define BARRETT_POLY_LO   0x42F0E1EBA9EA3693ULL
#define BARRETT_MU_LO     0x578D29D06CC4F872ULL

U64  barrett_poly_reduce_128(U64 t_hi, U64 t_lo);
U64  barrett_crc64_sector(const U8* data, size_t len);
U64  barrett_crc64_stream_parallel4(const U8* data, size_t len);
U0   barrett_poly_benchmark(U0);

#endif // BARRETT_POLY_H
