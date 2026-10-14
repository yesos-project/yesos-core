#ifndef LZ4_H
#define LZ4_H

#include "types.h"

#define LZ4_MEMORY_USAGE 14
#define LZ4_HASH_SIZE (1 << LZ4_MEMORY_USAGE)
#define LZ4_HASH_MASK (LZ4_HASH_SIZE - 1)
#define LZ4_MAX_INPUT_SIZE 0x7E000000

// In-Kernel Ultra-Fast LZ4 Streaming Compressor & Decompressor (> 2 GB/s)
I64 lz4_compress_bound(I64 isize);
I64 lz4_compress(const U8* src, I64 src_size, U8* dst, I64 dst_capacity);
I64 lz4_decompress(const U8* src, I64 src_size, U8* dst, I64 dst_capacity);

// Benchmark & Demonstration

#endif // LZ4_H
