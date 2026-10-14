#ifndef MEMORY_H
#define MEMORY_H

#include "types.h"

#define HEAP_MAGIC       0x5945534F534D454DLL // "YESOSMEM"
#define HEAP_CANARY_TAIL 0x5945534F5343414EULL // "YESOSCAN"
#define MEM_POISON_FREE  0xDF                  // Dead Free memory pattern
#define MEM_POISON_ALLOC 0xCD                  // Clean Dynamic allocation pattern

typedef struct BlockHeader {
    U64 magic;              // HEAP_MAGIC
    U64 size;               // Total block payload capacity (bytes)
    U64 requested_size;     // Exact size requested by caller (for tail canary)
    Bool is_free;           // Allocation status
    U8  pad[7];             // Align pointer to 8 bytes
    struct BlockHeader* next;
    struct BlockHeader* prev;
    U64 align_padding;      // Strict 16-byte alignment padding (64 bytes total)
} __attribute__((aligned(16))) BlockHeader;

typedef struct {
    U64 total_ram;
    U64 free_ram;
    U64 heap_start;
    U64 heap_end;
    U64 heap_used;
    U64 num_allocations;
    // Security & Hardening Telemetry
    U64 double_frees_prevented;
    U64 heap_overflows_detected;
    U64 invalid_ptrs_rejected;
} MemStats;

// Core Memory Functions
U0   mem_init(U64 ram_size_bytes);
void* Malloc(size_t size);
void* Calloc(size_t num, size_t size);
U0    Free(void* ptr);


// String & Memory primitives
void* MemSet(void* dest, I32 val, size_t count);
void* MemCpy(void* dest, const void* src, size_t count);
I32   MemCmp(const void* s1, const void* s2, size_t count);
void* memcpy(void* dest, const void* src, size_t count);
void* memset(void* dest, int val, size_t count);
void* memmove(void* dest, const void* src, size_t count);
size_t StrLen(const char* str);
char*  StrCpy(char* dest, const char* src);
char*  StrNCpy(char* dest, const char* src, size_t n);
char*  StrNCat(char* dest, const char* src, size_t n);
I32    StrCmp(const char* s1, const char* s2);
I32    StrNCmp(const char* s1, const char* s2, size_t n);
I32    StrICmp(const char* s1, const char* s2);
I32    StrNICmp(const char* s1, const char* s2, size_t n);

// Hardening & Memory Self-Test
typedef struct {
    Bool executed;
    Bool str_ok;
    Bool df_ok;
    Bool poison_ok;
    Bool can_ok;
    Bool heap_ok;
    Bool all_passed;
    U32  total_passed;
    U32  total_tests;
    U64  timestamp_ticks;
} SecurityAuditState;

Bool                 mem_verify_heap_integrity(U0);
U0                   demo_kernel_hardening_suite(U0);
SecurityAuditState*  mem_get_security_audit_state(U0);

MemStats mem_get_stats(U0);
U32      mem_get_heap_block_counts(U32* out_free, U32* out_used);

#endif // MEMORY_H
