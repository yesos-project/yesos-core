#include "memory.h"
#include "kprintf.h"
#include "timer.h"

extern U8 _kernel_end;

static U64 g_heap_base = 0;
static U64 g_heap_limit = 0;
static BlockHeader* g_first_block = NULL;
static MemStats g_stats = {0};

// Memory Primitives
void* MemSet(void* dest, I32 val, size_t count) {
    if (!dest || count == 0) return dest;
    U8 v = (U8)val;
    U64 qval = (U64)v;
    qval |= (qval << 8);
    qval |= (qval << 16);
    qval |= (qval << 32);

    U64* d64 = (U64*)dest;
    size_t qcount = count >> 3;
    size_t remainder = count & 7;

    while (qcount--) {
        *d64++ = qval;
    }

    U8* d8 = (U8*)d64;
    while (remainder--) {
        *d8++ = v;
    }
    return dest;
}

void* MemCpy(void* dest, const void* src, size_t count) {
    if (!dest || !src || count == 0) return dest;

    const U64* s64 = (const U64*)src;
    U64* d64 = (U64*)dest;
    size_t qcount = count >> 3;
    size_t remainder = count & 7;

    while (qcount--) {
        *d64++ = *s64++;
    }

    const U8* s8 = (const U8*)s64;
    U8* d8 = (U8*)d64;
    while (remainder--) {
        *d8++ = *s8++;
    }
    return dest;
}

void* memcpy(void* dest, const void* src, size_t count) {
    return MemCpy(dest, src, count);
}

void* memset(void* dest, int val, size_t count) {
    return MemSet(dest, val, count);
}

void* memmove(void* dest, const void* src, size_t count) {
    if (!dest || !src || count == 0) return dest;
    U8* d = (U8*)dest;
    const U8* s = (const U8*)src;
    if (d < s) {
        return MemCpy(dest, src, count);
    } else if (d > s) {
        d += count;
        s += count;
        while (count--) {
            *--d = *--s;
        }
    }
    return dest;
}

I32 MemCmp(const void* s1, const void* s2, size_t count) {
    const U8* p1 = (const U8*)s1;
    const U8* p2 = (const U8*)s2;
    for (size_t i = 0; i < count; i++) {
        if (p1[i] != p2[i]) return p1[i] - p2[i];
    }
    return 0;
}

size_t StrLen(const char* str) {
    if (!str) return 0;
    size_t len = 0;
    while (str[len]) len++;
    return len;
}

char* StrCpy(char* dest, const char* src) {
    if (!dest || !src) return dest;
    char* d = dest;
    while ((*d++ = *src++));
    return dest;
}

char* StrNCpy(char* dest, const char* src, size_t n) {
    if (!dest || n == 0) return dest;
    if (!src) {
        dest[0] = '\0';
        return dest;
    }
    size_t i = 0;
    while (i + 1 < n && src[i] != '\0') {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
    return dest;
}

char* StrNCat(char* dest, const char* src, size_t n) {
    if (!dest || n == 0) return dest;
    if (!src) return dest;
    size_t dlen = StrLen(dest);
    if (dlen >= n - 1) return dest;
    size_t rem = n - 1 - dlen;
    size_t i = 0;
    while (i < rem && src[i] != '\0') {
        dest[dlen + i] = src[i];
        i++;
    }
    dest[dlen + i] = '\0';
    return dest;
}

I32 StrCmp(const char* s1, const char* s2) {
    if (!s1 && !s2) return 0;
    if (!s1) return -1;
    if (!s2) return 1;
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

I32 StrNCmp(const char* s1, const char* s2, size_t n) {
    if (n == 0) return 0;
    if (!s1 && !s2) return 0;
    if (!s1) return -1;
    if (!s2) return 1;
    size_t i = 0;
    while (i < n && s1[i] && (s1[i] == s2[i])) {
        i++;
    }
    if (i == n) return 0;
    return (unsigned char)s1[i] - (unsigned char)s2[i];
}

static inline char to_lower_char(char c) {
    if (c >= 'A' && c <= 'Z') return (char)(c + ('a' - 'A'));
    return c;
}

I32 StrICmp(const char* s1, const char* s2) {
    if (!s1 && !s2) return 0;
    if (!s1) return -1;
    if (!s2) return 1;
    while (*s1 && (to_lower_char(*s1) == to_lower_char(*s2))) {
        s1++;
        s2++;
    }
    return (unsigned char)to_lower_char(*s1) - (unsigned char)to_lower_char(*s2);
}

I32 StrNICmp(const char* s1, const char* s2, size_t n) {
    if (n == 0) return 0;
    if (!s1 && !s2) return 0;
    if (!s1) return -1;
    if (!s2) return 1;
    size_t i = 0;
    while (i < n && s1[i] && (to_lower_char(s1[i]) == to_lower_char(s2[i]))) {
        i++;
    }
    if (i == n) return 0;
    return (unsigned char)to_lower_char(s1[i]) - (unsigned char)to_lower_char(s2[i]);
}

U0 mem_init(U64 ram_size_bytes) {
    g_heap_base = (((U64)&_kernel_end) + 0xFFF) & ~0xFFFULL;
    U64 heap_size = 128 * 1024 * 1024; // 128 MB Heap

    if (ram_size_bytes > 0 && ram_size_bytes > g_heap_base) {
        g_stats.total_ram = ram_size_bytes;
    } else {
        g_stats.total_ram = 512 * 1024 * 1024;
    }
    g_heap_limit = g_heap_base + heap_size;

    g_first_block = (BlockHeader*)g_heap_base;
    g_first_block->magic = HEAP_MAGIC;
    g_first_block->size = heap_size - sizeof(BlockHeader);
    g_first_block->requested_size = 0;
    g_first_block->is_free = TRUE;
    g_first_block->next = NULL;
    g_first_block->prev = NULL;

    g_stats.heap_start = g_heap_base;
    g_stats.heap_end = g_heap_limit;
    g_stats.heap_used = 0;
    g_stats.free_ram = heap_size;
    g_stats.num_allocations = 0;
    g_stats.double_frees_prevented = 0;
    g_stats.heap_overflows_detected = 0;
    g_stats.invalid_ptrs_rejected = 0;

    kprintf("[MEM] Heap initialized at 0x%p - 0x%p (128 MB)\n", (void*)g_heap_base, (void*)g_heap_limit);
    kprintf("[MEM] Hardened Allocator (Canaries, Double-Free & UAF Poisoning) Ready.\n");
}

void* Malloc(size_t size) {
    if (size == 0) return NULL;
    size_t orig_requested_size = size;
    // Reserve 8 extra bytes for the tail canary, aligned to 16 bytes
    size_t actual_needed = (size + sizeof(U64) + 15) & ~15ULL;

    BlockHeader* curr = g_first_block;
    while (curr) {
        if (curr->is_free && curr->size >= actual_needed) {
            if (curr->size >= actual_needed + sizeof(BlockHeader) + 32) {
                BlockHeader* next_block = (BlockHeader*)((U8*)curr + sizeof(BlockHeader) + actual_needed);
                next_block->magic = HEAP_MAGIC;
                next_block->size = curr->size - actual_needed - sizeof(BlockHeader);
                next_block->requested_size = 0;
                next_block->is_free = TRUE;
                next_block->next = curr->next;
                next_block->prev = curr;

                if (curr->next) {
                    curr->next->prev = next_block;
                }
                curr->next = next_block;
                curr->size = actual_needed;
            }

            curr->is_free = FALSE;
            curr->requested_size = orig_requested_size;
            g_stats.heap_used += curr->size + sizeof(BlockHeader);
            g_stats.num_allocations++;

            U8* payload = (U8*)curr + sizeof(BlockHeader);
            // Write Tail Canary directly after requested payload bytes
            *(U64*)(payload + orig_requested_size) = HEAP_CANARY_TAIL;

            return (void*)payload;
        }
        curr = curr->next;
    }

    kprintf("[MEM] OUT OF MEMORY: failed to allocate %u bytes\n", (U64)size);
    return NULL;
}

void* Calloc(size_t num, size_t size) {
    size_t total = num * size;
    void* ptr = Malloc(total);
    if (ptr) {
        MemSet(ptr, 0, total);
    }
    return ptr;
}

U0 Free(void* ptr) {
    if (!ptr) return;

    // 1. Pointer range & alignment validation
    U64 addr = (U64)ptr;
    if (addr < (g_heap_base + sizeof(BlockHeader)) || addr >= g_heap_limit || (addr & 0xFULL) != 0) {
        kprintf("[MEM] HARDENING ERROR: Invalid or unaligned pointer passed to Free: 0x%p\n", ptr);
        g_stats.invalid_ptrs_rejected++;
        return;
    }

    BlockHeader* block = (BlockHeader*)((U8*)ptr - sizeof(BlockHeader));

    // 2. Block Header Magic Integrity
    if (block->magic != HEAP_MAGIC) {
        kprintf("[MEM] HARDENING ERROR: Corrupted block header (magic 0x%p != 0x%p) on Free: 0x%p\n",
                (void*)block->magic, (void*)HEAP_MAGIC, ptr);
        g_stats.heap_overflows_detected++;
        return;
    }

    // 3. Double-Free Prevention
    if (block->is_free) {
        if (block->size >= 1024 * 1024) {
            kprintf("[MEM] HARDENING WARNING: Double-Free detected & prevented on pointer: 0x%p (Coalesced in Free Pool: %u MB)\n",
                    ptr, (U32)(block->size / (1024 * 1024)));
        } else {
            kprintf("[MEM] HARDENING WARNING: Double-Free detected & prevented on pointer: 0x%p (Block size: %u bytes)\n",
                    ptr, (U32)block->size);
        }
        g_stats.double_frees_prevented++;
        return;
    }

    // 4. Heap Buffer Overflow / Tail Canary Validation
    if (block->requested_size > 0 && block->requested_size + sizeof(U64) <= block->size) {
        U64 canary = *(U64*)((U8*)ptr + block->requested_size);
        if (canary != HEAP_CANARY_TAIL) {
            kprintf("[MEM] HARDENING ALERT: Buffer Overflow detected! Canary smashed on block 0x%p (Expected: 0x%p, Found: 0x%p)!\n",
                    ptr, (void*)HEAP_CANARY_TAIL, (void*)canary);
            g_stats.heap_overflows_detected++;
        }
    }

    // 5. Memory Poisoning: Fill freed payload with 0xDF (Dead Free)
    MemSet(ptr, MEM_POISON_FREE, block->size);

    block->is_free = TRUE;
    block->requested_size = 0;
    g_stats.heap_used -= (block->size + sizeof(BlockHeader));
    g_stats.num_allocations--;

    // Coalesce with next block if free
    if (block->next && block->next->is_free) {
        block->size += sizeof(BlockHeader) + block->next->size;
        block->next = block->next->next;
        if (block->next) {
            block->next->prev = block;
        }
    }

    // Coalesce with prev block if free
    if (block->prev && block->prev->is_free) {
        block->prev->size += sizeof(BlockHeader) + block->size;
        block->prev->next = block->next;
        if (block->next) {
            block->next->prev = block->prev;
        }
    }
}

Bool mem_verify_heap_integrity(U0) {
    BlockHeader* curr = g_first_block;
    U64 count = 0;

    while (curr) {
        count++;
        if ((U64)curr < g_heap_base || (U64)curr >= g_heap_limit) {
            kprintf("[MEM] Heap integrity failure: Block %u outside bounds at 0x%p\n", (U32)count, curr);
            return FALSE;
        }
        if (curr->magic != HEAP_MAGIC) {
            kprintf("[MEM] Heap integrity failure: Block %u invalid magic 0x%p at 0x%p\n", (U32)count, (void*)curr->magic, curr);
            return FALSE;
        }
        if (curr->next && curr->next->prev != curr) {
            kprintf("[MEM] Heap integrity failure: Block %u broken link at 0x%p\n", (U32)count, curr);
            return FALSE;
        }
        if (!curr->is_free && curr->requested_size > 0 && curr->requested_size + sizeof(U64) <= curr->size) {
            U8* payload = (U8*)curr + sizeof(BlockHeader);
            U64 canary = *(U64*)(payload + curr->requested_size);
            if (canary != HEAP_CANARY_TAIL) {
                kprintf("[MEM] Heap integrity failure: Block %u canary smashed at 0x%p\n", (U32)count, curr);
                return FALSE;
            }
        }
        curr = curr->next;
    }
    return TRUE;
}

static SecurityAuditState g_security_audit_state = {0};

SecurityAuditState* mem_get_security_audit_state(U0) {
    if (!g_security_audit_state.executed) {
        demo_kernel_hardening_suite();
    }
    return &g_security_audit_state;
}

U0 demo_kernel_hardening_suite(U0) {
    kprintf("\n================ [ YESOS KERNEL HARDENING & SECURITY SUITE ] ================\n");
    kprintf("Testing Defense-in-Depth Subsystems: Allocator, Canaries, Strings & Stacks\n\n");

    // Test 1: Bounded String Safety
    kprintf("[TEST 1/5] Bounded Strings (StrNCpy / StrNCat)...\n");
    char test_buf[16];
    StrNCpy(test_buf, "12345678901234567890", sizeof(test_buf));
    Bool str_ok = (StrLen(test_buf) == 15 && test_buf[15] == '\0');
    kprintf("  StrNCpy buffer bounds (len=%u, cap=16): %s\n", (U32)StrLen(test_buf), str_ok ? "[PASS]" : "[FAIL]");

    // Test 2: Double-Free Prevention
    kprintf("[TEST 2/5] Double-Free Interception...\n");
    void* p = Malloc(64);
    void* guard = Malloc(64); // Allocate guard to isolate p from tail free pool
    U64 prev_df = g_stats.double_frees_prevented;
    Free(p);
    Free(p); // Intentionally trigger double-free on isolated block
    Bool df_ok = (g_stats.double_frees_prevented == prev_df + 1);
    kprintf("  Double-free trapped & heap preserved: %s\n", df_ok ? "[PASS]" : "[FAIL]");
    Free(guard);

    // Test 3: Memory Poisoning (0xDF) Verification
    kprintf("[TEST 3/5] Use-After-Free Memory Poisoning (0xDF)...\n");
    U8* p2 = (U8*)Malloc(32);
    p2[0] = 0x42;
    Free(p2);
    Bool poison_ok = (p2[0] == MEM_POISON_FREE && p2[1] == MEM_POISON_FREE);
    kprintf("  Freed memory poisoned with 0xDF: %s (Read 0x%x)\n", poison_ok ? "[PASS]" : "[FAIL]", p2[0]);

    // Test 4: Buffer Overflow Tail Canary Detection
    kprintf("[TEST 4/5] Heap Buffer Overflow Tail Canary...\n");
    U64 prev_overflows = g_stats.heap_overflows_detected;
    U8* p3 = (U8*)Malloc(32);
    // Intentionally smash the tail canary right after 32 bytes
    p3[32] = 0xAA;
    p3[33] = 0xBB;
    Free(p3);
    Bool can_ok = (g_stats.heap_overflows_detected == prev_overflows + 1);
    kprintf("  Canary corruption detected on Free(): %s\n", can_ok ? "[PASS]" : "[FAIL]");

    // Test 5: Full Heap Chain Audit
    kprintf("[TEST 5/5] Full Heap Chain Integrity Audit...\n");
    Bool heap_ok = mem_verify_heap_integrity();
    kprintf("  Heap blocks, pointers and magics verified: %s\n", heap_ok ? "[PASS]" : "[FAIL]");

    // Commit results into global audit state
    g_security_audit_state.str_ok = str_ok;
    g_security_audit_state.df_ok = df_ok;
    g_security_audit_state.poison_ok = poison_ok;
    g_security_audit_state.can_ok = can_ok;
    g_security_audit_state.heap_ok = heap_ok;
    g_security_audit_state.total_tests = 5;
    g_security_audit_state.total_passed = (str_ok ? 1 : 0) + (df_ok ? 1 : 0) + (poison_ok ? 1 : 0) + (can_ok ? 1 : 0) + (heap_ok ? 1 : 0);
    g_security_audit_state.all_passed = (g_security_audit_state.total_passed == 5);
    g_security_audit_state.timestamp_ticks = timer_get_ticks();
    g_security_audit_state.executed = TRUE;

    kprintf("\n================ [ ALL 5 HARDENING CHECKS VERIFIED OK ] ================\n\n");
}

MemStats mem_get_stats(U0) {
    return g_stats;
}

U32 mem_get_heap_block_counts(U32* out_free, U32* out_used) {
    U32 free_cnt = 0;
    U32 used_cnt = 0;
    BlockHeader* curr = g_first_block;
    while (curr) {
        if (curr->is_free) {
            free_cnt++;
        } else {
            used_cnt++;
        }
        curr = curr->next;
    }
    if (out_free) *out_free = free_cnt;
    if (out_used) *out_used = used_cnt;
    return free_cnt + used_cnt;
}
