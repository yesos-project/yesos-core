#ifndef PORTS_H
#define PORTS_H

#include "types.h"

// Memory-Mapped I/O (MMIO) primitives for RISC-V 64-bit
static inline uint8_t mmio_read8(uintptr_t addr) {
    return *(volatile uint8_t*)addr;
}
static inline void mmio_write8(uintptr_t addr, uint8_t val) {
    *(volatile uint8_t*)addr = val;
}
static inline uint16_t mmio_read16(uintptr_t addr) {
    return *(volatile uint16_t*)addr;
}
static inline void mmio_write16(uintptr_t addr, uint16_t val) {
    *(volatile uint16_t*)addr = val;
}
static inline uint32_t mmio_read32(uintptr_t addr) {
    return *(volatile uint32_t*)addr;
}
static inline void mmio_write32(uintptr_t addr, uint32_t val) {
    *(volatile uint32_t*)addr = val;
}
static inline uint64_t mmio_read64(uintptr_t addr) {
    return *(volatile uint64_t*)addr;
}
static inline void mmio_write64(uintptr_t addr, uint64_t val) {
    *(volatile uint64_t*)addr = val;
}

static inline U0 cli(U0) {
    // Clear MIE (Machine Interrupt Enable) in mstatus (bit 3)
    __asm__ __volatile__("csrc mstatus, %0" : : "r"(1ULL << 3) : "memory");
}

static inline U0 sti(U0) {
    // Set MIE in mstatus (bit 3)
    __asm__ __volatile__("csrs mstatus, %0" : : "r"(1ULL << 3) : "memory");
}

static inline U0 hlt(U0) {
    __asm__ __volatile__("wfi");
}

static inline U0 smp_fence(U0) {
    __asm__ __volatile__("fence rw, rw" ::: "memory");
}

static inline U0 smp_pause(U0) {
    __asm__ __volatile__("nop");
}

static inline U32 smp_hart_id(U0) {
    U64 id = 0;
    __asm__ __volatile__("csrr %0, mhartid" : "=r"(id));
    return (U32)id;
}

#endif // PORTS_H
