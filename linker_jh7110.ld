/* YesOS 2.0 - RISC-V 64-bit Linker Script (StarFive JH7110 SoC / VisionFive 2)
 * Memory base: 0x40200000 (Standard U-Boot $kernel_addr_r payload location in DDR)
 */
OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY
{
    RAM (rwx) : ORIGIN = 0x40200000, LENGTH = 1024M
}

/* PMP policy windows. TODO(hardware): verify against the JH7110 memory map.
 * The device window extends to the kernel base and therefore also covers the
 * DDR below it that is used by earlier boot stages. */
_pmp_null_end   = 0x00010000;
_pmp_mmio_start = 0x00010000;
_pmp_mmio_end   = 0x40200000;

SECTIONS
{
    . = ORIGIN(RAM);

    /* Kernel code: PMP R-X (locked) */
    .text : ALIGN(4K) {
        _kernel_start = .;
        *(.text.boot)
        /* PMP cell runtime: the only kernel code a cell can execute */
        . = ALIGN(4K);
        _cell_text_start = .;
        KEEP(*(.cell_text))
        . = ALIGN(4K);
        _cell_text_end = .;
        *(.text .text.*)
        . = ALIGN(4K);
        _text_end = .;
    } > RAM

    /* Read-only data: PMP R-- (locked) */
    .rodata : ALIGN(4K) {
        _rodata_start = .;
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
        _rodata_sec_end = .;
    } > RAM

    /* Certificate written post-link by tools/pmp_prover.py (fixed size) */
    .pmp_proof : ALIGN(8) {
        KEEP(*(.pmp_proof))
    } > RAM

    /* BLAKE2b-256 of .text || .rodata, written post-link by tools/image_hash.py */
    .integrity : ALIGN(8) {
        KEEP(*(.integrity))
    } > RAM

    . = ALIGN(4K);
    _rodata_end = .;

    /* Data, BSS and hart stacks: PMP RW- (locked, never executable) */
    .data : ALIGN(4K) {
        *(.data .data.*)
        *(.sdata .sdata.*)
    } > RAM

    .bss : ALIGN(4K) {
        _bss_start = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
        _bss_end = .;
    } > RAM

    /* JIT arena: the only region that is both writable and executable */
    .jit (NOLOAD) : ALIGN(4K) {
        _jit_start = .;
        *(.jit .jit.*)
        . = ALIGN(4K);
        _jit_end = .;
    } > RAM

    /* Key vault: DEK, Argon2 memory and stack of the key hart (kernel/keyhart.c).
     * PMP-denied on every other hart. */
    .keyvault (NOLOAD) : ALIGN(4K) {
        _keyvault_start = .;
        *(.keyvault .keyvault.*)
        . = ALIGN(4K);
        _keyvault_end = .;
    } > RAM

    /* PMP cell arenas (see include/cell.h): per cell 64 KiB code + 448 KiB data */
    .cell (NOLOAD) : ALIGN(4K) {
        _cell_area_start = .;
        . += 5 * 0x80000;
        _cell_area_end = .;
    } > RAM

    . = ALIGN(4K);
    _kernel_end = .;

    /* Heap and free RAM up to _ram_end: PMP RW- (locked) */
    _ram_start = ORIGIN(RAM);
    _ram_end = ORIGIN(RAM) + LENGTH(RAM);

    /DISCARD/ : {
        *(.eh_frame)
        *(.comment)
    }
}
