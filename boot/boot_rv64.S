/*
 * YesOS 2.0 - RISC-V 64-bit Bare-Metal Boot Entry (RV64GC)
 * Machine Mode (M-Mode) Multi-Hart Boot Entry Point for QEMU virt board
 */

.section .text.boot
.global _start
.type _start, @function

_start:
    /* Disable interrupts globally in M-Mode during boot */
    csrw mstatus, zero
    csrw mie, zero

    /* Enable Floating Point Unit (FPU) & Vector Unit (RVV 1.0) in M-Mode:
     * mstatus.FS = 11b (Dirty, bits 14:13 = 0x6000)
     * mstatus.VS = 11b (Dirty, bits 10:9  = 0x0600)
     */
    li t0, (3 << 13) | (3 << 9)
    csrs mstatus, t0
    csrw fcsr, zero

    /* Read hardware thread ID */
    csrr a0, mhartid

    /* Branch: Hart 0 (BSP) vs Secondary Harts (AP: Hart 1, 2, 3...) */
    bnez a0, .Lsecondary_hart_entry

    /* =========================================================================
     * PRIMARY HART (Hart 0) BOOTSTRAP
     * ========================================================================= */
    /* Set up stack pointer for Hart 0 (top of Hart 0 stack: bottom + 64KB) */
    la t1, _hart_stacks_bottom
    li t2, 65536
    add sp, t1, t2

    /* Set up trap vector table (Direct Mode: BASE[63:2] | 00) */
    la t0, trap_vector
    csrw mtvec, t0

    /* Clear BSS section */
    la t0, _bss_start
    la t1, _bss_end
.Lbss_clear_loop:
    bgeu t0, t1, .Lbss_done
    sd zero, 0(t0)
    addi t0, t0, 8
    j .Lbss_clear_loop
.Lbss_done:

    /* Ensure BSS zeroing is fully committed to memory */
    fence rw, w

    /* Release secondary harts waiting for BSS clearance */
    la t0, g_smp_boot_release
    li t1, 1
    sd t1, 0(t0)
    fence w, rw

    /* Preserve DTB pointer passed by QEMU in a1 */
    mv s1, a1

    /* Call YesOS Kernel Main entry point on Hart 0 */
    csrr a0, mhartid        /* Arg 0: Hart ID (0) */
    mv a1, s1               /* Arg 1: Device Tree Blob physical address */
    call KernelMain

    /* If KernelMain returns, halt CPU */
.Lhalt_loop:
    wfi
    j .Lhalt_loop

    /* =========================================================================
     * SECONDARY HARTS (Hart 1..7) BOOTSTRAP
     * ========================================================================= */
.Lsecondary_hart_entry:
    /* Check bounds: only support up to 8 harts (0..7) */
    li t0, 8
    bgeu a0, t0, .Lpark_hart

    /* Calculate dedicated 64 KB stack pointer for this hart:
     * sp = _hart_stacks_bottom + 65536 * (hartid + 1)
     */
    la t1, _hart_stacks_bottom
    li t2, 65536
    addi t3, a0, 1          /* (hartid + 1) */
    mul t3, t3, t2
    add sp, t1, t3

    /* Set up trap vector table for this hart */
    la t0, trap_vector
    csrw mtvec, t0

    /* Spin-wait until Hart 0 signals that BSS is cleared */
    la t0, g_smp_boot_release
.Lwait_release_loop:
    ld t1, 0(t0)
    bnez t1, .Lrelease_done
    nop
    j .Lwait_release_loop
.Lrelease_done:
    fence r, rw

    /* Enter C runtime for secondary hart */
    csrr a0, mhartid        /* Arg 0: Hart ID */
    call smp_secondary_entry

.Lpark_hart:
    /* Park CPU core if unused or invalid */
    wfi
    j .Lpark_hart

.size _start, . - _start

/* Boot Data: Flag in .data to synchronize secondary harts safely */
.section .data
.align 8
.global g_smp_boot_release
g_smp_boot_release:
    .dword 0

/* Per-Hart Stack Allocation: 64 KB per Hart x 8 Harts = 512 KB */
.section .bss
.align 16
.global _hart_stacks_bottom
_hart_stacks_bottom:
    .space 65536 * 8
.global _hart_stacks_top
_hart_stacks_top:
