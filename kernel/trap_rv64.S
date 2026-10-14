/*
 * YesOS 2.0 - RISC-V 64-bit Trap Handler (M-Mode Interrupts & Exceptions)
 */

.section .text
.global trap_vector
.align 4
.type trap_vector, @function

trap_vector:
    /* Allocate stack frame for 32 registers + CSRs + Vector CSRs (320 bytes, 16-byte aligned) */
    addi sp, sp, -320

    /* Save caller & callee registers */
    sd ra,   0(sp)
    sd t0,   8(sp)
    sd t1,  16(sp)
    sd t2,  24(sp)
    sd s0,  32(sp)
    sd s1,  40(sp)
    sd a0,  48(sp)
    sd a1,  56(sp)
    sd a2,  64(sp)
    sd a3,  72(sp)
    sd a4,  80(sp)
    sd a5,  88(sp)
    sd a6,  96(sp)
    sd a7, 104(sp)
    sd s2, 112(sp)
    sd s3, 120(sp)
    sd s4, 128(sp)
    sd s5, 136(sp)
    sd s6, 144(sp)
    sd s7, 152(sp)
    sd s8, 160(sp)
    sd s9, 168(sp)
    sd s10, 176(sp)
    sd s11, 184(sp)
    sd t3, 192(sp)
    sd t4, 200(sp)
    sd t5, 208(sp)
    sd t6, 216(sp)
    sd gp, 224(sp)
    sd tp, 232(sp)

    /* Save CSRs */
    csrr t0, mepc
    csrr t1, mcause
    csrr t2, mtval
    csrr t3, mstatus
    sd t0, 240(sp)
    sd t1, 248(sp)
    sd t2, 256(sp)
    sd t3, 264(sp)

    /* Original sp before trap */
    addi t4, sp, 320
    sd t4, 272(sp)

    /* Save Vector CSRs (vtype, vl, vstart, vcsr) */
    csrr t0, vtype
    csrr t1, vl
    csrr t2, vstart
    csrr t3, vcsr
    sd t0, 280(sp)
    sd t1, 288(sp)
    sd t2, 296(sp)
    sd t3, 304(sp)

    /* Dispatch to C trap handler: a0 = TrapFrame* */
    mv a0, sp
    call trap_dispatch

    /* Restore Vector CSRs */
    ld t0, 280(sp)
    ld t1, 288(sp)
    ld t2, 296(sp)
    ld t3, 304(sp)
    csrw vcsr, t3
    csrw vstart, t2
    bgez t0, .Lrestore_vtype
    j .Lrestore_vector_done
.Lrestore_vtype:
    vsetvl zero, t1, t0
.Lrestore_vector_done:

    /* Restore CSRs */
    ld t0, 240(sp)
    ld t3, 264(sp)
    csrw mepc, t0
    csrw mstatus, t3

    /* Restore registers */
    ld ra,   0(sp)
    ld t0,   8(sp)
    ld t1,  16(sp)
    ld t2,  24(sp)
    ld s0,  32(sp)
    ld s1,  40(sp)
    ld a0,  48(sp)
    ld a1,  56(sp)
    ld a2,  64(sp)
    ld a3,  72(sp)
    ld a4,  80(sp)
    ld a5,  88(sp)
    ld a6,  96(sp)
    ld a7, 104(sp)
    ld s2, 112(sp)
    ld s3, 120(sp)
    ld s4, 128(sp)
    ld s5, 136(sp)
    ld s6, 144(sp)
    ld s7, 152(sp)
    ld s8, 160(sp)
    ld s9, 168(sp)
    ld s10, 176(sp)
    ld s11, 184(sp)
    ld t3, 192(sp)
    ld t4, 200(sp)
    ld t5, 208(sp)
    ld t6, 216(sp)
    ld gp, 224(sp)
    ld tp, 232(sp)

    addi sp, sp, 320
    mret

.size trap_vector, . - trap_vector
