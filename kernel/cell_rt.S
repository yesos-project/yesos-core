/*
 * YesOS 2.0 - PMP cell runtime (runs on cell harts, Machine mode).
 *
 * Lives in .cell_text, the only kernel code a cell can execute. Untrusted
 * cell code can jump to ANY instruction here, so every privileged
 * instruction in this file must be harmless out of context:
 *   csrw pmpaddrN / pmpcfg0  writes to locked entries are ignored; unused
 *                            entries rank below the locked catch-all
 *   csrr ...                 reads only
 *   csrsi mstatus, MIE       can only enable interrupts
 *   csrw mepc + mret         targets are limited to executable cell memory;
 *                            mret can only keep or lower privilege
 * There is deliberately no write to mtvec, mie, mideleg/medeleg or the
 * counters: those are set by kernel code before the PMP is locked.
 *
 * Registers are never trusted: the mailbox address is recomputed from
 * mhartid every time.
 */
#include "cell.h"

.section .cell_text, "ax"
.option norvc

/* Zihintpause PAUSE (a FENCE hint: plain fence on harts without the extension). */
.macro PAUSE
    .word 0x0100000F
.endm

/* t0 <- mailbox (data arena) of the current cell. Clobbers t1. */
.macro CELL_MAILBOX
    csrr  t0, mhartid
    addi  t0, t0, -CELL_FIRST_HART
    li    t1, CELL_STRIDE
    mul   t0, t0, t1
    la    t1, _cell_area_start
    add   t0, t0, t1
    li    t1, CELL_CODE_SIZE
    add   t0, t0, t1
.endm

/* sp <- top of the current cell's data arena. Clobbers t0, t1. */
.macro CELL_STACK
    CELL_MAILBOX
    li    t1, CELL_DATA_SIZE
    add   sp, t0, t1
.endm

/*
 * cell_boot(a0 = mailbox). Called from kernel text with interrupts disabled,
 * mtvec = cell_trap and mie = MSIE already set. Locks the layout staged by
 * hart 0, publishes the readback and enters the job loop. Never returns.
 */
.global cell_boot
.type cell_boot, @function
cell_boot:
    mv    s1, a0
    ld    t0, MB_PMP_ADDR+0*8(s1)
    csrw  pmpaddr0, t0
    ld    t0, MB_PMP_ADDR+1*8(s1)
    csrw  pmpaddr1, t0
    ld    t0, MB_PMP_ADDR+2*8(s1)
    csrw  pmpaddr2, t0
    ld    t0, MB_PMP_ADDR+3*8(s1)
    csrw  pmpaddr3, t0
    ld    t0, MB_PMP_ADDR+4*8(s1)
    csrw  pmpaddr4, t0
    ld    t0, MB_PMP_ADDR+5*8(s1)
    csrw  pmpaddr5, t0
    ld    t0, MB_PMP_ADDR+6*8(s1)
    csrw  pmpaddr6, t0
    ld    t0, MB_PMP_ADDR+7*8(s1)
    csrw  pmpaddr7, t0
    ld    t0, MB_PMP_CFG0(s1)
    csrw  pmpcfg0, t0                 /* L bits: the cell is now confined */
    fence rw, rw

    csrr  t0, pmpaddr0
    sd    t0, MB_RB_ADDR+0*8(s1)
    csrr  t0, pmpaddr1
    sd    t0, MB_RB_ADDR+1*8(s1)
    csrr  t0, pmpaddr2
    sd    t0, MB_RB_ADDR+2*8(s1)
    csrr  t0, pmpaddr3
    sd    t0, MB_RB_ADDR+3*8(s1)
    csrr  t0, pmpaddr4
    sd    t0, MB_RB_ADDR+4*8(s1)
    csrr  t0, pmpaddr5
    sd    t0, MB_RB_ADDR+5*8(s1)
    csrr  t0, pmpaddr6
    sd    t0, MB_RB_ADDR+6*8(s1)
    csrr  t0, pmpaddr7
    sd    t0, MB_RB_ADDR+7*8(s1)
    csrr  t0, pmpcfg0
    sd    t0, MB_RB_CFG0(s1)

    fence rw, rw
    li    t0, CELL_ST_BOOTED
    sd    t0, MB_STATE(s1)
    fence rw, rw
    csrsi mstatus, 8                  /* MIE: the kill IPI can now preempt */
    /* fall through */

/* Job loop: wait for CELL_ST_RUN, call the entry point, publish the result. */
.global cell_loop
cell_loop:
    CELL_STACK
1:
    fence rw, rw
    CELL_MAILBOX
    ld    t2, MB_STATE(t0)
    li    t1, CELL_ST_RUN
    beq   t2, t1, 2f
    PAUSE
    j     1b
2:
    li    t1, CELL_ST_RUNNING
    sd    t1, MB_STATE(t0)
    fence rw, rw
    ld    t2, MB_ENTRY(t0)
    ld    a0, MB_ARGS+0*8(t0)
    ld    a1, MB_ARGS+1*8(t0)
    ld    a2, MB_ARGS+2*8(t0)
    ld    a3, MB_ARGS+3*8(t0)
    jalr  ra, 0(t2)
    mv    t3, a0
    CELL_MAILBOX
    sd    t3, MB_RESULT(t0)
    fence rw, rw
    li    t1, CELL_ST_DONE
    sd    t1, MB_STATE(t0)
    fence rw, rw
    j     cell_loop

/*
 * Trap handler (mtvec, direct mode). Never returns to the interrupted code:
 *  - exception: record cause/tval/epc, state = FAULT, back to the job loop;
 *  - software interrupt (kill IPI from hart 0): park here while MSIP is
 *    pending, without touching the mailbox. Untrusted code cannot clear MSIP
 *    (it is an MMIO register the cell cannot reach), so hart 0 alone decides
 *    when the cell resumes, and it rewrites the job state while it is parked.
 */
.align 4
.global cell_trap
cell_trap:
    csrr  t3, mcause
    CELL_MAILBOX
    bltz  t3, 3f
    sd    t3, MB_FAULT_CAUSE(t0)
    csrr  t1, mtval
    sd    t1, MB_FAULT_TVAL(t0)
    csrr  t1, mepc
    sd    t1, MB_FAULT_EPC(t0)
    li    t1, CELL_ST_FAULT
    j     5f
3:
    /* Kill/park IPI: write nothing (hart 0 owns the job state while the
     * cell is parked) and wait until hart 0 clears MSIP. */
    csrr  t1, mip
    andi  t1, t1, 8
    beqz  t1, 6f
    PAUSE
    j     3b
5:
    fence rw, rw
    sd    t1, MB_STATE(t0)
    fence rw, rw
6:
    la    t1, cell_loop
    csrw  mepc, t1
    mret

/*
 * cell_rpc: called by cell code. a7 = operation, a0..a6 = arguments.
 * Posts the request in the mailbox and spins until hart 0 answers.
 * Uses only temporaries, as the caller expects callee-saved registers kept.
 */
.global cell_rpc
cell_rpc:
    CELL_MAILBOX
    sd    a7, MB_RPC_OP(t0)
    sd    a0, MB_RPC_ARGS+0*8(t0)
    sd    a1, MB_RPC_ARGS+1*8(t0)
    sd    a2, MB_RPC_ARGS+2*8(t0)
    sd    a3, MB_RPC_ARGS+3*8(t0)
    sd    a4, MB_RPC_ARGS+4*8(t0)
    sd    a5, MB_RPC_ARGS+5*8(t0)
    sd    a6, MB_RPC_ARGS+6*8(t0)
    fence rw, rw
    li    t1, CELL_RPC_REQUEST
    sd    t1, MB_RPC_STATE(t0)
    fence rw, rw
6:
    ld    t1, MB_RPC_STATE(t0)
    li    t2, CELL_RPC_DONE
    beq   t1, t2, 7f
    PAUSE
    j     6b
7:
    ld    a0, MB_RPC_RESULT(t0)
    sd    zero, MB_RPC_STATE(t0)
    fence rw, rw
    ret

/*
 * Drawing into the cell's private canvas (CELL_CANVAS_W x CELL_CANVAS_H, 32bpp).
 * Plain loads/stores with clipping; nothing here can reach outside the cell.
 *
 * gfx_rect(a0 = x, a1 = y, a2 = w, a3 = h, a4 = color)
 */
.global cell_gfx_rect
cell_gfx_rect:
    /* x0 = max(x, 0), x1 = min(x + w, W), likewise for y */
    add   t2, a0, a2
    add   t3, a1, a3
    bgez  a0, 1f
    li    a0, 0
1:  bgez  a1, 2f
    li    a1, 0
2:  li    t4, CELL_CANVAS_W
    ble   t2, t4, 3f
    mv    t2, t4
3:  li    t4, CELL_CANVAS_H
    ble   t3, t4, 4f
    mv    t3, t4
4:  bge   a0, t2, 9f
    bge   a1, t3, 9f
    CELL_MAILBOX                   /* t0 = data arena (clobbers t1) */
    li    t1, CELL_CANVAS_OFFSET
    add   t0, t0, t1               /* t0 = canvas */
5:  /* row a1: t5 = canvas + (a1 * W + a0) * 4, t6 = row end */
    li    t4, CELL_CANVAS_W
    mul   t5, a1, t4
    add   t6, t5, t2
    add   t5, t5, a0
    slli  t5, t5, 2
    slli  t6, t6, 2
    add   t5, t5, t0
    add   t6, t6, t0
6:  sw    a4, 0(t5)
    addi  t5, t5, 4
    bltu  t5, t6, 6b
    addi  a1, a1, 1
    blt   a1, t3, 5b
9:  ret

/* gfx_clear(a0 = color) */
.global cell_gfx_clear
cell_gfx_clear:
    mv    a4, a0
    li    a0, 0
    li    a1, 0
    li    a2, CELL_CANVAS_W
    li    a3, CELL_CANVAS_H
    j     cell_gfx_rect

/* gfx_plot(a0 = x, a1 = y, a2 = color) */
.global cell_gfx_plot
cell_gfx_plot:
    mv    a4, a2
    li    a2, 1
    li    a3, 1
    j     cell_gfx_rect
