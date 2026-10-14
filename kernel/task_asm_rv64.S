/*
 * YesOS 2.0 - RISC-V 64-bit Cooperative Task Switching
 * Fast callee-saved register save/restore (< 10 ns)
 */

.section .text
.global task_switch_context
.type task_switch_context, @function

/* void task_switch_context(TaskControlBlock* next, TaskControlBlock* prev)
 * a0 = next (TaskControlBlock*)
 * a1 = prev (TaskControlBlock*)
 * Offset 0 of TaskControlBlock is U64 rsp (saved sp).
 */
task_switch_context:
    /* If prev is NULL (first switch from Adam), skip saving */
    beqz a1, .Lrestore_next

    /* Allocate space on current task's stack for callee-saved registers:
     * ra, s0-s11 (13 registers * 8 bytes = 104 -> aligned to 112 bytes)
     */
    addi sp, sp, -112
    sd ra,   0(sp)
    sd s0,   8(sp)
    sd s1,  16(sp)
    sd s2,  24(sp)
    sd s3,  32(sp)
    sd s4,  40(sp)
    sd s5,  48(sp)
    sd s6,  56(sp)
    sd s7,  64(sp)
    sd s8,  72(sp)
    sd s9,  80(sp)
    sd s10, 88(sp)
    sd s11, 96(sp)

    /* Save current sp into prev->rsp (offset 0) */
    sd sp, 0(a1)

.Lrestore_next:
    /* Load next task's saved sp from next->rsp (offset 0) */
    ld sp, 0(a0)

    /* Restore callee-saved registers from next task's stack */
    ld ra,   0(sp)
    ld s0,   8(sp)
    ld s1,  16(sp)
    ld s2,  24(sp)
    ld s3,  32(sp)
    ld s4,  40(sp)
    ld s5,  48(sp)
    ld s6,  56(sp)
    ld s7,  64(sp)
    ld s8,  72(sp)
    ld s9,  80(sp)
    ld s10, 88(sp)
    ld s11, 96(sp)
    addi sp, sp, 112

    ret

.size task_switch_context, . - task_switch_context

/* Trampoline entry for newly spawned tasks */
.global task_startup_stub
.type task_startup_stub, @function

task_startup_stub:
    /* On newly spawned task, stack top holds entry and arg */
    ld a0, 0(sp)        /* entry point function pointer */
    ld a1, 8(sp)        /* arg pointer */
    addi sp, sp, 16
    jalr a0             /* Call task entry(arg) */
    call TaskExit       /* If entry returns, exit task cleanly */

.size task_startup_stub, . - task_startup_stub
