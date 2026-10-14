#include "trap.h"
#include "kprintf.h"
#include "timer.h"
#include "task.h"

extern void trap_vector(void);

#include "clint.h"
#include "smp.h"

// Fault probing: while active, an illegal-instruction or access-fault
// exception is recorded and execution resumes instead of halting the hart.
// Used to detect optional ISA extensions (Zkr `seed`, PMP entry count) and by
// the PMP self-test. Hart 0 only (boot and shell context).
static volatile Bool g_probe_active = FALSE;
static volatile Bool g_probe_faulted = FALSE;
static volatile U64  g_probe_cause = 0;

U0 trap_probe_begin(U0) {
    g_probe_faulted = FALSE;
    g_probe_cause = 0;
    g_probe_active = TRUE;
}

Bool trap_probe_end(U0) {
    g_probe_active = FALSE;
    return g_probe_faulted;
}

static U0 clint_timer_set_next(U32 hartid) {
    U64 now = *CLINT_MTIME;
    *CLINT_MTIMECMP(hartid) = now + CLINT_TICKS_PER_MS;
}

U0 trap_init(U0) {
    // Set trap vector in mtvec (Direct Mode)
    U64 vec = (U64)trap_vector;
    __asm__ __volatile__("csrw mtvec, %0" : : "r"(vec));

    // Initialize timer comparison in CLINT for Hart 0
    clint_timer_set_next(0);

    // Enable Machine Software Interrupt (MSIE = Bit 3), Timer Interrupt (MTIE = Bit 7), External Interrupt (MEIE = Bit 11)
    __asm__ __volatile__("csrs mie, %0" : : "r"((1ULL << 3) | (1ULL << 7) | (1ULL << 11)));

    // Enable Global Interrupts (MIE = Bit 3) & Floating Point Unit (FS = Bits 14:13)
    __asm__ __volatile__("csrs mstatus, %0" : : "r"((1ULL << 3) | (3ULL << 13)));

    kprintf("[TRAP] RISC-V 64-bit mtvec & CLINT timer armed.\n");
}

U0 trap_dispatch(TrapFrame* tf) {
    U64 is_interrupt = tf->mcause & (1ULL << 63);
    U64 cause = tf->mcause & ~(1ULL << 63);
    U32 hartid = smp_hart_id();

    if (is_interrupt) {
        switch (cause) {
            case 7: { // Machine Timer Interrupt
                clint_timer_set_next(hartid);
                if (hartid != 0) smp_heartbeat_tick(hartid);
                break;
            }
            case 11: { // Machine External Interrupt (PLIC)
                // Handled by device drivers (e.g. UART / VirtIO)
                break;
            }
            case 3: { // Machine Software Interrupt (IPI)
                smp_clear_ipi(hartid);
                smp_handle_ipi(hartid);
                break;
            }
            default:
                break;
        }
    } else {
        if (g_probe_active && (cause == 1 || cause == 2 || cause == 5 || cause == 7)) {
            g_probe_faulted = TRUE;
            g_probe_cause = cause;
            if (cause == 1) {
                // Instruction access fault: mepc is the unfetchable target, so
                // never read it; resume at the probe's return address.
                tf->mepc = tf->ra;
            } else {
                U16 inst_low = *(volatile U16*)tf->mepc;
                tf->mepc += ((inst_low & 0x03) == 0x03) ? 4 : 2;
            }
            return;
        }

        kprintf("\n=======================================================\n");
        kprintf(" [RISC-V EXCEPTION] Trap Occurred! Cause: 0x%p\n", (void*)cause);
        kprintf("   mepc    : 0x%p\n", (void*)tf->mepc);
        kprintf("   mtval   : 0x%p\n", (void*)tf->mtval);
        kprintf("   mstatus : 0x%p\n", (void*)tf->mstatus);
        kprintf("   vtype   : 0x%p | vl: %u | vstart: %u\n", (void*)tf->vtype, (U32)tf->vl, (U32)tf->vstart);
        kprintf("   ra      : 0x%p | sp: 0x%p\n", (void*)tf->ra, (void*)tf->sp);
        kprintf("=======================================================\n");

        if (cause == 3) {
            // ebreak / Breakpoint: advance instruction
            tf->mepc += 4;
            return;
        }

        if (cause == 1 || cause == 5 || cause == 7) {
            kprintf("[TRAP] PMP access fault: the locked memory protection blocked this access.\n");
        }

        // Fatal exception: halt hart
        kprintf("[TRAP] System halted.\n");
        while (1) {
            __asm__ __volatile__("wfi");
        }
    }
}
