#include "keyhart.h"
#include "cell.h"
#include "pmp.h"
#include "smp.h"
#include "kprintf.h"
#include "timer.h"
#include "memory.h"
#include "clint.h"


static HartControlBlock g_smp_harts[SMP_MAX_HARTS];
static volatile U32     g_smp_online_count = 1; // Hart 0 is always online
static volatile Bool    g_smp_initialized = FALSE;

U0 smp_init(U0) {
    kprintf("[SMP] Initializing RISC-V Multi-Hart Subsystem (M-Mode Flat Memory)...\n");

    MemSet(g_smp_harts, 0, sizeof(g_smp_harts));

    // Configure Hart 0 (Master Bootstrap Processor)
    g_smp_harts[0].hart_id = 0;
    g_smp_harts[0].state = HART_STATE_RUNNING;
    g_smp_harts[0].role = HART_ROLE_KERNEL;
    g_smp_harts[0].role_name = "KERNEL (NAS services & admin shell)";
    StrNCpy(g_smp_harts[0].status_desc, "NAS services & admin shell", sizeof(g_smp_harts[0].status_desc));

    for (U32 i = 1; i < SMP_MAX_HARTS; i++) {
        g_smp_harts[i].hart_id = i;
        g_smp_harts[i].state = HART_STATE_OFFLINE;
        if (i == 1) {
            g_smp_harts[i].role = HART_ROLE_WORKER;
            g_smp_harts[i].role_name = "WORKER (generic task dispatch)";
        } else if (i == 2) {
            g_smp_harts[i].role = HART_ROLE_KEY_HART;
            g_smp_harts[i].role_name = "KEY_HART (Vault key custody, PMP-private)";
        } else {
            g_smp_harts[i].role = HART_ROLE_CELL;
            g_smp_harts[i].role_name = "PMP_CELL (Isolated app core)";
        }
        StrNCpy(g_smp_harts[i].status_desc, "Waiting for Hart Check-In", sizeof(g_smp_harts[i].status_desc));
    }

    // Mark initialized so secondary harts can proceed
    smp_fence();
    g_smp_initialized = TRUE;
    smp_fence();

    // Spin-wait briefly for secondary harts to check in (approx 2 ms)
    for (volatile int wait = 0; wait < 200000; wait++) {
        smp_fence();
    }

    kprintf(" [ OK ] Multi-Hart Subsystem Online: %u Harts Detected (AMP Architecture)\n", g_smp_online_count);
    for (U32 i = 0; i < SMP_MAX_HARTS; i++) {
        if (g_smp_harts[i].state != HART_STATE_OFFLINE) {
            kprintf("        Hart %u: %s [%s]\n",
                    i, g_smp_harts[i].role_name,
                    g_smp_harts[i].state == HART_STATE_RUNNING ? "RUNNING" : "IDLE");
        }
    }
}

U0 smp_secondary_entry(U32 hart_id) {
    if (hart_id >= SMP_MAX_HARTS) {
        while (1) { hlt(); }
    }

    // Wait until Hart 0 has initialized the SMP table
    while (!g_smp_initialized) {
        smp_pause();
        smp_fence();
    }

    HartControlBlock* hcb = &g_smp_harts[hart_id];
    hcb->hart_id = hart_id;
    hcb->state = HART_STATE_IDLE;
    hcb->work_iterations = 0;
    hcb->cycles_executed = 0;
    hcb->task_active = FALSE;
    hcb->stop_requested = FALSE;
    StrNCpy(hcb->status_desc, "Idle / Ready for Work", sizeof(hcb->status_desc));

    if (hart_id == KEYHART_ID) {
        // Key hart: locks a layout with a private key vault, no devices, no JIT.
        hcb->role_name = "KEY_HART (Vault key custody, PMP-private)";
        StrNCpy(hcb->status_desc, "Serving vault key operations", sizeof(hcb->status_desc));
        __atomic_fetch_add(&g_smp_online_count, 1, __ATOMIC_SEQ_CST);
        keyhart_enter(hart_id);
    }

    if (cell_is_cell_hart(hart_id)) {
        // Isolated app core: locks its own cell PMP layout and never runs kernel code again.
        hcb->role_name = "PMP_CELL (Isolated app core, verified code only)";
        StrNCpy(hcb->status_desc, "Locked PMP cell", sizeof(hcb->status_desc));
        __atomic_fetch_add(&g_smp_online_count, 1, __ATOMIC_SEQ_CST);
        cell_hart_enter(hart_id);
    }

    // Lock the proven PMP layout on this hart before it runs anything else.
    pmp_init_secondary(hart_id);

    // Arm timer comparison in CLINT for this secondary hart (1ms interval)
    *CLINT_MTIMECMP(hart_id) = *CLINT_MTIME + CLINT_TICKS_PER_MS;

    // Enable Machine Software Interrupt (MSIE = Bit 3) and Timer Interrupt (MTIE = Bit 7) in mie
    __asm__ __volatile__("csrs mie, %0" : : "r"((1ULL << 3) | (1ULL << 7)));

    // Enable Global Interrupts (MIE = Bit 3) in mstatus
    __asm__ __volatile__("csrs mstatus, %0" : : "r"(1ULL << 3));

    // Atomically increment online hart counter
    __atomic_fetch_add(&g_smp_online_count, 1, __ATOMIC_SEQ_CST);

    // Main Worker Loop for this secondary hardware thread
    while (1) {
        if (hcb->task_active && hcb->task_func) {
            hcb->state = HART_STATE_RUNNING;
            hcb->stop_requested = FALSE;

            HartTaskFunc fn = hcb->task_func;
            void* arg = (void*)hcb->task_arg;

            U64 c_start = 0, c_end = 0;
            __asm__ __volatile__("csrr %0, mcycle" : "=r"(c_start));

            fn(arg);

            __asm__ __volatile__("csrr %0, mcycle" : "=r"(c_end));
            hcb->cycles_executed += (c_end - c_start);

            smp_fence();
            hcb->task_active = FALSE;
            hcb->task_func = NULL;
            hcb->task_arg = NULL;
            hcb->state = HART_STATE_IDLE;
            StrNCpy(hcb->status_desc, "Idle / Ready for Work", sizeof(hcb->status_desc));
        }

        smp_fence();
        hlt(); // wfi: sleeps until an IPI or interrupt arrives
    }
}

U32 smp_get_hart_count(U0) {
    return g_smp_online_count;
}

U32 smp_get_online_harts(U0) {
    return g_smp_online_count;
}

HartControlBlock* smp_get_hart_block(U32 hart_id) {
    if (hart_id >= SMP_MAX_HARTS) return NULL;
    return &g_smp_harts[hart_id];
}

Bool smp_is_hart_online(U32 hart_id) {
    if (hart_id >= SMP_MAX_HARTS) return FALSE;
    return g_smp_harts[hart_id].state != HART_STATE_OFFLINE;
}

U0 smp_send_ipi(U32 target_hart) {
    if (target_hart >= SMP_MAX_HARTS) return;
    *CLINT_MSIP(target_hart) = 1;
}

U0 smp_clear_ipi(U32 target_hart) {
    if (target_hart >= SMP_MAX_HARTS) return;
    *CLINT_MSIP(target_hart) = 0;
}

U0 smp_handle_ipi(U32 hart_id) {
    (void)hart_id;
    // Inter-processor interrupt received and cleared; hart continues execution loop
}

U0 smp_heartbeat_tick(U32 hart_id) {
    if (hart_id < SMP_MAX_HARTS) {
        g_smp_harts[hart_id].last_heartbeat_tick = timer_get_ticks();
    }
}

Bool smp_start_task(U32 hart_id, HartTaskFunc func, void* arg, const char* desc) {
    if (hart_id == 0 || hart_id >= SMP_MAX_HARTS) return FALSE;
    HartControlBlock* hcb = &g_smp_harts[hart_id];
    if (hcb->state == HART_STATE_OFFLINE) return FALSE;

    hcb->task_func = func;
    hcb->task_arg = arg;
    hcb->stop_requested = FALSE;
    if (desc) {
        StrNCpy(hcb->status_desc, desc, sizeof(hcb->status_desc));
    }
    smp_fence();
    hcb->task_active = TRUE;
    smp_fence();

    // Send IPI to wake up the target hart from wfi immediately
    smp_send_ipi(hart_id);
    return TRUE;
}

U0 smp_stop_task(U32 hart_id) {
    if (hart_id >= SMP_MAX_HARTS) return;
    g_smp_harts[hart_id].stop_requested = TRUE;
    smp_fence();
    smp_send_ipi(hart_id);
}

Bool smp_is_task_running(U32 hart_id) {
    if (hart_id >= SMP_MAX_HARTS) return FALSE;
    return g_smp_harts[hart_id].state == HART_STATE_RUNNING;
}

// ============================================================================
// DEDICATED REAL-TIME EML PHYSICS OFF-LOADING (Hart 2)
// ============================================================================

// ============================================================================
// DEDICATED REAL-TIME AUDIO DSP OFF-LOADING (Hart 1)
// ============================================================================

// ============================================================================
// SMP TELEMETRY & STATUS DISPLAY
// ============================================================================

U0 smp_print_telemetry(U0) {
    kprintf("\n===============================================================================\n");
    kprintf("        YESOS 2.0 - ASYMMETRIC MULTIPROCESSING (AMP) MULTI-HART DASHBOARD      \n");
    kprintf("===============================================================================\n");
    kprintf(" Total Online Harts : %u / %u | Architecture: RISC-V RV64GC M-Mode Bare-Metal\n",
            g_smp_online_count, SMP_MAX_HARTS);
    kprintf(" Inter-Hart Comm    : CLINT IPI (MSIP) + Wait-Free Memory Barriers (RVWMO)\n");
    kprintf(" Memory Isolation   : locked PMP per hart (kernel / key hart / cells, Z3-proven)\n");
    kprintf("-------------------------------------------------------------------------------\n");
    kprintf(" HART | ROLE           | STATE   | ITERATIONS | STATUS DESCRIPTION\n");
    kprintf("------+----------------+---------+------------+--------------------------------\n");

    for (U32 i = 0; i < SMP_MAX_HARTS; i++) {
        HartControlBlock* h = &g_smp_harts[i];
        if (h->state == HART_STATE_OFFLINE && i >= g_smp_online_count) continue;

        const char* state_str = "OFFLINE";
        switch (h->state) {
            case HART_STATE_RUNNING: state_str = "RUNNING"; break;
            case HART_STATE_IDLE:    state_str = "IDLE   "; break;
            case HART_STATE_BOOTING: state_str = "BOOTING"; break;
            case HART_STATE_PAUSED:  state_str = "PAUSED "; break;
            default: break;
        }

        const char* role_str = "WORKER        ";
        switch (h->role) {
            case HART_ROLE_KERNEL:   role_str = "KERNEL        "; break;
            case HART_ROLE_WORKER:   role_str = "WORKER        "; break;
            case HART_ROLE_KEY_HART: role_str = "KEY_HART      "; break;
            case HART_ROLE_CELL:     role_str = "PMP_CELL      "; break;
        }

        const char* desc = h->status_desc[0] ? h->status_desc : "Online";

        kprintf("  %u   | %s | %s | %10u | %s\n",
                i, role_str, state_str, (U32)h->work_iterations, desc);
    }
    kprintf("===============================================================================\n");
    kprintf(" Commands: 'smp bench', 'smp physics on/off', 'smp audio on/off', 'smp'\n\n");
}

// ============================================================================
// PARALLEL MULTI-HART BENCHMARK (1 Core vs 2 Cores vs 4 Cores)
// ============================================================================

typedef struct {
    U32 start_row;
    U32 end_row;
    U32 dim;
    const I64* A;
    const I64* B;
    I64* C;
    volatile Bool done;
} TropicalBenchJob;

