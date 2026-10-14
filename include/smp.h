#ifndef SMP_H
#define SMP_H

#include "types.h"
#include "ports.h"

#define SMP_MAX_HARTS 8

// Hart Lifecycle States
typedef enum {
    HART_STATE_OFFLINE   = 0,
    HART_STATE_BOOTING   = 1,
    HART_STATE_IDLE      = 2,
    HART_STATE_RUNNING   = 3,
    HART_STATE_PAUSED    = 4,
} HartState;

// Asymmetric Multiprocessing Roles (AMP)
typedef enum {
    HART_ROLE_KERNEL      = 0, // Hart 0: kernel, network, storage, admin shell
    HART_ROLE_WORKER      = 1, // Hart 1: generic worker (smp_dispatch_task)
    HART_ROLE_KEY_HART    = 2, // Hart 2: vault key custody (PMP-private)
    HART_ROLE_CELL        = 3, // Harts 3+: PMP cells for packages
} HartRole;

typedef void (*HartTaskFunc)(void* arg);

// Control block per hardware thread
typedef struct {
    U32                 hart_id;
    volatile HartState  state;
    HartRole            role;
    const char*         role_name;
    volatile HartTaskFunc task_func;
    volatile void*      task_arg;
    volatile Bool       task_active;
    volatile Bool       stop_requested;
    volatile U64        work_iterations;
    volatile U64        cycles_executed;
    volatile U64        last_heartbeat_tick;
    char                status_desc[64];
} HartControlBlock;

// Public SMP Core API
U0                smp_init(U0);
U0                smp_secondary_entry(U32 hart_id);
U32               smp_get_hart_count(U0);
U32               smp_get_online_harts(U0);
HartControlBlock* smp_get_hart_block(U32 hart_id);
Bool              smp_is_hart_online(U32 hart_id);

// Inter-Processor Interrupts (IPI) via CLINT
U0                smp_send_ipi(U32 target_hart);
U0                smp_clear_ipi(U32 target_hart);
U0                smp_handle_ipi(U32 hart_id);
U0                smp_heartbeat_tick(U32 hart_id);

// Task dispatching to dedicated harts
Bool              smp_start_task(U32 hart_id, HartTaskFunc func, void* arg, const char* desc);
U0                smp_stop_task(U32 hart_id);
Bool              smp_is_task_running(U32 hart_id);

// Asymmetric Offloading Hooks


// Telemetry & Benchmarks
U0                smp_print_telemetry(U0);

#endif // SMP_H
