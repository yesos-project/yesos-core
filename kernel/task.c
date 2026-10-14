#include "task.h"
#include "memory.h"
#include "timer.h"
#include "ports.h"
#include "kprintf.h"

#define DEFAULT_STACK_SIZE (64 * 1024)

extern U0 task_switch_context(TaskControlBlock* next, TaskControlBlock* prev);
extern U0 task_startup_stub(U0);

static TaskControlBlock* g_current_task = NULL;
static TaskControlBlock* g_task_list = NULL;
static TaskControlBlock* g_zombie_task = NULL;
static U64 g_next_task_id = 1;

static U0 task_reap_zombie(U0) {
    if (g_zombie_task) {
        TaskControlBlock* z = g_zombie_task;
        g_zombie_task = NULL;
        if (z->stack_base) {
            Free(z->stack_base);
            z->stack_base = NULL;
        }
        Free(z);
    }
}

Bool task_check_stack_canary(TaskControlBlock* task) {
    if (!task) return FALSE;
    if (!task->stack_base) return TRUE; // Adam task has no heap stack
    if (task->stack_canary != STACK_CANARY_MAGIC) return FALSE;
    U64 canary_val = *(U64*)task->stack_base;
    return (canary_val == STACK_CANARY_MAGIC);
}

U0 task_init(U0) {
    // Create the Main / Adam task
    TaskControlBlock* adam = (TaskControlBlock*)Malloc(sizeof(TaskControlBlock));
    if (!adam) return;
    adam->task_id = g_next_task_id++;
    StrNCpy(adam->name, "Adam Task", sizeof(adam->name));
    adam->state = TASK_RUNNING;
    adam->stack_base = NULL;
    adam->stack_size = 0;
    adam->stack_canary = STACK_CANARY_MAGIC;
    adam->sleep_until_tick = 0;
    adam->next = adam;
    adam->prev = adam;

    g_current_task = adam;
    g_task_list = adam;

    kprintf("[TASK] Adam task initialized (TID %u)\n", (U32)adam->task_id);
}

TaskControlBlock* TaskSpawn(const char* name, void (*entry)(void*), void* arg) {
    if (!entry) return NULL;

    task_reap_zombie();

    TaskControlBlock* task = (TaskControlBlock*)Malloc(sizeof(TaskControlBlock));
    if (!task) return NULL;

    task->task_id = g_next_task_id++;
    StrNCpy(task->name, name ? name : "Task", sizeof(task->name));
    task->state = TASK_READY;
    task->stack_size = DEFAULT_STACK_SIZE;
    task->stack_base = Malloc(DEFAULT_STACK_SIZE);
    if (!task->stack_base) {
        kprintf("[TASK] Error: Out of memory allocating stack for task '%s'\n", task->name);
        Free(task);
        return NULL;
    }

    // Plant stack overflow canary at the very bottom of the allocated buffer
    *(U64*)task->stack_base = STACK_CANARY_MAGIC;
    task->stack_canary = STACK_CANARY_MAGIC;
    task->sleep_until_tick = 0;

    // Set up initial stack frame for task_switch_context
    U64* stack_top = (U64*)((U8*)task->stack_base + task->stack_size);

    // Align stack to 16 bytes
    stack_top = (U64*)((U64)stack_top & ~0xFULL);

    // Push task arguments for task_startup_stub:
    *(--stack_top) = (U64)arg;                  // 8(sp) in task_startup_stub
    *(--stack_top) = (U64)entry;                // 0(sp) in task_startup_stub

    // Callee-saved frame restored by task_switch_context (14 QWORDs = 112 bytes):
    *(--stack_top) = 0;                         // 104: 16-byte alignment padding
    *(--stack_top) = 0;                         // 96: s11
    *(--stack_top) = 0;                         // 88: s10
    *(--stack_top) = 0;                         // 80: s9
    *(--stack_top) = 0;                         // 72: s8
    *(--stack_top) = 0;                         // 64: s7
    *(--stack_top) = 0;                         // 56: s6
    *(--stack_top) = 0;                         // 48: s5
    *(--stack_top) = 0;                         // 40: s4
    *(--stack_top) = 0;                         // 32: s3
    *(--stack_top) = 0;                         // 24: s2
    *(--stack_top) = 0;                         // 16: s1
    *(--stack_top) = 0;                         // 8:  s0
    *(--stack_top) = (U64)task_startup_stub;    // 0:  ra (trampoline entry)

    task->rsp = (U64)stack_top;

    // Insert into circular linked list
    task->next = g_task_list;
    task->prev = g_task_list->prev;
    g_task_list->prev->next = task;
    g_task_list->prev = task;

    kprintf("[TASK] Spawned task '%s' (TID %u)\n", task->name, (U32)task->task_id);
    return task;
}

TaskControlBlock* TaskCurrent(U0) {
    return g_current_task;
}

U0 TaskYield(U0) {
    task_reap_zombie();

    if (!g_current_task || !g_current_task->next) return;

    if (!task_check_stack_canary(g_current_task)) {
        kprintf("[SECURITY ALERT] Stack canary violation in task '%s' (TID %u)!\n",
                g_current_task->name, (U32)g_current_task->task_id);
    }

    U64 current_tick = timer_get_ticks();
    TaskControlBlock* next_task = g_current_task->next;

    // Find next ready task
    while (next_task != g_current_task) {
        if (next_task->state == TASK_SLEEPING && current_tick >= next_task->sleep_until_tick) {
            next_task->state = TASK_READY;
        }

        if (next_task->state == TASK_READY || next_task->state == TASK_RUNNING) {
            break;
        }
        next_task = next_task->next;
    }

    if (next_task == g_current_task) return; // No other task ready

    TaskControlBlock* prev = g_current_task;
    if (prev->state == TASK_RUNNING) {
        prev->state = TASK_READY;
    }
    next_task->state = TASK_RUNNING;
    g_current_task = next_task;

    task_switch_context(next_task, prev);
}

static volatile Bool g_break_requested = FALSE;

U0 TaskBreak(U0) {
    g_break_requested = TRUE;
    TaskKillAllChildren();
    kprintf("\n[TASK] *** BREAK / KILL ALL TASKS (Ctrl+Alt+C) ***\n");
}

Bool TaskIsBreakRequested(U0) {
    return g_break_requested;
}

U0 TaskClearBreak(U0) {
    g_break_requested = FALSE;
}

U0 TaskKillAllChildren(U0) {
    if (!g_task_list) return;

    TaskControlBlock* curr = g_task_list->next;
    while (curr != g_task_list) {
        TaskControlBlock* next = curr->next;
        curr->state = TASK_DEAD;
        curr->prev->next = curr->next;
        curr->next->prev = curr->prev;
        
        if (curr == g_current_task) {
            g_zombie_task = curr;
        } else {
            if (curr->stack_base) {
                Free(curr->stack_base);
                curr->stack_base = NULL;
            }
            Free(curr);
        }
        curr = next;
    }

    if (g_current_task != g_task_list) {
        g_current_task = g_task_list;
        g_task_list->state = TASK_RUNNING;
        task_switch_context(g_task_list, g_zombie_task);
    } else {
        g_task_list->state = TASK_RUNNING;
    }
}

U0 TaskExit(U0) {
    if (!g_current_task) return;
    if (g_current_task == g_task_list) {
        // Adam task cannot exit
        while (1) {
            TaskYield();
            hlt();
        }
    }

    TaskControlBlock* dying_task = g_current_task;
    dying_task->state = TASK_DEAD;

    // Unlink from scheduler
    dying_task->prev->next = dying_task->next;
    dying_task->next->prev = dying_task->prev;

    g_current_task = dying_task->next;
    g_current_task->state = TASK_RUNNING;

    // CRITICAL: Do NOT free dying_task or its stack here!
    // The CPU is currently executing on dying_task->rsp, and task_switch_context
    // will push registers onto this stack. We designate it as zombie so the next
    // running task safely frees it during TaskYield/TaskSpawn.
    g_zombie_task = dying_task;

    task_switch_context(g_current_task, dying_task);

    while (1) {
        hlt();
    }
}

