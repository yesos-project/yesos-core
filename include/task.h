#ifndef TASK_H
#define TASK_H

#include "types.h"

typedef enum {
    TASK_READY,
    TASK_RUNNING,
    TASK_SLEEPING,
    TASK_DEAD
} TaskState;

#define STACK_CANARY_MAGIC 0x594553535441434BULL // "YESSTACK"

typedef struct TaskControlBlock {
    U64 rsp;                    // Saved stack pointer (MUST be first for asm)
    U64 task_id;
    char name[32];
    TaskState state;
    void* stack_base;
    U64 stack_size;
    U64 stack_canary;           // Canary validation field
    U64 sleep_until_tick;
    struct TaskControlBlock* next;
    struct TaskControlBlock* prev;
} TaskControlBlock;

U0                task_init(U0);
TaskControlBlock* TaskSpawn(const char* name, void (*entry)(void*), void* arg);
U0                TaskYield(U0);
U0                TaskExit(U0);
TaskControlBlock* TaskCurrent(U0);
U0                TaskKillAllChildren(U0);
U0                TaskBreak(U0);
Bool              TaskIsBreakRequested(U0);
U0                TaskClearBreak(U0);
Bool              task_check_stack_canary(TaskControlBlock* task);

#endif // TASK_H
