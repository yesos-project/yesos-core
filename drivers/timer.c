#include "timer.h"
#include "clint.h"
#include "ports.h"
#include "kprintf.h"

// Time is read from the CLINT's free-running mtime counter, never counted
// from timer interrupts: an interrupt served late or with MIE off is lost, and
// a counted clock fell ~3% behind real time under QEMU. The 1 ms timer
// interrupt is still armed (trap.c) so SleepMS can wait with wfi.

U0 timer_init(U0) {
    kprintf("[CLINT] Timer: mtime at %u Hz, 1 ms tick\n", (U32)CLINT_TIMEBASE_HZ);
}

U64 timer_get_uptime_ms(U0) {
    return *CLINT_MTIME / CLINT_TICKS_PER_MS;
}

// One tick is one millisecond (callers use tick differences as ms).
U64 timer_get_ticks(U0) {
    return timer_get_uptime_ms();
}

U0 SleepMS(U64 ms) {
    if (ms == 0) return;
    sti(); // Ensure interrupts are enabled
    U64 target = timer_get_uptime_ms() + ms;
    while (timer_get_uptime_ms() < target) {
        hlt(); // wfi (Wait for interrupt)
    }
}
