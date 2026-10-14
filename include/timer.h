#ifndef TIMER_H
#define TIMER_H

#include "types.h"

U0  timer_init(U0);
U64 timer_get_ticks(U0);
U64 timer_get_uptime_ms(U0);
U0  SleepMS(U64 ms);

#endif // TIMER_H
