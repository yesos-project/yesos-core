#ifndef SPEAKER_H
#define SPEAKER_H

#include "types.h"

// System Acoustic Earcons / Feedback Events
typedef enum {
    BEEP_CONFIRM = 0,   // Quick positive chirp (880 Hz, 25ms) - command executed ok
    BEEP_ERROR,         // Low alert buzz (220 Hz, 70ms) - syntax error, invalid param
    BEEP_SUCCESS,       // Ascending double-tone (659 Hz -> 880 Hz) - compilation/sim finished
    BEEP_WARN,          // Dual-pulse warning (523 Hz) - resource limit, prompt
    BEEP_CLICK,         // Ultra-fast micro-click (1500 Hz, 4ms) - UI navigation
    BEEP_BOOT           // Boot startup chime (523 Hz -> 659 Hz -> 784 Hz)
} BeepEvent;

// Earcons are no-ops on the NAS (drivers/earcon.c); kept so call sites
// stay shared with yesos-lab.
U0   speaker_event(BeepEvent event);

#endif // SPEAKER_H
