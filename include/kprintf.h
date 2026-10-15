#ifndef KPRINTF_H
#define KPRINTF_H

#include "types.h"
#include <stdarg.h>

U0 serial_init(U0);
U0 serial_putc(char c);
U0 serial_puts(const char* str);
Bool serial_has_char(U0);
char serial_getc(U0);

// The hook sees every character the console writes (kprintf and the
// shell's echo), after the serial port; one hook at a time.
typedef U0 (*KprintfHookFn)(char c);
U0  kprintf_set_hook(KprintfHookFn hook);
U0  kputc(char c);                       // one character to the serial port and the hook
U0  kprintf(const char* fmt, ...);
U0  kvprintf(const char* fmt, va_list args);
I64 ksnprintf(char* buf, size_t max_len, const char* fmt, ...);

#endif // KPRINTF_H
