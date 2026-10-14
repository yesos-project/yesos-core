#include "ports.h"
#include "kprintf.h"

// Default UART Base (0x10000000 for QEMU virt & JH7110 UART0, 0x12440000 for JH7110 UART3 debug header)
#ifndef UART0_BASE
#define UART0_BASE 0x10000000ULL
#endif

#define UART_RBR  0 // Receiver Buffer Register (read) / Transmitter Holding Register (write)
#define UART_IER  1 // Interrupt Enable Register
#define UART_FCR  2 // FIFO Control Register
#define UART_LCR  3 // Line Control Register
#define UART_MCR  4 // Modem Control Register
#define UART_LSR  5 // Line Status Register

U0 serial_init(U0) {
    mmio_write8(UART0_BASE + UART_IER, 0x00); // Disable interrupts
    mmio_write8(UART0_BASE + UART_LCR, 0x80); // Enable DLAB (set baud rate divisor)
    mmio_write8(UART0_BASE + 0, 0x01);        // Set divisor low (38.4k / 115.2k)
    mmio_write8(UART0_BASE + 1, 0x00);        // Set divisor high
    mmio_write8(UART0_BASE + UART_LCR, 0x03); // 8 bits, no parity, one stop bit
    mmio_write8(UART0_BASE + UART_FCR, 0x07); // Enable FIFO, clear TX/RX
    mmio_write8(UART0_BASE + UART_MCR, 0x03); // RTS/DTR set
}

static inline I32 is_transmit_empty(U0) {
    return mmio_read8(UART0_BASE + UART_LSR) & 0x20;
}

U0 serial_putc(char c) {
    int timeout = 100000;
    while (!is_transmit_empty() && --timeout > 0);
    mmio_write8(UART0_BASE + UART_RBR, (U8)c);
}

U0 serial_puts(const char* str) {
    if (!str) return;
    while (*str) {
        if (*str == '\n') serial_putc('\r');
        serial_putc(*str++);
    }
}

Bool serial_has_char(U0) {
    return (mmio_read8(UART0_BASE + UART_LSR) & 0x01) != 0;
}

char serial_getc(U0) {
    if (!serial_has_char()) return 0;
    return (char)mmio_read8(UART0_BASE + UART_RBR);
}
