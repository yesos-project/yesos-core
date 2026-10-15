#include "kprintf.h"
#include "kprintf.h"

static KprintfHookFn g_kprintf_hook = NULL;

U0 kprintf_set_hook(KprintfHookFn hook) {
    g_kprintf_hook = hook;
}

static inline U0 kprintf_emit_char(char c) {
    serial_putc(c);
    if (g_kprintf_hook) {
        g_kprintf_hook(c);
    }
}

U0 kputc(char c) {
    kprintf_emit_char(c);
}

static U0 print_num(I64 num, I64 base, Bool is_signed, int width, Bool pad_zero, Bool left_align, char* out, int* out_idx) {
    char digits[] = "0123456789ABCDEF";
    char buf[65];
    int i = 0;
    uint64_t unum;

    if (is_signed && num < 0) {
        if (out && out_idx) out[(*out_idx)++] = '-';
        else {
            kprintf_emit_char('-');
        }
        unum = (uint64_t)(-num);
        if (width > 0) width--;
    } else {
        unum = (uint64_t)num;
    }

    if (unum == 0) {
        buf[i++] = '0';
    } else {
        while (unum > 0) {
            buf[i++] = digits[unum % base];
            unum /= base;
        }
    }

    if (left_align) {
        int printed = i;
        while (i > 0) {
            char c = buf[--i];
            if (out && out_idx) out[(*out_idx)++] = c;
            else {
                kprintf_emit_char(c);
            }
        }
        while (printed < width) {
            char pad_char = ' ';
            if (out && out_idx) out[(*out_idx)++] = pad_char;
            else {
                kprintf_emit_char(pad_char);
            }
            printed++;
        }
    } else {
        while (i < width) {
            char pad_char = pad_zero ? '0' : ' ';
            if (out && out_idx) out[(*out_idx)++] = pad_char;
            else {
                kprintf_emit_char(pad_char);
            }
            width--;
        }

        while (i > 0) {
            char c = buf[--i];
            if (out && out_idx) out[(*out_idx)++] = c;
            else {
                kprintf_emit_char(c);
            }
        }
    }
}

static U0 print_str(const char* str, char* out, int* out_idx) {
    if (!str) str = "(null)";
    while (*str) {
        if (out && out_idx) out[(*out_idx)++] = *str;
        else {
            kprintf_emit_char(*str);
        }
        str++;
    }
}

U0 kvprintf(const char* fmt, va_list args) {
    if (!fmt) return;

    for (int i = 0; fmt[i] != '\0'; i++) {
        if (fmt[i] != '%') {
            kprintf_emit_char(fmt[i]);
            continue;
        }

        i++;
        if (fmt[i] == '\0') break;

        // Parse left-align, zero-pad flag and field width
        Bool left_align = FALSE;
        Bool pad_zero = FALSE;
        int width = 0;
        if (fmt[i] == '-') {
            left_align = TRUE;
            i++;
        }
        if (fmt[i] == '0' && !left_align) {
            pad_zero = TRUE;
            i++;
        }
        while (fmt[i] >= '0' && fmt[i] <= '9') {
            width = width * 10 + (fmt[i] - '0');
            i++;
        }
        if (fmt[i] == '\0') break;

        switch (fmt[i]) {
            case 'c': {
                char c = (char)va_arg(args, int);
                kprintf_emit_char(c);
                break;
            }
            case 's': {
                const char* s = va_arg(args, const char*);
                print_str(s, NULL, NULL);
                break;
            }
            case 'd':
            case 'i': {
                I64 d = va_arg(args, I64);
                print_num(d, 10, TRUE, width, pad_zero, left_align, NULL, NULL);
                break;
            }
            case 'u': {
                U64 u = va_arg(args, U64);
                print_num((I64)u, 10, FALSE, width, pad_zero, left_align, NULL, NULL);
                break;
            }
            case 'x':
            case 'X': {
                U64 x = va_arg(args, U64);
                if (width > 0 && width <= 8) x &= 0xFFFFFFFFULL;
                print_num((I64)x, 16, FALSE, width, pad_zero, left_align, NULL, NULL);
                break;
            }
            case 'p': {
                U64 p = va_arg(args, U64);
                print_num((I64)p, 16, FALSE, 16, TRUE, FALSE, NULL, NULL);
                break;
            }
            case '%': {
                kprintf_emit_char('%');
                break;
            }
            default: {
                kprintf_emit_char('%');
                kprintf_emit_char(fmt[i]);
                break;
            }
        }
    }
}

U0 kprintf(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    kvprintf(fmt, args);
    va_end(args);
}

// Bounded formatter: EVERY byte written goes through the max_len check
// (the old version bounded only literal characters, so a long %s argument
// overflowed the caller's buffer). Output is always NUL-terminated and
// truncated to max_len - 1 characters; the return value is the length written.
I64 ksnprintf(char* buf, size_t max_len, const char* fmt, ...) {
    if (!buf || max_len == 0 || !fmt) return 0;
    va_list args;
    va_start(args, fmt);

    size_t out = 0;
    const size_t cap = max_len - 1;
#define KS_PUT(ch) do { if (out < cap) buf[out++] = (ch); } while (0)

    for (int i = 0; fmt[i] != '\0' && out < cap; i++) {
        if (fmt[i] != '%') {
            KS_PUT(fmt[i]);
            continue;
        }
        i++;
        if (fmt[i] == '\0') break;

        Bool left_align = FALSE;
        Bool pad_zero = FALSE;
        int width = 0;
        if (fmt[i] == '-') {
            left_align = TRUE;
            i++;
        }
        if (fmt[i] == '0' && !left_align) {
            pad_zero = TRUE;
            i++;
        }
        while (fmt[i] >= '0' && fmt[i] <= '9') {
            width = width * 10 + (fmt[i] - '0');
            i++;
        }
        if (width > 64) width = 64;   // keeps the number scratch buffer bounded
        if (fmt[i] == '\0') break;

        char tmp[96];
        int tn = 0;
        switch (fmt[i]) {
            case 'c':
                KS_PUT((char)va_arg(args, int));
                break;
            case 's': {
                const char* sv = va_arg(args, const char*);
                if (!sv) sv = "(null)";
                size_t len = 0;
                while (sv[len]) len++;
                size_t pad = (width > 0 && (size_t)width > len) ? (size_t)width - len : 0;
                if (!left_align) for (size_t k = 0; k < pad; k++) KS_PUT(' ');
                for (size_t k = 0; k < len && out < cap; k++) KS_PUT(sv[k]);
                if (left_align) for (size_t k = 0; k < pad; k++) KS_PUT(' ');
                break;
            }
            case 'd':
            case 'i':
                print_num(va_arg(args, I64), 10, TRUE, width, pad_zero, left_align, tmp, &tn);
                break;
            case 'u':
                print_num((I64)va_arg(args, U64), 10, FALSE, width, pad_zero, left_align, tmp, &tn);
                break;
            case 'x':
            case 'X': {
                U64 x = va_arg(args, U64);
                if (width > 0 && width <= 8) x &= 0xFFFFFFFFULL;
                print_num((I64)x, 16, FALSE, width, pad_zero, left_align, tmp, &tn);
                break;
            }
            case 'p':
                print_num((I64)va_arg(args, U64), 16, FALSE, 16, TRUE, FALSE, tmp, &tn);
                break;
            case '%':
                KS_PUT('%');
                break;
        }
        for (int k = 0; k < tn; k++) KS_PUT(tmp[k]);
    }
#undef KS_PUT
    buf[out] = '\0';
    va_end(args);
    return (I64)out;
}
