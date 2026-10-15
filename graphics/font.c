// YesOS font helpers: UTF-8 decoding and glyph lookup for the 8x16 font.
#include "font.h"

U32 font_utf8_next(const char** sp) {
    const U8* s = (const U8*)*sp;
    U32 cp = 0xFFFD, len = 1;
    if (s[0] < 0x80) {
        cp = s[0];
    } else if ((s[0] & 0xE0) == 0xC0 && (s[1] & 0xC0) == 0x80) {
        cp = ((U32)(s[0] & 0x1F) << 6) | (s[1] & 0x3F);
        len = 2;
    } else if ((s[0] & 0xF0) == 0xE0 && (s[1] & 0xC0) == 0x80 && (s[2] & 0xC0) == 0x80) {
        cp = ((U32)(s[0] & 0x0F) << 12) | ((U32)(s[1] & 0x3F) << 6) | (s[2] & 0x3F);
        len = 3;
    } else if ((s[0] & 0xF8) == 0xF0 && (s[1] & 0xC0) == 0x80 && (s[2] & 0xC0) == 0x80 && (s[3] & 0xC0) == 0x80) {
        cp = 0x10000;                                   // beyond the font in any case
        len = 4;
    }
    *sp += len;                                         // a continuation byte is never NUL
    return cp;
}

const U8* font_glyph(U32 cp) {
    if (cp == ' ') return g_font_8x16[' '];
    if (cp <= 0xFF) {
        for (U32 r = 0; r < FONT_HEIGHT; r++)
            if (g_font_8x16[cp][r]) return g_font_8x16[cp];
    }
    return g_font_8x16['?'];
}
