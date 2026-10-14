// ============================================================================
// YesOS core - static IPv4 address of the NAS's own stack (SYS/NET.CFG)
// ============================================================================

#include "netcfg.h"
#include "kprintf.h"
#include "memory.h"
#include "redsea_eml.h"
#include "virtio_net.h"

#define NET_CFG "SYS/NET.CFG"
#define NETCFG_HOOKS 4

static NetcfgHook s_hooks[NETCFG_HOOKS];
static U32 s_hook_count = 0;

U0 netcfg_on_change(NetcfgHook fn) {
    if (fn && s_hook_count < NETCFG_HOOKS) s_hooks[s_hook_count++] = fn;
}

static Bool parse_ipv4(const char** p, U32* out) {
    U32 v = 0;
    for (U32 k = 0; k < 4; k++) {
        if (**p < '0' || **p > '9') return FALSE;
        U32 b = 0;
        while (**p >= '0' && **p <= '9') { b = b * 10 + (U32)(**p - '0'); (*p)++; if (b > 255) return FALSE; }
        v = (v << 8) | b;
        if (k < 3) { if (**p != '.') return FALSE; (*p)++; }
    }
    *out = v;
    return TRUE;
}

// "a.b.c.d/nn [gw a.b.c.d]" -> TRUE and the values.
static Bool parse_net_cfg(const char* s, U32* ip, U32* mask, U32* gw) {
    while (*s == ' ') s++;
    if (!parse_ipv4(&s, ip) || *s != '/') return FALSE;
    s++;
    U32 pfx = 0;
    if (*s < '0' || *s > '9') return FALSE;
    while (*s >= '0' && *s <= '9') pfx = pfx * 10 + (U32)(*s++ - '0');
    if (pfx < 8 || pfx > 30) return FALSE;
    *mask = 0xFFFFFFFFu << (32 - pfx);
    *gw = 0;
    while (*s == ' ') s++;
    if (s[0] == 'g' && s[1] == 'w' && s[2] == ' ') {
        s += 3;
        while (*s == ' ') s++;
        if (!parse_ipv4(&s, gw) || ((*gw ^ *ip) & *mask) != 0) return FALSE;
    }
    while (*s == ' ' || *s == '\n' || *s == '\r') s++;
    return *s == '\0' && (*ip & ~*mask) != 0 && (*ip & ~*mask) != ~*mask;
}

U0 netcfg_load(U0) {
    size_t size = 0;
    U8* net = redsea_eml_read_file(NET_CFG, &size);
    if (net) {
        char line[96];
        size_t n = size < sizeof(line) - 1 ? size : sizeof(line) - 1;
        MemCpy(line, net, n);
        line[n] = '\0';
        Free(net);
        U32 ip, mask, gw;
        if (parse_net_cfg(line, &ip, &mask, &gw)) {
            net_set_ipv4(ip, mask, gw);
            kprintf("[NET] static address %u.%u.%u.%u/%u from " NET_CFG "\n", ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255,
                    (U32)__builtin_popcount(mask));
        } else {
            kprintf("[NET] " NET_CFG " ignored: not 'a.b.c.d/nn [gw a.b.c.d]'\n");
        }
    }
}

U0 netcfg_shell(const char* args) {
    while (*args == ' ') args++;
    U32 ip, mask, gw;
    if (*args == '\0') {
        net_get_ipv4(&ip, &mask, &gw);
        kprintf("[NET] %u.%u.%u.%u/%u gw %u.%u.%u.%u\n", ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255,
                (U32)__builtin_popcount(mask), gw >> 24, (gw >> 16) & 255, (gw >> 8) & 255, gw & 255);
        return;
    }
    if (StrCmp(args, "default") == 0) {
        redsea_eml_delete_file(NET_CFG);
        kprintf("[NET] static address removed; the default applies after a reboot.\n");
        return;
    }
    if (!parse_net_cfg(args, &ip, &mask, &gw)) {
        kprintf("usage: net ip <a.b.c.d/nn> [gw <a.b.c.d>]   |   net ip default\n");
        return;
    }
    net_set_ipv4(ip, mask, gw);
    for (U32 i = 0; i < s_hook_count; i++) s_hooks[i]();
    if (redsea_eml_write_file(NET_CFG, args, StrLen(args), 0)) kprintf("[NET] address set and saved.\n");
    else kprintf("[NET] address set, but " NET_CFG " could not be saved.\n");
}
