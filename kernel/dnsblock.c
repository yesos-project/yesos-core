// ============================================================================
// YesOS NAS - DNS filter glue (see include/dnsblock.h, rust_core/src/dns.rs)
// ============================================================================

#include "dnsblock.h"
#include "kprintf.h"
#include "memory.h"
#include "redsea_eml.h"
#include "timer.h"
#include "virtio_net.h"
#include "shell.h"

I32  yc_dns_udp(U32 src_ip, const U8* src_mac, U16 sport, U16 dport, const U8* data, size_t len, U64 now_ms);
U0   yc_dns_poll(U64 now_ms);
U0   yc_dns_config_load(const U8* text, size_t len);
U0   yc_dns_set_default_upstream(U32 ip);
I32  yc_dns_config_text(U8* out, size_t max);
I32  yc_dns_list_name(U32 i, char* out, size_t max);
I32  yc_dns_list_load(const char* name, const U8* data, size_t len, Bool create);
I32  yc_dns_list_remove(const char* name);
I32  yc_dns_action(const char* action, const char* name, const char* value, char* msg, size_t max);
I32  yc_dns_json(char* out, size_t max, U64 now_ms);
I32  yc_dns_status(char* out, size_t max);
I32  yc_dns_log_text(char* out, size_t max, U64 now_ms, U32 count);

#define DNS_CFG       "SYS/DNS.CFG"
#define DNS_LIST_DIR  "SYS/DNSLIST/"
#define DNS_CFG_MAX   (640 * 1024)

static Bool g_dns_ready = FALSE;

static U0 list_file(const char* name, char* out, size_t max) {
    ksnprintf(out, max, DNS_LIST_DIR "%s.txt", name);
}

static Bool save_config(U0) {
    U8* buf = (U8*)Malloc(DNS_CFG_MAX);
    if (!buf) return FALSE;
    I32 n = yc_dns_config_text(buf, DNS_CFG_MAX);
    Bool ok = n >= 0 && redsea_eml_write_file(DNS_CFG, buf, (size_t)n, 0);
    Free(buf);
    if (!ok) kprintf("[DNS] could not save " DNS_CFG "\n");
    return ok;
}

// Automatic upstream: QEMU's resolver (10.0.2.3) on its user network, else the
// gateway. Used only while the owner has not chosen servers.
U0 dnsblock_refresh_upstream(U0) {
    U32 me, mask, gw;
    net_get_ipv4(&me, &mask, &gw);
    yc_dns_set_default_upstream((me & 0xFFFFFF00u) == 0x0A000200u ? 0x0A000203u : gw);
}

static Bool dns_shell_run(const char* cmd);
static U0 dns_shell_help(U0);

U0 dnsblock_init(U0) {
    static const ShellExtension ext = { dns_shell_run, dns_shell_help, NULL, NULL };
    shell_register(&ext);
    size_t size = 0;
    U8* cfg = redsea_eml_read_file(DNS_CFG, &size);
    if (cfg) {
        yc_dns_config_load(cfg, size);
        Free(cfg);
    }
    dnsblock_refresh_upstream();

    char name[40], path[64];
    U32 lists = 0, domains = 0;
    for (U32 i = 0; yc_dns_list_name(i, name, sizeof(name)) >= 0; i++) {
        list_file(name, path, sizeof(path));
        U8* data = redsea_eml_read_file(path, &size);
        I32 n = data ? yc_dns_list_load(name, data, size, FALSE) : 0;
        if (data) Free(data);
        if (n > 0) { lists++; domains += (U32)n; }
        else kprintf("[DNS] list '%s': file %s missing or empty\n", name, path);
    }
    if (!cfg) save_config();
    g_dns_ready = TRUE;
    kprintf("[DNS] Filter listening on UDP 53: %u list(s), %u domains (LAN clients only).\n", lists, domains);
}

U0 dnsblock_poll(U0) {
    if (g_dns_ready) yc_dns_poll(timer_get_uptime_ms());
}

Bool dnsblock_udp(U32 src_ip, const U8* src_mac, U16 src_port, U16 dst_port, const U8* data, size_t len) {
    if (!g_dns_ready) return FALSE;
    return yc_dns_udp(src_ip, src_mac, src_port, dst_port, data, len, timer_get_uptime_ms()) != 0;
}

I32 dnsblock_action(const char* action, const char* name, const char* value, char* msg, size_t msg_max) {
    if (StrCmp(action, "dns_list_delete") == 0) {
        if (yc_dns_list_remove(name) != 0) {
            ksnprintf(msg, msg_max, "No such list.");
            return 404;
        }
        char path[64];
        list_file(name, path, sizeof(path));
        redsea_eml_delete_file(path);
        save_config();
        ksnprintf(msg, msg_max, "List '%s' deleted.", name);
        return 200;
    }
    I32 st = yc_dns_action(action, name, value, msg, msg_max);
    if (st == 200 && StrCmp(action, "dns_upstreams") == 0) dnsblock_refresh_upstream();
    if (st == 200 && StrCmp(action, "dns_test") != 0 && StrCmp(action, "dns_cache_clear") != 0) {
        if (!save_config()) {
            ksnprintf(msg, msg_max, "Change applied, but it could not be saved to disk.");
            return 507;
        }
    }
    return st;
}

I32 dnsblock_list_store(const char* name, const U8* data, size_t len, char* msg, size_t msg_max) {
    if (len > 16 * 1024 * 1024) {
        ksnprintf(msg, msg_max, "List too large (16 MiB at most).");
        return 400;
    }
    I32 n = yc_dns_list_load(name, data, len, TRUE);
    if (n == -1) {
        ksnprintf(msg, msg_max, "Invalid name: 1-32 characters a-z, 0-9, - or _.");
        return 400;
    }
    if (n == -2) {
        ksnprintf(msg, msg_max, "At most 8 lists: delete one first.");
        return 409;
    }
    if (n == 0) {
        ksnprintf(msg, msg_max, "The file has no valid domains (hosts format or one per line).");
        return 400;
    }
    char path[64];
    list_file(name, path, sizeof(path));
    if (!redsea_eml_write_file(path, data, len, 0)) {
        yc_dns_list_remove(name);
        save_config();
        ksnprintf(msg, msg_max, "The list could not be saved to disk.");
        return 507;
    }
    save_config();
    kprintf("[DNS] list '%s' loaded: %d domains\n", name, n);
    ksnprintf(msg, msg_max, "List '%s' loaded: %d domains.", name, n);
    return 200;
}

static Bool prefix(const char* p, const char* s) {
    while (*p) if (*p++ != *s++) return FALSE;
    return TRUE;
}

U0 dnsblock_shell(const char* args) {
    while (*args == ' ') args++;
    char msg[256];
    msg[0] = '\0';
    I32 st = 200;
    static const struct { const char* cmd; const char* action; const char* value; } map[] = {
        { "test ", "dns_test", "" },        { "allow ", "dns_allow", "add" },   { "unallow ", "dns_allow", "del" },
        { "block ", "dns_block", "add" },   { "unblock ", "dns_block", "del" }, { "upstream ", "dns_upstreams", NULL },
        { "log ", "dns_log", NULL },        { "doh ", "dns_doh", NULL },        { "list on ", "dns_list", "1" },
        { "list off ", "dns_list", "0" },   { "list delete ", "dns_list_delete", "" },
    };
    if (*args == '\0' || StrCmp(args, "status") == 0) {
        static char status[512];
        yc_dns_status(status, sizeof(status));
        kprintf("[DNS] %s\n", status);
        return;
    } else if (StrCmp(args, "on") == 0 || StrCmp(args, "off") == 0) {
        st = dnsblock_action("dns_enable", "", args[1] == 'n' ? "1" : "0", msg, sizeof(msg));
    } else if (StrCmp(args, "log") == 0) {
        static char text[16 * 1024];
        if (yc_dns_log_text(text, sizeof(text), timer_get_uptime_ms(), 40) >= 0) kprintf("%s", text);
        return;
    } else if (prefix("list add ", args)) {
        // A list copied onto the disk beforehand (e.g. with tools/redsea_injector.py)
        const char* name = args + 9;
        char path[64];
        list_file(name, path, sizeof(path));
        size_t size = 0;
        U8* data = redsea_eml_read_file(path, &size);
        if (!data) {
            kprintf("[DNS] error: %s not found (copy the list there first)\n", path);
            return;
        }
        st = dnsblock_list_store(name, data, size, msg, sizeof(msg));
        Free(data);
    } else if (StrCmp(args, "flush") == 0) {
        st = dnsblock_action("dns_cache_clear", "", "", msg, sizeof(msg));
    } else {
        U32 i;
        for (i = 0; i < sizeof(map) / sizeof(map[0]); i++) {
            if (prefix(map[i].cmd, args)) {
                const char* arg = args + StrLen(map[i].cmd);
                st = map[i].value ? dnsblock_action(map[i].action, arg, map[i].value, msg, sizeof(msg))
                                  : dnsblock_action(map[i].action, "", arg, msg, sizeof(msg));
                break;
            }
        }
        if (i == sizeof(map) / sizeof(map[0])) {
            kprintf("usage: dns [status | log | on | off | flush | test <domain> | allow|unallow|block|unblock <domain> |\n"
                    "            upstream <ip[:port]> ... | log on|off|clear | doh on|off | list add|on|off|delete <name>]\n");
            return;
        }
    }
    kprintf("[DNS] %s%s\n", st == 200 ? "" : "error: ", msg);
}

static Bool dns_shell_run(const char* cmd) {
    if (StrCmp(cmd, "dns") != 0 && !shell_is_prefix("dns ", cmd)) return FALSE;
    dnsblock_shell(cmd + 3);
    return TRUE;
}

static U0 dns_shell_help(U0) {
    kprintf("  DNS filter (UDP 53)\n");
    kprintf("    dns  dns log  dns test <domain>  dns allow|block|unallow|unblock <domain>  dns upstream <ip>...|auto\n");
    kprintf("    dns log on|off|clear  dns doh on|off  dns list add|on|off|delete <name>  (lists: SYS/DNSLIST/<name>.txt)\n");
}
