#include "shell.h"
#include "pci.h"
#include "vault.h"
#include "product.h"
#include "netcfg.h"
#include "integrity.h"
#include "keyhart.h"
#include "cell.h"
#include "yesos_crypto.h"
#include "timer.h"
#include "memory.h"
#include "speaker.h"
#include "kprintf.h"
#include "ports.h"
#include "task.h"
#include "ramfs.h"
#include "holyq_jit.h"
#include "airgap_firewall.h"
#include "ata.h"
#include "redsea_eml.h"
#include "security_pin.h"
#include "vfs.h"
#include "pmp.h"
#include "smp.h"
#include "virtio_blk.h"
#include "barrett_poly.h"
#include "virtio_net.h"

// Admin shell on the serial console (UART): core commands here; each product
// adds its own with shell_register().

#define CMD_BUFFER_SIZE 256

#define SHELL_MAX_EXTENSIONS 8
static const ShellExtension* g_ext[SHELL_MAX_EXTENSIONS];
static U32 g_ext_count = 0;

static char g_cmd_line[CMD_BUFFER_SIZE];
static int g_cmd_idx = 0;

// QEMU virt / SiFive test finisher (0x100000). On real boards without it the
// hart just parks.
U0 sys_poweroff(U0) {
    kprintf("\n[SYSTEM] YesOS shutdown.\n");
    SleepMS(50);
    mmio_write32(0x100000, 0x5555);
    kprintf("[SYSTEM] Halted. Safe to power off.\n");
    cli();
    while (1) hlt();
}

U0 sys_reboot(U0) {
    kprintf("\n[SYSTEM] YesOS reboot.\n");
    SleepMS(50);
    cli();
    mmio_write32(0x100000, 0x7777);
    while (1) hlt();
}

static U64 parse_uint(const char* p);
static Bool is_prefix(const char* prefix, const char* str);

Bool shell_secret_prompt_active(U0) {
    for (U32 i = 0; i < g_ext_count; i++) {
        if (g_ext[i]->prompt && g_ext[i]->prompt()) return TRUE;
    }
    return FALSE;
}

const char* shell_secret_prompt_label(U0) {
    for (U32 i = 0; i < g_ext_count; i++) {
        const char* l = g_ext[i]->prompt ? g_ext[i]->prompt() : NULL;
        if (l) return l;
    }
    return "";
}

U64 shell_parse_uint(const char* p) {
    return parse_uint(p);
}

Bool shell_is_prefix(const char* prefix, const char* str) {
    return is_prefix(prefix, str);
}

static U0 print_prompt(U0) {
    if (security_pin_is_locked()) kprintf("\nPIN> ");
    else kprintf("\nYesOS [%s]> ", vfs_get_cwd());
}

U0 shell_init(U0) {
    g_cmd_idx = 0;
    g_cmd_line[0] = '\0';
    kprintf("\n");
    kprintf("================================================================================\n");
    kprintf("  %s // RISC-V M-mode\n", PRODUCT_NAME);
    kprintf("  YesOS core: locked PMP (Z3-proven) | key hart | PMP cells | RedSea\n");
    kprintf("================================================================================\n");
    kprintf("Type 'help' for commands.\n");
    print_prompt();
}


U0 shell_register(const ShellExtension* ext) {
    if (ext && g_ext_count < SHELL_MAX_EXTENSIONS) g_ext[g_ext_count++] = ext;
}

static U64 parse_uint(const char* p) {
    while (*p == ' ') p++;
    U64 v = 0;
    while (*p >= '0' && *p <= '9') v = v * 10 + (U64)(*p++ - '0');
    return v;
}

static Bool is_prefix(const char* prefix, const char* str) {
    while (*prefix) {
        if (*prefix != *str) return FALSE;
        prefix++;
        str++;
    }
    return TRUE;
}

static Bool has_char(const char* str, char c) {
    while (*str) {
        if (*str == c) return TRUE;
        str++;
    }
    return FALSE;
}

static Bool has_suffix(const char* str, const char* suffix) {
    if (!str || !suffix) return FALSE;
    size_t slen = StrLen(str);
    size_t sufflen = StrLen(suffix);
    if (slen < sufflen) return FALSE;
    return StrCmp(str + slen - sufflen, suffix) == 0;
}

U0 shell_execute_command(const char* cmd) {
    for (U32 i = 0; i < g_ext_count; i++) {
        if (g_ext[i]->capture && g_ext[i]->capture(cmd)) return;   // a pending hidden prompt took the line
    }

    // Locked console: the only accepted input is the Master PIN.
    if (security_pin_is_locked()) {
        if (*cmd) security_pin_unlock(cmd);
        return;
    }

    while (*cmd == ' ') cmd++; // Skip leading spaces
    if (*cmd == '\0') return;

    TaskClearBreak();

    if (StrCmp(cmd, "help") != 0) {
        for (U32 i = 0; i < g_ext_count; i++) {
            if (g_ext[i]->run(cmd)) return;
        }
    }

    if (StrCmp(cmd, "help") == 0) {
        kprintf("\n================ [ %s CONSOLE ] ================\n", PRODUCT_NAME);
        kprintf("  Files (VFS)\n");
        kprintf("    ls/dir [path]  cd <path>  pwd  tree [path]  cat <file>\n");
        kprintf("    write <path> <text>  mkdir <path>  rm <path>\n");
        kprintf("  Storage (RedSea)\n");
        kprintf("    disk                 volume, devices and directory\n");
        kprintf("    disk cat|save|rm|verify <name>, disk free, disk bench\n");
        kprintf("    format ERASE-ALL     erase the volume\n");
        kprintf("    fsck [quick]          check the volume (structure + every file's CRC)\n");
        kprintf("  Console\n");
        kprintf("    pin [status|set <6 digits>|change <old> <new>]   lock\n");
        kprintf("  Network\n");
        kprintf("    net  ping [ip]  net bench  net ip <a.b.c.d/nn> [gw <ip>] | default   firewall [status|audit]\n");
        kprintf("  Isolation and integrity\n");
        kprintf("    pmp  pmp test  cell  cell test  cell run <file.HQ> [n]\n");
        kprintf("    keyhart test  integrity\n");
        kprintf("  HolyQ\n");
        kprintf("    run <file.HQ>  jit <code>  jit bench|rvv|disasm <f>  (console: full privileges)\n");
        kprintf("  System\n");
        kprintf("    sysinfo  mem  hardening  smp  uptime  tasks  ata  pci  clear  reboot  poweroff\n");
        for (U32 i = 0; i < g_ext_count; i++) if (g_ext[i]->help) g_ext[i]->help();
        kprintf("=============================================================\n");
    } else if (StrCmp(cmd, "clear") == 0 || StrCmp(cmd, "cls") == 0) {
        kprintf("\x1b[2J\x1b[H");
    } else if (StrCmp(cmd, "pwd") == 0) {
        vfs_cmd_pwd();
        speaker_event(BEEP_CONFIRM);
    } else if (StrCmp(cmd, "cd") == 0) {
        vfs_cmd_cd("/");
    } else if (is_prefix("cd ", cmd)) {
        const char* p = cmd + 3;
        while (*p == ' ') p++;
        vfs_cmd_cd(p);
    } else if (StrCmp(cmd, "dir") == 0 || StrCmp(cmd, "ls") == 0) {
        vfs_cmd_ls(NULL);
    } else if (is_prefix("ls ", cmd) || is_prefix("dir ", cmd)) {
        const char* p = cmd + (cmd[0] == 'l' ? 3 : 4);
        while (*p == ' ') p++;
        vfs_cmd_ls(p);
    } else if (is_prefix("mkdir ", cmd) || is_prefix("md ", cmd)) {
        const char* p = cmd + (cmd[1] == 'k' ? 6 : 3);
        while (*p == ' ') p++;
        vfs_cmd_mkdir(p);
    } else if (StrCmp(cmd, "tree") == 0) {
        vfs_print_tree(NULL, 4);
    } else if (is_prefix("tree ", cmd)) {
        const char* p = cmd + 5;
        while (*p == ' ') p++;
        vfs_print_tree(p, 4);
    } else if (is_prefix("cat ", cmd) || is_prefix("type ", cmd)) {
        const char* p = cmd + (cmd[0] == 'c' ? 4 : 5);
        while (*p == ' ') p++;
        vfs_cmd_cat(p);
    } else if (is_prefix("write ", cmd)) {
        // write <path> <text> : stores text through the VFS (honours /vault encryption)
        const char* p = cmd + 6;
        while (*p == ' ') p++;
        char path[VFS_MAX_PATH];
        int pi = 0;
        while (*p != ' ' && *p != '\0' && pi < VFS_MAX_PATH - 1) path[pi++] = *p++;
        path[pi] = '\0';
        while (*p == ' ') p++;
        if (path[0] == '\0') {
            kprintf("Usage: write <path> <text>\n");
        } else if (vfs_write_file(path, p, StrLen(p))) {
            kprintf("write: %u bytes -> %s\n", (U32)StrLen(p), path);
            speaker_event(BEEP_SUCCESS);
        } else {
            kprintf("write: failed to write %s\n", path);
            speaker_event(BEEP_WARN);
        }
    } else if (is_prefix("rm ", cmd) || is_prefix("del ", cmd)) {
        const char* p = cmd + 3;
        while (*p == ' ') p++;
        vfs_cmd_rm(p);
    } else if (is_prefix("run ", cmd) || is_prefix("#include ", cmd)) {
        const char* p = cmd + (cmd[0] == 'r' ? 4 : 9);
        while (*p == ' ' || *p == '"' || *p == '<') p++;
        char fname[64];
        int fi = 0;
        while (*p != ' ' && *p != '"' && *p != '>' && *p != '\0' && fi < 63) fname[fi++] = *p++;
        fname[fi] = '\0';
        holyq_jit_exec_file(fname);
    } else if (StrCmp(cmd, "jit bench") == 0 || StrCmp(cmd, "jitbench") == 0) {
        holyq_jit_benchmark();
    } else if (StrCmp(cmd, "jit rvv") == 0 || StrCmp(cmd, "rvv bench") == 0 || StrCmp(cmd, "rvv") == 0 || StrCmp(cmd, "jit rvv bench") == 0) {
        holyq_jit_rvv_benchmark();
    } else if (is_prefix("jit disasm ", cmd) || is_prefix("jit disas ", cmd)) {
        const char* p = cmd + (is_prefix("jit disasm ", cmd) ? 11 : 10);
        while (*p == ' ') p++;
        holyq_jit_disasm(p);
    } else if (is_prefix("jit ", cmd) || is_prefix("hq ", cmd)) {
        const char* p = cmd + (cmd[0] == 'j' ? 4 : 3);
        while (*p == ' ') p++;
        if (StrCmp(p, "bench") == 0) {
            holyq_jit_benchmark();
        } else if (StrCmp(p, "rvv") == 0 || StrCmp(p, "rvv bench") == 0) {
            holyq_jit_rvv_benchmark();
        } else if (is_prefix("disasm ", p) || is_prefix("disas ", p)) {
            const char* dp = p + (is_prefix("disasm ", p) ? 7 : 6);
            while (*dp == ' ') dp++;
            holyq_jit_disasm(dp);
        } else if (has_suffix(p, ".HQ") || has_suffix(p, ".hq")) {
            holyq_jit_exec_file(p);
        } else {
            holyq_jit_compile_and_run(p);
        }
        speaker_event(BEEP_SUCCESS);
    } else if (StrCmp(cmd, "jit") == 0 || StrCmp(cmd, "hq") == 0) {
        kprintf("\n================ [ YESOS HOLYQ NATIVE RV64GC JIT ] ================\n");
        kprintf("Commands:\n");
        kprintf("  jit <code_line>       - Execute statement or define function in RAM\n");
        kprintf("  jit bench             - Run full RV64GC JIT hardware benchmark suite\n");
        kprintf("  jit rvv               - Run RVV 1.0 vector auto-vectorization benchmark\n");
        kprintf("  jit disasm <func>     - Disassemble native RISC-V machine instructions\n");
        kprintf("  jit <script.hq>       - Execute HolyQ script file (full privileges: console only)\n");
        kprintf("====================================================================\n\n");
    } else if (StrCmp(cmd, "net") == 0 || StrCmp(cmd, "ifconfig") == 0 || StrCmp(cmd, "netstat") == 0) {
        net_print_status();
        speaker_event(BEEP_CONFIRM);
    } else if (StrCmp(cmd, "net bench") == 0 || StrCmp(cmd, "netbench") == 0) {
        net_run_benchmark();
    } else if (is_prefix("ping", cmd)) {
        const char* p = cmd + 4;
        while (*p == ' ') p++;
        if (*p == '\0') {
            net_ping("10.0.2.2", 4);
        } else {
            char ip_buf[32];
            int ii = 0;
            while (*p != ' ' && *p != '\0' && ii < 31) ip_buf[ii++] = *p++;
            ip_buf[ii] = '\0';
            net_ping(ip_buf, 4);
        }
    } else if (StrCmp(cmd, "fsck") == 0 || StrCmp(cmd, "fsck quick") == 0) {
        Bool full = StrCmp(cmd, "fsck") == 0;
        kprintf("Checking RedSea volume%s...\n", full ? " (structure and every file's CRC)" : " (structure only)");
        RedSeaFsckReport r;
        Bool ok = redsea_eml_fsck(full, TRUE, &r);
        kprintf("fsck: %s - %u error(s), %u warning(s) in %u ms\n", ok ? "CLEAN" : "PROBLEMS FOUND", r.errors, r.warnings, (U32)r.duration_ms);
        kprintf("  %u files, %u directories, %u shared extents (snapshots), %u legacy file(s) in /backup\n",
                r.files, r.dirs, r.shared_extents, r.legacy_backup_files);
        kprintf("  sectors: %u used, %u free, %u lost\n", (U32)r.used_sectors, (U32)r.free_sectors, (U32)r.lost_sectors);
        if (full) kprintf("  data: %u CRC OK, %u legacy CRC OK, %u BAD, %u unreadable\n", r.crc_ok, r.crc_legacy, r.crc_bad, r.unreadable);
    } else if (StrCmp(cmd, "net ip") == 0 || is_prefix("net ip ", cmd)) {
        netcfg_shell(cmd + 6);
    } else if (StrCmp(cmd, "pmp test") == 0 || StrCmp(cmd, "pmp fault") == 0 || StrCmp(cmd, "pmp sandbox") == 0 || StrCmp(cmd, "pmptest") == 0) {
        speaker_event(pmp_self_test() ? BEEP_SUCCESS : BEEP_ERROR);
    } else if (StrCmp(cmd, "cell") == 0 || StrCmp(cmd, "cells") == 0) {
        cell_print_status();
    } else if (StrCmp(cmd, "integrity") == 0) {
        integrity_print_status();
    } else if (StrCmp(cmd, "keyhart test") == 0 || StrCmp(cmd, "vault keytest") == 0) {
        speaker_event(keyhart_self_test() ? BEEP_SUCCESS : BEEP_ERROR);
    } else if (StrCmp(cmd, "cell test") == 0) {
        speaker_event(cell_self_test() ? BEEP_SUCCESS : BEEP_ERROR);
    } else if (is_prefix("cell run ", cmd)) {
        // cell run <file.HQ> [arg] : compile the file's function in cell mode and run it isolated
        const char* p = cmd + 9;
        while (*p == ' ') p++;
        char path[VFS_MAX_PATH];
        int pi = 0;
        while (*p && *p != ' ' && pi < VFS_MAX_PATH - 1) path[pi++] = *p++;
        path[pi] = '\0';
        while (*p == ' ') p++;
        I64 arg = 0;
        Bool neg = (*p == '-');
        if (neg) p++;
        while (*p >= '0' && *p <= '9') arg = arg * 10 + (*p++ - '0');
        if (neg) arg = -arg;
        size_t sz = 0;
        U8* src = vfs_read_file(path, &sz);
        if (!src) {
            kprintf("cell run: cannot read %s\n", path);
        } else {
            CellResult r;
            Bool ok = cell_run_source((const char*)src, &arg, 1, 5000, &r);
            Free(src);
            if (ok) kprintf("[CELL] result = %d\n", (I32)r.value);
            else    kprintf("[CELL] %s\n", r.reason);
        }
    } else if (StrCmp(cmd, "pmp") == 0 || StrCmp(cmd, "pmpinfo") == 0) {
        pmp_dump_config();
        speaker_event(BEEP_SUCCESS);
    } else if (StrCmp(cmd, "mem") == 0) {
        speaker_event(BEEP_CONFIRM);
        MemStats s = mem_get_stats();
        kprintf("\n--- [ Memory Statistics & Hardening Telemetry ] ---\n");
        kprintf("Total RAM detected   : %u MB\n", (U32)(s.total_ram / (1024 * 1024)));
        kprintf("Heap base address    : 0x%p\n", s.heap_start);
        kprintf("Heap limit address   : 0x%p\n", s.heap_end);
        kprintf("Heap memory in use   : %u KB\n", (U32)(s.heap_used / 1024));
        kprintf("Active allocations   : %u blocks\n", (U32)s.num_allocations);
        kprintf("Double-frees guarded : %u\n", (U32)s.double_frees_prevented);
        kprintf("Heap overflows caught: %u\n", (U32)s.heap_overflows_detected);
        kprintf("Invalid ptrs rejected: %u\n\n", (U32)s.invalid_ptrs_rejected);
    } else if (StrCmp(cmd, "hardening") == 0 || StrCmp(cmd, "audit") == 0 || StrCmp(cmd, "sec") == 0 || StrCmp(cmd, "heapcheck") == 0) {
        speaker_event(BEEP_CONFIRM);
        demo_kernel_hardening_suite();
        speaker_event(BEEP_SUCCESS);
    } else if (StrCmp(cmd, "smp") == 0 || StrCmp(cmd, "smp status") == 0 || StrCmp(cmd, "cores") == 0 || StrCmp(cmd, "harts") == 0) {
        speaker_event(BEEP_CONFIRM);
        smp_print_telemetry();
    } else if (StrCmp(cmd, "uptime") == 0) {
        speaker_event(BEEP_CONFIRM);
        U64 ms = timer_get_uptime_ms();
        kprintf("Uptime: %u.%03u seconds (CLINT mtime)\n", (U32)(ms / 1000), (U32)(ms % 1000));
    } else if (StrCmp(cmd, "tasks") == 0) {
        speaker_event(BEEP_CONFIRM);
        TaskControlBlock* cur = TaskCurrent();
        kprintf("Current Task: %s (TID: %u, State: Running)\n", cur ? cur->name : "Unknown", cur ? (U32)cur->task_id : 0);
    } else if (StrCmp(cmd, "ata") == 0 || StrCmp(cmd, "hdd") == 0 || StrCmp(cmd, "virtio blk") == 0) {
        speaker_event(BEEP_CONFIRM);
        ata_dump_telemetry();
    } else if (StrCmp(cmd, "virtio bench") == 0 || StrCmp(cmd, "blk bench") == 0) {
        speaker_event(BEEP_CONFIRM);
        virtio_blk_benchmark();
        speaker_event(BEEP_SUCCESS);
    } else if (StrCmp(cmd, "barrett") == 0 || StrCmp(cmd, "barrett bench") == 0 || StrCmp(cmd, "crc64") == 0) {
        speaker_event(BEEP_CONFIRM);
        barrett_poly_benchmark();
        speaker_event(BEEP_SUCCESS);
    } else if (StrCmp(cmd, "disk bench") == 0) {
        speaker_event(BEEP_CONFIRM);
        virtio_blk_benchmark();
        redsea_eml_benchmark();
        speaker_event(BEEP_SUCCESS);
    } else if (StrCmp(cmd, "disk extents") == 0 || StrCmp(cmd, "extents") == 0 || StrCmp(cmd, "disk free") == 0 || StrCmp(cmd, "free") == 0) {
        speaker_event(BEEP_CONFIRM);
        redsea_eml_list_free_extents();
    } else if (StrCmp(cmd, "disk test") == 0 || StrCmp(cmd, "extent test") == 0) {
        speaker_event(BEEP_CONFIRM);
        redsea_eml_test_free_extent();
        speaker_event(BEEP_SUCCESS);
    } else if (StrCmp(cmd, "disk sync") == 0 || StrCmp(cmd, "sync") == 0) {
        speaker_event(BEEP_CONFIRM);
        redsea_eml_sync_from_ramfs();
    } else if (is_prefix("disk load ", cmd)) {
        const char* p = cmd + 10;
        while (*p == ' ') p++;
        speaker_event(BEEP_CONFIRM);
        redsea_eml_load_to_ramfs(p);
    } else if (is_prefix("disk cat ", cmd)) {
        const char* p = cmd + 9;
        while (*p == ' ') p++;
        speaker_event(BEEP_CONFIRM);
        size_t sz = 0;
        U8* data = redsea_eml_read_file(p, &sz);
        if (data) {
            kprintf("\n--- File '%s' (%u Bytes) on Persistent RedSea Disk ---\n", p, (U32)sz);
            kprintf("%s\n", (const char*)data);
            kprintf("------------------------------------------------------\n");
            Free(data);
        } else {
            kprintf("RedSea-EML: File '%s' not found.\n", p);
        }
    } else if (is_prefix("disk rm ", cmd) || is_prefix("disk del ", cmd)) {
        const char* p = cmd + (cmd[5] == 'r' ? 8 : 9);
        while (*p == ' ') p++;
        if (redsea_eml_delete_file(p)) {
            kprintf("RedSea-EML: File '%s' deleted from persistent disk.\n", p);
            speaker_event(BEEP_WARN);
        } else {
            kprintf("RedSea-EML: Failed to delete '%s'.\n", p);
        }
    } else if (is_prefix("disk save ", cmd)) {
        const char* p = cmd + 10;
        while (*p == ' ') p++;
        char fname[32];
        int fi = 0;
        while (*p != ' ' && *p != '\0' && fi < 31) fname[fi++] = *p++;
        fname[fi] = '\0';
        while (*p == ' ') p++;
        size_t slen = StrLen(p);
        if (redsea_eml_write_file(fname, p, slen, 0)) {
            kprintf("RedSea-EML: Saved '%s' (%u bytes) to persistent storage.\n", fname, (U32)slen);
            speaker_event(BEEP_SUCCESS);
        } else {
            kprintf("RedSea-EML: Failed to save '%s'.\n", fname);
        }
    } else if (is_prefix("disk verify ", cmd) || is_prefix("barrett verify ", cmd)) {
        const char* p = cmd + (cmd[0] == 'd' ? 12 : 15);
        while (*p == ' ') p++;
        U64 crc = 0;
        if (redsea_eml_verify_barrett(p, &crc)) {
            kprintf("RedSea-EML: File '%s' Barrett CRC64 (Zbc clmul): 0x%p [INTEGRITY OK]\n", p, (void*)crc);
            speaker_event(BEEP_SUCCESS);
        } else {
            kprintf("RedSea-EML: File '%s' not found on disk.\n", p);
        }
    } else if (StrCmp(cmd, "pci") == 0) {
        pci_print();
    } else if (StrCmp(cmd, "disk") == 0 || StrCmp(cmd, "disks") == 0 || StrCmp(cmd, "redsea") == 0 || StrCmp(cmd, "vol") == 0) {
        speaker_event(BEEP_CONFIRM);
        kprintf("\n================ [ YESOS APPLIANCE DISK SUBSYSTEM ] ================\n");
        if (virtio_blk_is_present()) {
            VirtIOBlkInfo* bi = virtio_blk_get_info();
            kprintf("  VirtIO-Block PCI  : %u MB (%u Sectors DMA Synchronous)\n",
                    (U32)(bi->capacity_bytes / (1024*1024)), (U64)bi->total_sectors);
        }
        kprintf("  S.M.A.R.T.        : not available (virtio-blk exposes no SMART data)\n");
        kprintf("--------------------------------------------------------------------\n");
        kprintf("  Persistent Volume Directory Listing (RedSea-EML Contiguous LBA):\n");
        redsea_eml_list_files();
        kprintf("====================================================================\n\n");
    } else if (StrCmp(cmd, "format") == 0 || is_prefix("format ", cmd)) {
        // Erases the whole volume: require an explicit confirmation word.
        if (StrCmp(cmd, "format ERASE-ALL") == 0) {
            redsea_eml_format(0, "YESOS_EML_ROOT");
        } else {
            kprintf("format erases every file on the RedSea volume (including vault ciphertext).\n");
            kprintf("To proceed type exactly: format ERASE-ALL\n");
        }
    } else if (StrCmp(cmd, "lock") == 0) {
        security_pin_lock();
        if (security_pin_is_locked()) {
            kprintf("\n[SECURITY] Serial console LOCKED. Enter the Master PIN to continue.\n");
        }
    } else if (StrNCmp(cmd, "pin", 3) == 0 || StrNCmp(cmd, "passwd", 6) == 0 || StrNCmp(cmd, "password", 8) == 0) {
        const char* sub = cmd;
        if (StrNCmp(cmd, "passwd", 6) == 0) sub += 6;
        else if (StrNCmp(cmd, "password", 8) == 0) sub += 8;
        else sub += 3;
        while (*sub == ' ') sub++;
        if (*sub == '\0' || StrCmp(sub, "status") == 0) {
            SecurityPinState* ps = security_pin_get_state();
            kprintf("\n================ [ PHYSICAL CONSOLE SECURITY PIN ] ================\n");
            kprintf("  Console Lock:      %s\n", ps->is_locked ? "LOCKED (Master PIN required)" : "UNLOCKED");
            kprintf("  Failed Attempts:   %u / %u\n", ps->failed_attempts, PIN_MAX_FAILED);
            kprintf("  Penalty Lockout:   %s\n", security_pin_is_in_lockout() ? "ACTIVE (30s Cooldown)" : "INACTIVE");
            kprintf("  Config Storage:    SYS/PIN.CFG (RedSea / RamFS Persistent)\n");
            kprintf("  Hash Verification: Argon2id (8 MiB, t=3) + 128-bit salt\n");
            kprintf("\n  Change the Master PIN:\n");
            kprintf("    pin set <new_6_digits>            - Set the Master PIN (e.g. pin set 654321)\n");
            kprintf("    pin change <current> <new>        - Change the PIN, checking the current one\n");
            kprintf("    passwd <new_6_digits>             - Same as pin set\n");
            kprintf("    lock                              - Lock the serial console (asks for the PIN)\n");
            kprintf("===================================================================\n");
            speaker_event(BEEP_SUCCESS);
        } else if (StrNCmp(sub, "set ", 4) == 0 || StrNCmp(sub, "change ", 7) == 0) {
            const char* args = (StrNCmp(sub, "set ", 4) == 0) ? (sub + 4) : (sub + 7);
            while (*args == ' ') args++;
            char p1[32] = {0};
            char p2[32] = {0};
            int i = 0;
            while (*args && *args != ' ' && i < 30) p1[i++] = *args++;
            p1[i] = '\0';
            while (*args == ' ') args++;
            i = 0;
            while (*args && *args != ' ' && i < 30) p2[i++] = *args++;
            p2[i] = '\0';

            if (p2[0] != '\0') {
                security_pin_change(p1, p2);
            } else if (p1[0] != '\0') {
                security_pin_change(NULL, p1);
            } else {
                kprintf("Usage: pin set <new_6_digits>  or  pin change <current> <new_6_digits>\n");
            }
        } else if (StrNCmp(sub, "unlock ", 7) == 0) {
            const char* test_pin = sub + 7;
            while (*test_pin == ' ') test_pin++;
            security_pin_unlock(test_pin);
        } else if (StrLen(sub) == 6) {
            // Direct 6 numeric digits: if console is locked, unlock; if unlocked, change PIN
            if (security_pin_is_locked()) {
                security_pin_unlock(sub);
            } else {
                security_pin_change(NULL, sub);
            }
        } else {
            kprintf("Usage: pin [status | set <6-dig> | change <current> <new> | unlock <6-dig>]\n");
            kprintf("       passwd <new_6_digits>\n");
        }
    } else if (StrNCmp(cmd, "firewall", 8) == 0) {
        const char* sub = cmd + 8;
        while (*sub == ' ') sub++;
        if (*sub == '\0' || StrNCmp(sub, "status", 6) == 0) {
            firewall_print_status();
            speaker_event(BEEP_SUCCESS);
        } else if (StrNCmp(sub, "audit", 5) == 0 || StrNCmp(sub, "test", 4) == 0) {
            firewall_audit();
            speaker_event(BEEP_SUCCESS);
        } else {
            kprintf("Usage: firewall [status | audit]\n");
        }
    } else if (StrCmp(cmd, "sysinfo") == 0 || StrCmp(cmd, "info") == 0) {
        MemStats ms = mem_get_stats();
        RedSeaVolume* v = redsea_eml_get_volume();
        kprintf("\n  YesOS NAS 2.0 (RISC-V RV64GCV, M-mode, locked PMP)\n");
        kprintf("  Harts online     : %u (0 kernel, 2 key hart, 3+ PMP cells)\n", smp_get_online_harts());
        kprintf("  PMP              : %s on %u hart(s)\n",
                pmp_get_state() == PMP_STATE_LOCKED_PROVEN ? "Z3-proven layout" : "boot-verified layout",
                pmp_locked_hart_count());
        kprintf("  Memory           : %u MB | heap in use %u KB\n",
                (U32)(ms.total_ram / (1024 * 1024)), (U32)(ms.heap_used / 1024));
        if (v && v->is_mounted) {
            kprintf("  RedSea volume    : %u MB, %u MB free\n",
                    (U32)((v->sb.total_sectors * 512) / (1024 * 1024)),
                    (U32)((redsea_eml_get_free_sectors() * 512) / (1024 * 1024)));
        } else {
            kprintf("  RedSea volume    : not mounted\n");
        }
#ifdef YESOS_WITH_VAULT
        kprintf("  Vault            : %s\n", !vault_is_initialized() ? "not initialized" :
                (vault_is_unlocked() ? "unlocked" : "locked"));
#endif
        kprintf("  Uptime           : %u s\n\n", (U32)(timer_get_uptime_ms() / 1000));
    } else if (StrCmp(cmd, "reboot") == 0 || StrCmp(cmd, "restart") == 0) {
        sys_reboot();
    } else if (StrCmp(cmd, "poweroff") == 0 || StrCmp(cmd, "shutdown") == 0 || StrCmp(cmd, "halt") == 0 || StrCmp(cmd, "off") == 0) {
        sys_poweroff();
    } else if (is_prefix("I64 ", cmd) || is_prefix("U64 ", cmd) || is_prefix("I32 ", cmd) ||
               is_prefix("U32 ", cmd) || is_prefix("U0 ", cmd) || is_prefix("EML64 ", cmd) ||
               is_prefix("char ", cmd) || is_prefix("for", cmd) || is_prefix("while", cmd) ||
               is_prefix("kprintf(", cmd) || is_prefix("print(", cmd) || (has_char(cmd, '(') && has_char(cmd, ')'))) {
        // Direct TempleOS C/HolyQ interpretation
        holyq_jit_compile_and_run(cmd);
        speaker_event(BEEP_SUCCESS);
    } else {
        speaker_event(BEEP_ERROR);
        kprintf("Unknown command: '%s'. Type 'help' for the list of commands.\n", cmd);
    }
}


static Bool input_is_masked(U0) {
    return shell_secret_prompt_active() || security_pin_is_locked();
}

static U0 process_char(char c) {
    if (c == '\r' || c == '\n') {
        kprintf("\n");
        g_cmd_line[g_cmd_idx] = '\0';
        Bool was_secret = input_is_masked();
        shell_execute_command(g_cmd_line);
        if (was_secret) yc_wipe((U8*)g_cmd_line, sizeof(g_cmd_line));
        g_cmd_idx = 0;
        g_cmd_line[0] = '\0';
        if (!shell_secret_prompt_active()) print_prompt();
    } else if (c == '\b' || c == 127) {
        if (g_cmd_idx > 0) {
            // Remove one whole character: UTF-8 continuation bytes, then its lead byte.
            while (g_cmd_idx > 0 && ((U8)g_cmd_line[g_cmd_idx - 1] & 0xC0) == 0x80) g_cmd_idx--;
            if (g_cmd_idx > 0) g_cmd_idx--;
            g_cmd_line[g_cmd_idx] = '\0';
            kputc('\b');
            kputc(' ');
            kputc('\b');
        }
    } else if ((c >= 32 && c <= 126) || (U8)c >= 0x80) {
        // Printable ASCII and UTF-8 bytes (accented letters, n with tilde...).
        // A multi-byte character is kept only if it fits whole.
        U8 b = (U8)c;
        U32 need = b < 0x80 ? 1 : b >= 0xF0 ? 4 : b >= 0xE0 ? 3 : b >= 0xC0 ? 2 : 1;
        Bool cont = (b & 0xC0) == 0x80;
        if (cont ? g_cmd_idx < CMD_BUFFER_SIZE - 1 : g_cmd_idx + need < CMD_BUFFER_SIZE) {
            g_cmd_line[g_cmd_idx++] = c;
            g_cmd_line[g_cmd_idx] = '\0';
            if (!input_is_masked()) kputc(c);
            else if (!cont) kputc('*');               // one '*' per character
        }
    }
}

U0 shell_update(U0) {
    while (serial_has_char()) {
        char c = serial_getc();
        process_char(c);
    }
}

U0 shell_process_char(char c) {
    process_char(c);
}
