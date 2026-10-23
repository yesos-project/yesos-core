#include "rust_security.h"
#include "types.h"
#include "ports.h"
#include "kprintf.h"
#include "memory.h"
#include "trap.h"
#include "timer.h"
#include "task.h"
#include "shell.h"
#include "ramfs.h"
#include "holyq_jit.h"
#include "ata.h"
#include "redsea_eml.h"
#include "vfs.h"
#include "pmp.h"
#include "cell.h"
#include "keyhart.h"
#include "integrity.h"
#include "smp.h"
#include "virtio_net.h"
#include "app_registry.h"
#include "airgap_firewall.h"
#include "security_pin.h"
#include "yesos_crypto.h"
#include "vault.h"
#include "netcfg.h"
#include "product.h"
#ifdef YESOS_WITH_MATH
#include "yesmath.h"
U0 ym_shell_register(U0);    // math/ym_shell.c
#endif

// YesOS core boot: serial console, memory, locked PMP, harts, storage,
// network drivers, file systems, entropy and vault; the product (NAS,
// Security, Desktop) adds its services through include/product.h.
U0 KernelMain(U0) {
    // 1. Serial console
    serial_init();
    kprintf("\n[BOOT] Entering %s (RISC-V RV64GC, M-mode)...\n", PRODUCT_NAME);

    // 2. Memory manager and heap
    mem_init(512 * 1024 * 1024);

    // 3. Trap vector and CLINT
    trap_init();

    // 4. Locked PMP (Z3-proven layout), cell and key-hart layouts
    pmp_init();
    cell_prepare_layouts();
    keyhart_prepare_layout();

    // 5. Secondary harts: key hart (2) and PMP cells (3+)
    smp_init();
    cell_verify_booted();
    keyhart_verify_booted();

    // 6. Timer (1000 Hz)
    timer_init();

    // 7. Block storage and network
    ata_init();
    virtio_net_init();
    product_early_init();

    // 8. Multitasking
    task_init();

    // 9. File systems: RamFS, persistent RedSea volume, VFS
    ramfs_init();
    redsea_eml_init();
    vfs_init();

    // 10. Seed the kernel DRBG (needs the volume for SYS/RNG.SEED) and load
    //     the encrypted vault header. Must precede anything that creates
    //     salts or keys (NAS accounts, console PIN, vault).
    entropy_init();
#ifdef YESOS_WITH_VAULT
    vault_init();
    vault_shell_register();
#endif
    integrity_arm();

    // 11. Packages, LAN firewall of the stack, static address, product services, console PIN
#ifdef YESOS_WITH_MATH
    ym_init();                  // vector versions if this hart has V (mstatus.VS is on since boot)
    ym_shell_register();
#endif
#ifdef YESOS_WITH_PACKAGES
    app_registry_init();
    app_registry_register_shell();
#endif
    firewall_init();
    netcfg_load();
    product_init();
    security_pin_init();

    // 12. HolyQ JIT
    yscript_jit_init();

    ATADriveInfo* d0 = ata_get_drive_info(0);
    MemStats ms = mem_get_stats();
    U64 vlenb = 0;
    __asm__ __volatile__("csrr %0, vlenb" : "=r"(vlenb));

    kprintf("\n===============================================================================\n");
    kprintf("   %s - BOOT SUMMARY\n", PRODUCT_NAME);
    kprintf("===============================================================================\n");
    kprintf(" [ OK ] CPU              : RISC-V RV64GC + Zba/Zbb/Zbc/Zbs + RVV 1.0 (VLEN %u)\n", (U32)(vlenb * 8));
    kprintf(" [ OK ] HARTS            : %u online (kernel, key hart, PMP cells)\n", smp_get_online_harts());
    kprintf(" [ OK ] HARDWARE PMP     : Locked in M-Mode on %u hart(s), %s\n", pmp_locked_hart_count(),
            pmp_get_state() == PMP_STATE_LOCKED_PROVEN ? "Z3-proven layout" : "boot-verified layout");
    kprintf(" [ OK ] MEMORY           : %u MB RAM\n", (U32)(ms.total_ram / (1024 * 1024)));
    product_boot_summary();
    kprintf(" [ OK ] LAN FIREWALL     : RFC 1918 private networks only\n");
    if (d0->is_present) {
        kprintf(" [ OK ] STORAGE          : %s (%u MB | RedSea)\n",
                d0->model, (U32)(d0->capacity_bytes / (1024 * 1024)));
    } else {
        kprintf(" [WARN] STORAGE          : no block device (RamFS only, nothing persists)\n");
    }
    if (virtio_net_is_present()) {
        char mac_str[24], ip_str[20];
        VirtIONetInfo* ni = virtio_net_get_info();
        net_format_mac(ni->mac, mac_str, sizeof(mac_str));
        net_format_ip(ni->ip, ip_str, sizeof(ip_str));
        kprintf(" [ OK ] VIRTIO-NET       : MAC %s | IPv4 %s\n", mac_str, ip_str);
    }
    kprintf(" [ OK ] HOLYQ JIT        : %u symbols\n", yscript_jit_get_context()->symbol_count);
    kprintf("===============================================================================\n");

    // 13. Allocator hardening self-test
    demo_kernel_hardening_suite();

    // 14. Admin shell on the serial console
    shell_init();

    while (1) {
        // Network rings
        virtio_net_poll();

        // Integrity alarms raised by the key hart
        integrity_poll();

        // Asynchronous cell apps (RPCs, frames, completion)
        cell_poll();

        // Product services (TCP timers, snapshots, DNS, ...)
        product_poll();

        // Serial console input
        shell_update();

        TaskYield();
        hlt();
    }
}
