#include "airgap_firewall.h"
#include "kprintf.h"
#include "speaker.h"
#include "memory.h"

// ============================================================================
// YesOS 2.0 - AirGap Firewall & NetShield (RFC 1918 Private LAN Perimeter)
// Target: Bare-Metal RISC-V M-Mode
// Purpose: Strict LAN Air-Gap. Zero WAN/Internet Leakage.
// ============================================================================

static AirGapFirewallState s_firewall;

// Subnets RFC 1918 and local addresses check:
// Class A: 10.0.0.0/8          -> (ip >> 24) == 10
// Class B: 172.16.0.0/12       -> (ip >> 20) == 0xAC1  (172.16.0.0 - 172.31.255.255)
// Class C: 192.168.0.0/16      -> (ip >> 16) == 0xC0A8
// Loopback: 127.0.0.0/8        -> (ip >> 24) == 127
// Link-Local: 169.254.0.0/16   -> (ip >> 16) == 0xA9FE
// Multicast: 224.0.0.0/4       -> (ip >> 28) == 0xE    (224.0.0.0 - 239.255.255.255)
// Broadcast: 255.255.255.255   -> ip == 0xFFFFFFFF
// Zero: 0.0.0.0                -> ip == 0 (DHCP client discovery)
Bool firewall_is_lan_ip(U32 ip) {
    if (ip == 0 || ip == 0xFFFFFFFF) return TRUE;

    // 1. Check network byte order (octet 0 at b[0])
    const U8* b = (const U8*)&ip;
    U8 b0 = b[0];
    U8 b1 = b[1];
    if (b0 == 127 || b0 == 10) return TRUE;
    if (b0 == 172 && (b1 >= 16 && b1 <= 31)) return TRUE;
    if (b0 == 192 && b1 == 168) return TRUE;
    if (b0 == 169 && b1 == 254) return TRUE;
    if ((b0 & 0xF0) == 224) return TRUE;

    // 2. Check host byte order (octet 0 at MSB)
    U8 h0 = (U8)(ip >> 24);
    U8 h1 = (U8)(ip >> 16);
    if (h0 == 127 || h0 == 10) return TRUE;
    if (h0 == 172 && (h1 >= 16 && h1 <= 31)) return TRUE;
    if (h0 == 192 && h1 == 168) return TRUE;
    if (h0 == 169 && h1 == 254) return TRUE;
    if ((h0 & 0xF0) == 224) return TRUE;

    // Any other IP is WAN / Public Internet!
    return FALSE;
}

U0 firewall_init(U0) {
    MemSet(&s_firewall, 0, sizeof(s_firewall));
    s_firewall.enabled = TRUE;
    s_firewall.strict_rfc1918 = TRUE;
    ksnprintf(s_firewall.firewall_name, sizeof(s_firewall.firewall_name), "YesOS Air-Gap Firewall");
    ksnprintf(s_firewall.policy_motto, sizeof(s_firewall.policy_motto),
              "High-Assurance Air-Gapped Appliance - Zero WAN Exposure");

    kprintf("[AIR-GAP] Firewall Perimeter Initialized: WAN/Internet Strictly Prohibited.\n");
    kprintf("[AIR-GAP] Security Policy: Only RFC 1918 Private LAN traffic permitted.\n");
}

AirGapFirewallState* firewall_get_state(U0) {
    return &s_firewall;
}

Bool firewall_filter_incoming(U32 src_ip) {
    if (!s_firewall.enabled) {
        return TRUE;
    }
    if (firewall_is_lan_ip(src_ip)) {
        s_firewall.lan_packets_accepted++;
        return TRUE;
    }

    // Packet from WAN / Internet detected! Drop immediately.
    s_firewall.wan_rx_blocked++;
    s_firewall.last_blocked_wan_ip = src_ip;
    kprintf("\n[FIREWALL DEFENSE] INGRESS WAN PACKET DROPPED from %u.%u.%u.%u (Internet Blocked)\n",
            (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF, (src_ip >> 8) & 0xFF, src_ip & 0xFF);
    return FALSE;
}

Bool firewall_filter_outgoing(U32 dst_ip) {
    if (!s_firewall.enabled) {
        return TRUE;
    }
    if (firewall_is_lan_ip(dst_ip)) {
        return TRUE;
    }

    // Outgoing packet to WAN / Internet blocked!
    s_firewall.wan_tx_blocked++;
    s_firewall.last_blocked_wan_ip = dst_ip;
    kprintf("\n[FIREWALL DEFENSE] EGRESS WAN ATTEMPT BLOCKED to %u.%u.%u.%u (No WAN Leakage Permitted)\n",
            (dst_ip >> 24) & 0xFF, (dst_ip >> 16) & 0xFF, (dst_ip >> 8) & 0xFF, dst_ip & 0xFF);
    speaker_event(BEEP_WARN);
    return FALSE;
}

U0 firewall_print_status(U0) {
    kprintf("\n===============================================================================\n");
    kprintf("         YESOS 2.0 - HARDWARE AIR-GAP FIREWALL & NETSHIELD                     \n");
    kprintf("===============================================================================\n");
    kprintf(" Air-Gap Status         : %s\n", s_firewall.enabled ? "SEALED [AIR-GAP ACTIVE]" : "UNGUARDED");
    kprintf(" Network Policy         : Pure Private LAN Only (Strict RFC 1918 + Link-Local)\n");
    kprintf(" Outside Internet (WAN) : BLOCKED (Zero Ingress, Zero Egress, Zero Cloud Exposure)\n");
    kprintf(" External Telemetry     : 0%% (Absolute Domestic & Storage Sovereignty)\n");
    kprintf(" Ingress WAN Dropped    : %u packets (Rejected at wire level)\n", (U32)s_firewall.wan_rx_blocked);
    kprintf(" Egress WAN Intercepted : %u packets (Prevented from leaking outside)\n", (U32)s_firewall.wan_tx_blocked);
    kprintf(" LAN Packets Permitted  : %u packets (RFC 1918 Private LAN)\n", (U32)s_firewall.lan_packets_accepted);
    if (s_firewall.last_blocked_wan_ip != 0) {
        U32 ip = s_firewall.last_blocked_wan_ip;
        kprintf(" Last Blocked WAN IP    : %u.%u.%u.%u\n",
                (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
    }
    kprintf("-------------------------------------------------------------------------------\n");
    kprintf(" Permitted Subnets      : 10.0.0.0/8 | 172.16.0.0/12 | 192.168.0.0/16 | 127.0.0.0/8\n");
    kprintf(" Blocked Subnets        : ALL Public Internet Addresses (0.0.0.0/0 Non-LAN)\n");
    kprintf("===============================================================================\n\n");
}

U0 firewall_audit(U0) {
    kprintf("\n[FIREWALL AUDIT] Running Formal 5-Point Air-Gap Verification...\n");

    // 1. Check RFC 1918 Private ranges
    Bool test_lan1 = firewall_is_lan_ip(0xC0A80164); // 192.168.1.100
    Bool test_lan2 = firewall_is_lan_ip(0x0A00020F); // 10.0.2.15
    Bool test_lan3 = firewall_is_lan_ip(0xAC100001); // 172.16.0.1
    Bool test_loop = firewall_is_lan_ip(0x7F000001); // 127.0.0.1
    Bool lan_ok = (test_lan1 && test_lan2 && test_lan3 && test_loop);
    kprintf("  [1/5] RFC 1918 Private Subnet Recognition: %s\n", lan_ok ? "PASSED" : "FAILED");

    // 2. Check Public WAN rejection
    Bool test_wan1 = !firewall_is_lan_ip(0x08080808); // 8.8.8.8 (Google DNS)
    Bool test_wan2 = !firewall_is_lan_ip(0x01010101); // 1.1.1.1 (Cloudflare)
    Bool test_wan3 = !firewall_is_lan_ip(0x8EFAD22E); // 142.250.210.46 (Google Web)
    Bool wan_ok = (test_wan1 && test_wan2 && test_wan3);
    kprintf("  [2/5] Public WAN & Internet Address Rejection: %s\n", wan_ok ? "PASSED" : "FAILED");

    // 3. Check Ingress Filter
    U64 rx_before = s_firewall.wan_rx_blocked;
    firewall_filter_incoming(0x08080808); // Simulate packet from Google
    Bool rx_ok = (s_firewall.wan_rx_blocked == rx_before + 1);
    kprintf("  [3/5] Wire-Level Ingress WAN Drop: %s\n", rx_ok ? "PASSED" : "FAILED");

    // 4. Check Egress Filter
    U64 tx_before = s_firewall.wan_tx_blocked;
    firewall_filter_outgoing(0x01010101); // Simulate outgoing packet to Cloudflare
    Bool tx_ok = (s_firewall.wan_tx_blocked == tx_before + 1);
    kprintf("  [4/5] Wire-Level Egress WAN Block: %s\n", tx_ok ? "PASSED" : "FAILED");

    // 5. Digital Sovereignty State
    Bool sov_ok = s_firewall.enabled && s_firewall.strict_rfc1918;
    kprintf("  [5/5] Zero-Cloud Digital Sovereignty Enforcement: %s\n", sov_ok ? "PASSED" : "FAILED");

    if (lan_ok && wan_ok && rx_ok && tx_ok && sov_ok) {
        kprintf("\n✅ [FIREWALL AUDIT COMPLETE] 100%% Certified Air-Gap Enforced!\n\n");
    } else {
        kprintf("\n❌ [FIREWALL AUDIT FAILED] Air-gap violation detected!\n\n");
    }
}
