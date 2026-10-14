#ifndef AIRGAP_FIREWALL_H
#define AIRGAP_FIREWALL_H

#include "types.h"

// ============================================================================
// YesOS 2.0 - AirGap Firewall & NetShield (RFC 1918 Private LAN Perimeter)
// Target: Bare-Metal RISC-V M-Mode
// Purpose: Strict LAN Air-Gap. Zero WAN/Internet Leakage.
// ============================================================================

typedef struct {
    Bool   enabled;              // TRUE = AirGap firewall active (enforced by default)
    Bool   strict_rfc1918;       // TRUE = Allow strictly RFC 1918 & Local IP space
    U64    wan_rx_blocked;       // Ingress packets from WAN dropped at wire-level
    U64    wan_tx_blocked;       // Egress packets attempted to WAN blocked
    U64    lan_packets_accepted; // Valid LAN packets accepted into the private network
    U32    last_blocked_wan_ip;  // Last attempted foreign WAN IP
    char   firewall_name[32];    // "YesOS Air-Gap Firewall"
    char   policy_motto[64];     // "High-Assurance Air-Gapped Appliance - Zero WAN Exposure"
} AirGapFirewallState;

// Subsystem Lifecycle
U0   firewall_init(U0);
AirGapFirewallState* firewall_get_state(U0);

// Core Air-Gap Verification
Bool firewall_is_lan_ip(U32 ip);
Bool firewall_filter_incoming(U32 src_ip);
Bool firewall_filter_outgoing(U32 dst_ip);

// Telemetry, Audit & Shell
U0   firewall_print_status(U0);
U0   firewall_audit(U0);

#endif // AIRGAP_FIREWALL_H
