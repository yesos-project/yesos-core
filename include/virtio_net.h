#ifndef VIRTIO_NET_H
#define VIRTIO_NET_H

#include "types.h"

// ----------------------------------------------------------------------------
// YesOS VirtIO Modern 1.0 PCIe Network Interface & Deterministic Telemetry
// Target: RISC-V RV64 Bare-Metal M-Mode
// Supports: virtio-net-pci (Vendor 0x1AF4, Device 0x1041 or 0x1000)
// ----------------------------------------------------------------------------

#define VIRTIO_NET_PCI_VENDOR     0x1AF4
#define VIRTIO_NET_PCI_DEV_MOD    0x1041 // Modern VirtIO Network (0x1040 + 1)
#define VIRTIO_NET_PCI_DEV_LEG    0x1000 // Transitional VirtIO Network

#define VIRTIO_NET_F_MAC          (1 << 5)
#define VIRTIO_NET_F_STATUS       (1 << 16)

#define VIRTIO_NET_S_LINK_UP      1

#define ETH_ALEN                  6
#define ETH_HLEN                  14
#define ETH_MTU                   1500
#define ETH_MAX_FRAME_SIZE        1518

#define ETH_TYPE_IPV4             0x0800
#define ETH_TYPE_ARP              0x0806

#define IP_PROTO_ICMP             1
#define IP_PROTO_TCP              6
#define IP_PROTO_UDP              17

#define ICMP_TYPE_ECHO_REPLY      0
#define ICMP_TYPE_ECHO_REQUEST    8

#define ARP_OP_REQUEST            1
#define ARP_OP_REPLY              2

#define TELEM_MAGIC               0x59455354 // "YEST"

// VirtIO Network Packet Header (Modern 1.0 layout, 12 bytes)
struct virtio_net_hdr {
    uint8_t  flags;
    uint8_t  gso_type;
    uint16_t hdr_len;
    uint16_t gso_size;
    uint16_t csum_start;
    uint16_t csum_offset;
    uint16_t num_buffers;
} __attribute__((packed));

// Ethernet II Header
typedef struct {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ethertype;
} __attribute__((packed)) EthHeader;

// ARP Packet Header
typedef struct {
    uint16_t htype;
    uint16_t ptype;
    uint8_t  hlen;
    uint8_t  plen;
    uint16_t opcode;
    uint8_t  sender_mac[6];
    uint32_t sender_ip;
    uint8_t  target_mac[6];
    uint32_t target_ip;
} __attribute__((packed)) ARPHeader;

// IPv4 Header
typedef struct {
    uint8_t  version_ihl;
    uint8_t  tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} __attribute__((packed)) IPv4Header;

// ICMP Header
typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
    uint8_t  data[];
} __attribute__((packed)) ICMPHeader;

// UDP Header
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} __attribute__((packed)) UDPHeader;

// Deterministic UDP Telemetry Packet Format
typedef struct {
    uint32_t magic;             // TELEM_MAGIC
    uint32_t version;           // 1
    uint64_t clint_ticks;       // Hardware timer tick count
    uint32_t uptime_seconds;    // Seconds since boot
    uint8_t  hart_count;        // Online SMP cores
    uint8_t  rvv_enabled;       // 1 if RVV 1.0 vector unit is active
    uint16_t rvv_vlen;          // Vector length in bits (128)
    uint32_t ram_total_mb;      // Total system RAM
    uint32_t ram_used_kb;       // Kernel Heap in use
    uint32_t jit_symbol_count;  // Registered live JIT functions
    uint32_t audio_sample_rate; // Audio master sampling rate (48000 Hz)
    uint32_t audio_drops;       // DAC under-runs
    uint64_t phase_space_h;     // unused (0); kept for wire compatibility
    uint64_t rotor_norm;        // Rodrigues-Clifford rotor norm
    uint32_t worst_case_delay_ns;// D_max from Min-Plus Deconvolution (Network Calculus)
    uint32_t max_backlog_bytes; // B_max maximum backlog buffer bound
    uint32_t zero_loss_verified;// 1 = Mathematically proven 0% packet loss
    uint64_t tx_packets;        // Total transmitted packets
    uint64_t rx_packets;        // Total received packets
    char     status_msg[32];    // "YESOS_DETERMINISTIC_OK"
} __attribute__((packed)) YesOSTelemetryPacket;

// Remote Control Protocol (Host <-> YesOS over UDP 5555)
#define REMOTE_CMD_MAGIC  0x59455343 // "YESC" (YesOS Command)
#define REMOTE_RESP_MAGIC 0x59455352 // "YESR" (YesOS Response)

typedef enum {
    REMOTE_CMD_SHELL_EXEC        = 1, // Execute shell command string
    REMOTE_CMD_HOLYQ_EVAL        = 2, // Compile & evaluate HolyQ code in JIT
    REMOTE_CMD_REQUEST_TELEMETRY = 3, // Request instant telemetry packet
    REMOTE_CMD_BEEP              = 4, // Trigger system acoustic earcon
    REMOTE_CMD_REBOOT            = 5, // Trigger system reboot
    REMOTE_CMD_PKG_BEGIN         = 10, // Start incoming .YPK package transfer
    REMOTE_CMD_PKG_CHUNK         = 11, // Incoming .YPK chunk data
    REMOTE_CMD_PKG_FINISH        = 12  // Finalize and install package!
} RemoteCommandType;

typedef struct __attribute__((packed)) {
    uint32_t magic;         // REMOTE_CMD_MAGIC
    uint16_t seq;           // Sequence number
    uint16_t cmd_type;      // RemoteCommandType
    uint32_t payload_len;   // Payload length
    char     payload[256];  // Command / Code string
} YesOSRemoteCommand;

typedef struct __attribute__((packed)) {
    uint32_t magic;         // REMOTE_RESP_MAGIC
    uint16_t seq;           // Matching sequence number
    uint16_t status;        // 0 = OK, 1 = Error
    uint32_t resp_len;      // Length of response message
    char     response[256]; // Text output or ACK
} YesOSRemoteResponse;

// Network Telemetry & Statistics
typedef struct {
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t rx_arp_replies;
    uint64_t rx_icmp_replies;
    uint64_t rx_icmp_requests;
    uint64_t tx_telemetry_frames;
    uint64_t rx_drops;
    uint64_t tx_errors;
} VirtIONetStats;

// Interface Information
typedef struct {
    Bool     is_present;
    Bool     link_up;
    uint32_t pci_slot;
    uint8_t  mac[6];
    uint32_t ip;
    uint32_t netmask;
    uint32_t gateway_ip;
    uint8_t  gateway_mac[6];
    uint16_t rx_queue_size;
    uint16_t tx_queue_size;
} VirtIONetInfo;


// ----------------------------------------------------------------------------
// Service registry (products plug their services into the core network code)
// ----------------------------------------------------------------------------
typedef struct {
    U32         src_ip;     // host byte order
    const U8*   src_mac;
    U16         src_port;
    U16         dst_port;
    const U8*   data;       // UDP payload, bounded by the UDP length
    size_t      len;
    const void* frame;      // the received Ethernet frame (for replies)
} NetUdpDatagram;

// Returns TRUE when the datagram was consumed.
typedef Bool (*NetUdpHandler)(const NetUdpDatagram* d);
// Port 0: sees every datagram before the port handlers. Up to 16 handlers.
Bool net_register_udp(U16 port, NetUdpHandler fn);
Bool net_udp_reply(const NetUdpDatagram* d, const U8* data, size_t len);

typedef U0 (*NetTcpHandler)(const U8* packet, size_t len, size_t ip_hdr_len);
U0   net_register_tcp(NetTcpHandler fn);   // without one, TCP is dropped

typedef struct {
    Bool (*is_port)(U32 port);
    Bool (*owns_stack)(U0);
    U0   (*input)(U32 port, const U8* frame, size_t len);
    Bool (*output_local)(const U8* frame, size_t len);
} NetBridgeOps;
U0   net_set_bridge(const NetBridgeOps* ops);

// Telemetry datagram to the gateway, UDP 5555 (lab tools). Off unless a
// product turns the 1 s broadcast on.
U0   net_set_telemetry(Bool periodic);
Bool net_telemetry_to_port(U16 port);

// Core Driver Interface
#define NET_MAX_PORTS 3
U32  net_port_count(U0);
const U8* net_port_mac(U32 port);
VirtIONetStats* net_port_stats(U32 port);
Bool net_port_send(U32 port, const U8* frame, size_t len);   // raw, no stack filters
U0   net_stack_input(const U8* frame, size_t len);           // frame for the NAS itself
Bool virtio_net_init(U0);
Bool virtio_net_is_present(U0);
VirtIONetInfo* virtio_net_get_info(U0);
VirtIONetStats* virtio_net_get_stats(U0);

// Raw Frame Transmission & Polling
Bool virtio_net_send_raw(const void* frame, size_t len);
U0   virtio_net_poll(U0);

// Protocol Utilities & Services
U32  net_parse_ip(const char* str);
U0   net_format_ip(U32 ip, char* out, size_t max_len);
U0   net_format_mac(const uint8_t* mac, char* out, size_t max_len);
Bool net_send_arp_request(U32 target_ip);

// Outbound UDP (IPv4 addresses in host byte order). With dst_mac NULL the
// next hop is resolved: the gateway for other subnets, else the neighbour
// cache; on a cache miss an ARP request is sent and FALSE returned (retry).
Bool net_udp_send(U32 dst_ip, const U8* dst_mac, U16 src_port, U16 dst_port, const U8* data, size_t len);
U0   net_set_ipv4(U32 ip, U32 mask, U32 gw);   // host byte order
U0   net_get_ipv4(U32* ip, U32* mask, U32* gw);
Bool net_ping(const char* ip_str, U32 count);
Bool net_send_telemetry(const char* dst_ip_str, U16 port);
U0   net_print_status(U0);
U0   net_run_benchmark(U0);

#define NET_HISTORY_SAMPLES 32
U0   virtio_net_get_rates(U32* rx_bps, U32* tx_bps, U32* rx_pps, U32* tx_pps);
U0   virtio_net_get_history(const U32** out_rx, const U32** out_tx, U32* out_count);

#endif // VIRTIO_NET_H

