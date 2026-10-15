//! ==============================================================================
//! YesOS core - Rust part of the core (`yesos_core`, linked into every product)
//! Target: riscv64gc-unknown-none-elf (#![no_std])
//! Ring -3 Hardware Filter and Anti-Ransomware Entropy Guard
//! ==============================================================================

#![no_std]

extern crate alloc;

use core::alloc::{GlobalAlloc, Layout};
use core::panic::PanicInfo;
use core::slice;

// -----------------------------------------------------------------------------
// Heap: Rust allocations are served by the kernel allocator (Malloc/Free).
// Each block is over-allocated so it can be aligned to any power of two; the
// original pointer is stored in the word just below the aligned address.
// -----------------------------------------------------------------------------

extern "C" {
    fn Malloc(size: usize) -> *mut u8;
    fn Free(ptr: *mut u8);
}

struct KernelAllocator;

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align = layout.align().max(core::mem::size_of::<usize>());
        let total = match layout.size().checked_add(align + core::mem::size_of::<usize>()) {
            Some(t) => t,
            None => return core::ptr::null_mut(),
        };
        let raw = Malloc(total);
        if raw.is_null() {
            return raw;
        }
        let start = raw as usize + core::mem::size_of::<usize>();
        let aligned = (start + align - 1) & !(align - 1);
        *((aligned - core::mem::size_of::<usize>()) as *mut usize) = raw as usize;
        aligned as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        if ptr.is_null() {
            return;
        }
        let raw = *((ptr as usize - core::mem::size_of::<usize>()) as *const usize);
        Free(raw as *mut u8);
    }
}

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

pub mod crypto;
#[cfg(any(feature = "dns", feature = "frames"))]
pub mod frames;
#[cfg(feature = "dns")]
pub mod dns;

// -----------------------------------------------------------------------------
// Constants for Ring -3 Management Traffic & Protocol Signatures
// -----------------------------------------------------------------------------

pub const ETH_TYPE_IPV4: u16 = 0x0800;
pub const ETH_TYPE_NCSI: u16 = 0x88F8;

pub const IP_PROTO_TCP: u8 = 6;
pub const IP_PROTO_UDP: u8 = 17;

// Intel AMT Out-of-Band Ports
pub const PORT_INTEL_AMT_HTTP: u16 = 16992;
pub const PORT_INTEL_AMT_HTTPS: u16 = 16993;
pub const PORT_INTEL_AMT_SOL: u16 = 16994;
pub const PORT_INTEL_AMT_SOL_S: u16 = 16995;
pub const PORT_INTEL_AMT_ZTP: u16 = 9971;

// AMD DASH / ASF / RMCP Ports
pub const PORT_AMD_DASH_ASF: u16 = 623;
pub const PORT_AMD_DASH_ASF_S: u16 = 664;
pub const PORT_AMD_DASH_WSMAN_HTTP: u16 = 5985;
pub const PORT_AMD_DASH_WSMAN_HTTPS: u16 = 5986;

// RMCP Protocol Identifiers
pub const RMCP_VERSION_1_0: u8 = 0x06;
pub const RMCP_CLASS_ASF: u8 = 0x06;

// Anti-Ransomware Shannon Entropy Threshold in fixed-point (7.85 * 1000 = 7850)
pub const AI_RANSOMWARE_ENTROPY_THRESH_FP: u32 = 7850;

// -----------------------------------------------------------------------------
// Hardware-Level Ring -3 Wire Filter
// -----------------------------------------------------------------------------

/// Inspects raw link-layer Ethernet frames before delivering them to the network stack.
/// Silences and drops out-of-band surveillance traffic from Intel ME and AMD PSP.
///
/// Returns:
///   1 -> Packet is clean (permitted)
///   0 -> Packet is a Ring -3 surveillance / out-of-band threat (DROPPED)
#[no_mangle]
pub extern "C" fn rust_filter_packet(buf: *const u8, len: usize) -> i32 {
    if buf.is_null() || len < 14 {
        return 1; // Not enough data for Ethernet header; permit or let C stack handle
    }

    // Safety: Caller must guarantee `buf` points to valid memory of at least `len` bytes
    let frame = unsafe { slice::from_raw_parts(buf, len) };

    // 1. Hardware NC-SI (Network Controller Sideband Interface) EtherType 0x88F8
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype == ETH_TYPE_NCSI {
        return 0; // Trapped: Direct NC-SI sideband frame dropped
    }

    // Pass non-IPv4 (e.g. ARP 0x0806 is safe)
    if ethertype != ETH_TYPE_IPV4 {
        return 1;
    }

    if len < 34 {
        return 1; // Minimum IPv4 packet length (14 Eth + 20 IP)
    }

    let ip_hdr = &frame[14..];
    let version_ihl = ip_hdr[0];
    let ihl = ((version_ihl & 0x0F) as usize) * 4;
    if ihl < 20 || len < 14 + ihl {
        return 1;
    }

    let protocol = ip_hdr[9];
    let l4_offset = 14 + ihl;
    let l4_len = len - l4_offset;

    // 2. UDP Inspection: RMCP / ASF Beacons & Intel AMT ZTP / Out-of-band
    if protocol == IP_PROTO_UDP {
        if l4_len < 8 {
            return 1;
        }
        let udp = &frame[l4_offset..];
        let src_port = u16::from_be_bytes([udp[0], udp[1]]);
        let dst_port = u16::from_be_bytes([udp[2], udp[3]]);

        // Check AMD DASH / RMCP ASF (UDP 623 / 664)
        if src_port == PORT_AMD_DASH_ASF || dst_port == PORT_AMD_DASH_ASF
            || src_port == PORT_AMD_DASH_ASF_S || dst_port == PORT_AMD_DASH_ASF_S
        {
            // Deep check RMCP header if available
            if l4_len >= 8 + 8 {
                let rmcp = &udp[8..];
                if rmcp[0] == RMCP_VERSION_1_0 && rmcp[3] == RMCP_CLASS_ASF {
                    return 0; // Trapped: AMD/Intel RMCP-ASF beacon dropped
                }
            }
            return 0; // Trapped: AMD DASH UDP packet dropped
        }

        // Check Intel AMT Zero-Touch Provisioning (UDP 9971)
        if src_port == PORT_INTEL_AMT_ZTP || dst_port == PORT_INTEL_AMT_ZTP {
            return 0; // Trapped: Intel AMT ZTP dropped
        }

        // Check Intel AMT UDP Out-of-band ranges (16992 - 16995)
        if (src_port >= PORT_INTEL_AMT_HTTP && src_port <= PORT_INTEL_AMT_SOL_S)
            || (dst_port >= PORT_INTEL_AMT_HTTP && dst_port <= PORT_INTEL_AMT_SOL_S)
        {
            return 0; // Trapped: Intel AMT UDP traffic dropped
        }
    }

    // 3. TCP Inspection: Intel ME Web/SoL & AMD DASH WS-Management
    if protocol == IP_PROTO_TCP {
        if l4_len < 20 {
            return 1;
        }
        let tcp = &frame[l4_offset..];
        let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
        let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);

        // Intel AMT Web UI (16992, 16993) and SoL/IDE-R (16994, 16995)
        if (src_port >= PORT_INTEL_AMT_HTTP && src_port <= PORT_INTEL_AMT_SOL_S)
            || (dst_port >= PORT_INTEL_AMT_HTTP && dst_port <= PORT_INTEL_AMT_SOL_S)
        {
            return 0; // Trapped: Intel AMT TCP session dropped
        }

        // Intel AMT ZTP over TCP (9971)
        if src_port == PORT_INTEL_AMT_ZTP || dst_port == PORT_INTEL_AMT_ZTP {
            return 0; // Trapped: Intel AMT ZTP TCP dropped
        }

        // AMD DASH WS-Management (5985, 5986)
        if src_port == PORT_AMD_DASH_WSMAN_HTTP
            || dst_port == PORT_AMD_DASH_WSMAN_HTTP
            || src_port == PORT_AMD_DASH_WSMAN_HTTPS
            || dst_port == PORT_AMD_DASH_WSMAN_HTTPS
        {
            return 0; // Trapped: AMD DASH WSMAN session dropped
        }
    }

    1 // Clean packet: Permitted
}

