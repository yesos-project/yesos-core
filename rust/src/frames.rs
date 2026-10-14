//! YesOS core - Ethernet frame parser shared by the bridge firewall and the
//! DNS interceptor: Ethernet, up to two VLAN tags, PPPoE session, IPv4 / IPv6
//! (with extension headers), TCP / UDP ports. Every length is checked.

#[derive(Clone, Copy, PartialEq)]
pub enum Addr {
    V4(u32),
    V6([u8; 16]),
}

// ---------------------------------------------------------------------------
// Frame parsing
// ---------------------------------------------------------------------------

pub struct L2 {
    pub l3: usize,              // offset of the IP header
    pub v6: bool,
    pub pppoe_len: Option<usize>, // offset of the PPPoE length field
}

pub enum Parsed {
    NotIp,
    Bad,
    Ip { l2: L2, tcp: bool, src: Addr, dst: Addr, sport: u16, dport: u16, l4: usize, ports: bool, udp_len: usize },
    OtherProto,
}

fn be16(p: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([p[o], p[o + 1]])
}

pub fn parse(f: &[u8]) -> Parsed {
    if f.len() < 14 {
        return Parsed::Bad;
    }
    let mut o = 12;
    let mut et = be16(f, o);
    o += 2;
    for _ in 0..2 {
        if et == 0x8100 || et == 0x88A8 {
            if f.len() < o + 4 {
                return Parsed::Bad;
            }
            et = be16(f, o + 2);
            o += 4;
        }
    }
    let mut pppoe_len = None;
    if et == 0x8864 {
        // PPPoE session: ver/type, code, session, length, then the PPP protocol
        if f.len() < o + 8 || f[o] != 0x11 || f[o + 1] != 0 {
            return Parsed::Bad;
        }
        let plen = be16(f, o + 4) as usize;
        if plen < 2 || o + 6 + plen > f.len() {
            return Parsed::Bad;
        }
        pppoe_len = Some(o + 4);
        et = match be16(f, o + 6) {
            0x0021 => 0x0800,
            0x0057 => 0x86DD,
            _ => return Parsed::NotIp, // LCP, IPCP, ... pass
        };
        o += 8;
    }
    match et {
        0x0800 => parse_v4(f, o, pppoe_len),
        0x86DD => parse_v6(f, o, pppoe_len),
        _ => Parsed::NotIp,
    }
}

fn parse_v4(f: &[u8], o: usize, pppoe_len: Option<usize>) -> Parsed {
    if f.len() < o + 20 || f[o] >> 4 != 4 {
        return Parsed::Bad;
    }
    let ihl = (f[o] & 15) as usize * 4;
    let total = be16(f, o + 2) as usize;
    if ihl < 20 || total < ihl || f.len() < o + total {
        return Parsed::Bad;
    }
    let proto = f[o + 9];
    let frag_off = be16(f, o + 6) & 0x1FFF;
    let src = Addr::V4(u32::from_be_bytes([f[o + 12], f[o + 13], f[o + 14], f[o + 15]]));
    let dst = Addr::V4(u32::from_be_bytes([f[o + 16], f[o + 17], f[o + 18], f[o + 19]]));
    l4(f, o, o + ihl, o + total, proto, frag_off != 0, false, pppoe_len, src, dst)
}

fn parse_v6(f: &[u8], o: usize, pppoe_len: Option<usize>) -> Parsed {
    if f.len() < o + 40 || f[o] >> 4 != 6 {
        return Parsed::Bad;
    }
    let plen = be16(f, o + 4) as usize;
    let end = o + 40 + plen;
    if f.len() < end {
        return Parsed::Bad;
    }
    let mut a = [0u8; 16];
    a.copy_from_slice(&f[o + 8..o + 24]);
    let src = Addr::V6(a);
    a.copy_from_slice(&f[o + 24..o + 40]);
    let dst = Addr::V6(a);
    let mut nh = f[o + 6];
    let mut p = o + 40;
    let mut later_fragment = false;
    for _ in 0..8 {
        match nh {
            0 | 43 | 60 => {
                if end < p + 8 {
                    return Parsed::Bad;
                }
                nh = f[p];
                p += 8 + f[p + 1] as usize * 8;
            }
            44 => {
                if end < p + 8 {
                    return Parsed::Bad;
                }
                nh = f[p];
                later_fragment = be16(f, p + 2) & 0xFFF8 != 0;
                p += 8;
            }
            51 => {
                if end < p + 8 {
                    return Parsed::Bad;
                }
                nh = f[p];
                p += (f[p + 1] as usize + 2) * 4;
            }
            _ => break,
        }
        if p > end {
            return Parsed::Bad;
        }
    }
    l4(f, o, p, end, nh, later_fragment, true, pppoe_len, src, dst)
}

#[allow(clippy::too_many_arguments)]
fn l4(f: &[u8], l3: usize, p: usize, end: usize, proto: u8, later_fragment: bool, v6: bool,
      pppoe_len: Option<usize>, src: Addr, dst: Addr) -> Parsed {
    let l2 = L2 { l3, v6, pppoe_len };
    if proto != 6 && proto != 17 {
        return Parsed::OtherProto;
    }
    if later_fragment {
        // no ports in later fragments: the first fragment carried them
        return Parsed::Ip { l2, tcp: proto == 6, src, dst, sport: 0, dport: 0, l4: p, ports: false, udp_len: 0 };
    }
    if end < p + 4 || (proto == 17 && end < p + 8) {
        return Parsed::Bad;
    }
    let udp_len = if proto == 17 { be16(f, p + 4) as usize } else { 0 };
    Parsed::Ip { l2, tcp: proto == 6, src, dst, sport: be16(f, p), dport: be16(f, p + 2), l4: p, ports: true, udp_len }
}

