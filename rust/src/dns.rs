//! YesOS NAS - DNS filter for the LAN (Pi-hole style), UDP port 53.
//!
//! Clients on the LAN ask the NAS; blocked names get 0.0.0.0 / :: (other
//! types: no data), everything else is forwarded to an upstream resolver on
//! the LAN (the air-gap firewall forbids the Internet) and cached.
//!
//! - A blocked domain blocks its subdomains; the allowlist always wins.
//! - Lists (hosts files, plain domains, `||domain^`) are kept as sorted keyed
//!   SipHash values: 8 bytes per domain, binary search per lookup.
//! - Every packet is untrusted: strict bounds, no compression pointers in
//!   questions, malformed queries get FORMERR or are dropped.
//! - Upstream answers are accepted only from the upstream that was asked,
//!   on the random port used for that query, with the random ID and the same
//!   question (anti-spoofing / cache poisoning).
//! - Only private (RFC 1918) clients are answered, each limited to
//!   RATE_PER_MIN queries per minute.
//! - The query log lives only in RAM (last LOG_MAX queries) and can be off.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;
use core::slice;

use crate::crypto::{rng_fill, Locked};

extern "C" {
    fn net_port_send(port: u32, frame: *const u8, len: usize) -> bool;
    fn net_udp_send(dst_ip: u32, dst_mac: *const u8, src_port: u16, dst_port: u16, data: *const u8, len: usize) -> bool;
}

const DNS_PORT: u16 = 53;
const MAX_UPSTREAMS: usize = 4;
const MAX_LISTS: usize = 8;
const MAX_CUSTOM: usize = 1024;
const MAX_PENDING: usize = 256;
const CACHE_MAX: usize = 4096;
const LOG_MAX: usize = 1000;
const LOG_JSON: usize = 200;
const RATE_PER_MIN: u32 = 1000;
/// Intercepted queries all come from the router (the whole house behind NAT).
const RATE_PER_MIN_BRIDGE: u32 = 20_000;
const RATE_CLIENTS: usize = 256;
const BLOCKED_TTL: u32 = 2;
const MAX_TTL: u32 = 86_400;
const NEG_TTL_MAX: u32 = 3_600;
const UPSTREAM_TIMEOUT_MS: u64 = 1_500;
const ARP_RETRY_MS: u64 = 250;
const MAX_TRIES: u8 = 3;
const EDNS_MAX: u16 = 1232;
const CANARY: &[u8] = b"use-application-dns.net";

/// Well-known DNS-over-HTTPS / DoT resolvers (optional "doh" setting): a
/// device using them would bypass the filter.
const DOH_PROVIDERS: &[&str] = &[
    "dns.google", "dns.google.com", "8888.google", "cloudflare-dns.com", "one.one.one.one",
    "1dot1dot1dot1.cloudflare-dns.com", "dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net",
    "dns11.quad9.net", "doh.opendns.com", "dns.opendns.com", "doh.cleanbrowsing.org",
    "dns.adguard.com", "dns.adguard-dns.com", "dns.nextdns.io", "doh.mullvad.net", "dns.mullvad.net",
    "doh.dns.sb", "dns.sb", "doh.libredns.gr", "dns.controld.com", "freedns.controld.com",
    "doh.xfinity.com", "dns.alidns.com", "doh.pub", "dns.twnic.tw", "doh.ffmuc.net",
];

// Log/verdict sources
const SRC_CUSTOM: u8 = 200;
const SRC_DOH: u8 = 201;
const SRC_CANARY: u8 = 202;
const SRC_NONE: u8 = 255;

#[derive(Clone, Copy, PartialEq)]
enum Outcome {
    Blocked,
    Cached,
    Forwarded,
    Failed,
}

struct List {
    name: String,
    enabled: bool,
    hashes: Vec<u64>,
    loaded: bool,
}

/// Where the answer goes: straight back to a client of the NAS, or (bridge
/// interception) out of the bridge port it came from, spoofing the server the
/// client actually asked, inside the same Ethernet/VLAN/PPPoE framing.
#[derive(Clone)]
#[cfg_attr(not(feature = "intercept"), allow(dead_code))]
enum ReplyTo {
    Direct { ip: u32, mac: [u8; 6], port: u16 },
    Bridge { port: u32, l2: Vec<u8>, pppoe_len: Option<usize>, server: u32, client: u32, client_port: u16 },
}

struct Pending {
    qid: u16,
    port: u16,
    up: usize,
    client_ip: u32,
    to: ReplyTo,
    client_id: u16,
    name: Vec<u8>,
    qtype: u16,
    qclass: u16,
    query: Vec<u8>,
    sent: u64,
    sent_ok: bool,
    start: u64,
    tries: u8,
}

struct CacheEntry {
    name: Vec<u8>,
    qtype: u16,
    qclass: u16,
    resp: Vec<u8>,
    ttl_offs: Vec<u16>,
    has_opt: bool,
    expires: u64,
}

struct LogEntry {
    t: u64,
    client: u32,
    name: String,
    qtype: u16,
    outcome: Outcome,
    src: u8,
    ms: u32,
}

struct Window {
    ip: u32,
    start: u64,
    count: u32,
}

#[derive(Default)]
struct Stats {
    queries: u64,
    blocked: u64,
    cached: u64,
    forwarded: u64,
    failed: u64,
    rate_dropped: u64,
    malformed: u64,
    refused: u64,
    spoofed: u64,
}

struct Dns {
    keyed: bool,
    key: (u64, u64),
    enabled: bool,
    log_on: bool,
    doh: bool,
    upstreams: Vec<(u32, u16)>,
    /// No server chosen by the owner: follow the network's default (gateway).
    upstream_auto: bool,
    lists: Vec<List>,
    allow: Vec<String>,
    block: Vec<String>,
    allow_h: Vec<u64>,
    block_h: Vec<u64>,
    doh_h: Vec<u64>,
    pending: Vec<Pending>,
    cache: BTreeMap<u64, CacheEntry>,
    log: VecDeque<LogEntry>,
    windows: Vec<Window>,
    stats: Stats,
}

static DNS: Locked<Dns> = Locked::new(Dns {
    keyed: false,
    key: (0, 0),
    enabled: true,
    log_on: true,
    doh: false,
    upstreams: Vec::new(),
    upstream_auto: true,
    lists: Vec::new(),
    allow: Vec::new(),
    block: Vec::new(),
    allow_h: Vec::new(),
    block_h: Vec::new(),
    doh_h: Vec::new(),
    pending: Vec::new(),
    cache: BTreeMap::new(),
    log: VecDeque::new(),
    windows: Vec::new(),
    stats: Stats {
        queries: 0, blocked: 0, cached: 0, forwarded: 0, failed: 0,
        rate_dropped: 0, malformed: 0, refused: 0, spoofed: 0,
    },
});

// ---------------------------------------------------------------------------
// Helpers: hashing, names, addresses
// ---------------------------------------------------------------------------

#[allow(deprecated)]
fn sip(key: (u64, u64), data: &[u8]) -> u64 {
    use core::hash::Hasher;
    let mut h = core::hash::SipHasher::new_with_keys(key.0, key.1);
    h.write(data);
    h.finish()
}

fn random_u32() -> u32 {
    let mut b = [0u8; 4];
    if rng_fill(&mut b) != 0 {
        return 0;
    }
    u32::from_le_bytes(b)
}

fn rd16(p: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([p[o], p[o + 1]])
}

fn wr16(p: &mut [u8], o: usize, v: u16) {
    p[o..o + 2].copy_from_slice(&v.to_be_bytes());
}

fn is_private(ip: u32) -> bool {
    let a = (ip >> 24) as u8;
    let b = (ip >> 16) as u8;
    a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168)
}

fn domain_char(c: u8) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_'
}

/// Lowercase, validated domain with at least two labels, or None.
fn norm_domain(s: &[u8]) -> Option<Vec<u8>> {
    let mut s = s;
    while let Some((&c, rest)) = s.split_first() {
        if c.is_ascii_whitespace() { s = rest } else { break }
    }
    while let Some((&c, rest)) = s.split_last() {
        if c.is_ascii_whitespace() { s = rest } else { break }
    }
    if let Some(stripped) = s.strip_suffix(b".") {
        s = stripped;
    }
    if s.is_empty() || s.len() > 253 {
        return None;
    }
    let out: Vec<u8> = s.iter().map(|c| c.to_ascii_lowercase()).collect();
    let mut labels = 0;
    for label in out.split(|&c| c == b'.') {
        if label.is_empty() || label.len() > 63 || !label.iter().all(|&c| domain_char(c)) {
            return None;
        }
        labels += 1;
    }
    if labels < 2 {
        return None;
    }
    Some(out)
}

/// Hashes of `name` and of each parent domain that still has two labels
/// (ads.tracker.example.com -> itself, tracker.example.com, example.com).
fn suffix_hashes(key: (u64, u64), name: &[u8]) -> Vec<u64> {
    let mut out = Vec::new();
    let mut start = 0;
    loop {
        let rest = &name[start..];
        if !rest.contains(&b'.') {
            break;
        }
        out.push(sip(key, rest));
        match rest.iter().position(|&c| c == b'.') {
            Some(d) => start += d + 1,
            None => break,
        }
    }
    out
}

fn in_set(set: &[u64], hs: &[u64]) -> bool {
    hs.iter().any(|h| set.binary_search(h).is_ok())
}

fn sorted_hashes(key: (u64, u64), names: &[String]) -> Vec<u64> {
    let mut v: Vec<u64> = names.iter().map(|n| sip(key, n.as_bytes())).collect();
    v.sort_unstable();
    v.dedup();
    v
}

fn push_ip(out: &mut Vec<u8>, ip: u32) {
    for i in 0..4 {
        if i > 0 {
            out.push(b'.');
        }
        push_num(out, ((ip >> (24 - 8 * i)) & 0xFF) as u64);
    }
}

fn push_num(out: &mut Vec<u8>, mut n: u64) {
    let mut t = [0u8; 20];
    let mut i = t.len();
    loop {
        i -= 1;
        t[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(&t[i..]);
}

fn parse_ip(s: &[u8]) -> Option<u32> {
    let mut ip: u32 = 0;
    let mut parts = 0;
    for p in s.split(|&c| c == b'.') {
        if p.is_empty() || p.len() > 3 || !p.iter().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let v: u32 = p.iter().fold(0, |a, &c| a * 10 + (c - b'0') as u32);
        if v > 255 {
            return None;
        }
        ip = (ip << 8) | v;
        parts += 1;
    }
    if parts == 4 { Some(ip) } else { None }
}

/// "a.b.c.d" or "a.b.c.d:port".
fn parse_endpoint(s: &[u8]) -> Option<(u32, u16)> {
    let (ip_s, port) = match s.iter().position(|&c| c == b':') {
        Some(c) => {
            let p = &s[c + 1..];
            if p.is_empty() || p.len() > 5 || !p.iter().all(|c| c.is_ascii_digit()) {
                return None;
            }
            let v: u32 = p.iter().fold(0, |a, &c| a * 10 + (c - b'0') as u32);
            if v == 0 || v > 65535 {
                return None;
            }
            (&s[..c], v as u16)
        }
        None => (s, DNS_PORT),
    };
    parse_ip(ip_s).map(|ip| (ip, port))
}

fn valid_list_name(n: &[u8]) -> bool {
    !n.is_empty() && n.len() <= 32 && n.iter().all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
}

fn type_name(t: u16) -> &'static str {
    match t {
        1 => "A", 2 => "NS", 5 => "CNAME", 6 => "SOA", 12 => "PTR", 15 => "MX", 16 => "TXT",
        28 => "AAAA", 33 => "SRV", 64 => "SVCB", 65 => "HTTPS", 255 => "ANY",
        _ => "?",
    }
}

// ---------------------------------------------------------------------------
// Wire format
// ---------------------------------------------------------------------------

/// Question name (no compression allowed) as lowercase dotted text.
/// Labels with dots or non-printable bytes are rejected.
fn read_qname(p: &[u8], mut o: usize) -> Option<(Vec<u8>, usize)> {
    let mut name = Vec::new();
    loop {
        let len = *p.get(o)? as usize;
        o += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return None; // compression pointer or reserved label type
        }
        let label = p.get(o..o + len)?;
        if !label.iter().all(|&c| c > 0x20 && c < 0x7f && c != b'.') {
            return None;
        }
        if !name.is_empty() {
            name.push(b'.');
        }
        name.extend(label.iter().map(|c| c.to_ascii_lowercase()));
        if name.len() > 253 {
            return None;
        }
        o += len;
    }
    Some((name, o))
}

fn skip_name(p: &[u8], mut o: usize) -> Option<usize> {
    for _ in 0..128 {
        let len = *p.get(o)?;
        if len == 0 {
            return Some(o + 1);
        }
        if len & 0xC0 == 0xC0 {
            p.get(o + 1)?;
            return Some(o + 2);
        }
        if len & 0xC0 != 0 {
            return None;
        }
        o += 1 + len as usize;
    }
    None
}

struct RecordScan {
    ttl_offs: Vec<u16>,
    min_ttl: u32,
    neg_ttl: u32,
    has_opt: bool,
}

/// Walks the answer, authority and additional sections starting at `o`.
fn scan_records(p: &[u8], mut o: usize) -> Option<RecordScan> {
    let an = rd16(p, 6) as usize;
    let ns = rd16(p, 8) as usize;
    let ar = rd16(p, 10) as usize;
    let mut s = RecordScan { ttl_offs: Vec::new(), min_ttl: u32::MAX, neg_ttl: 0, has_opt: false };
    for i in 0..an + ns + ar {
        o = skip_name(p, o)?;
        let hdr = p.get(o..o + 10)?;
        let rtype = rd16(hdr, 0);
        let ttl = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
        let rdlen = rd16(hdr, 8) as usize;
        let rdata = o + 10;
        p.get(rdata..rdata + rdlen)?;
        if rtype == 41 {
            s.has_opt = true;
        } else {
            s.ttl_offs.push((o + 4) as u16);
            if i < an {
                s.min_ttl = s.min_ttl.min(ttl);
            } else if i < an + ns && rtype == 6 && rdlen >= 4 {
                let m = &p[rdata + rdlen - 4..rdata + rdlen];
                s.neg_ttl = ttl.min(u32::from_be_bytes([m[0], m[1], m[2], m[3]]));
            }
        }
        o = rdata + rdlen;
    }
    Some(s)
}

/// Header + question of `q` turned into a response with `rcode`.
fn reply_base(q: &[u8], qend: usize, rcode: u8) -> Vec<u8> {
    let mut r = Vec::with_capacity(qend + 40);
    r.extend_from_slice(&q[..qend]);
    r[2] = 0x80 | (q[2] & 0x79); // QR, keep opcode and RD
    r[3] = 0x80 | rcode;         // RA
    r[4..12].copy_from_slice(&[0, if qend > 12 { 1 } else { 0 }, 0, 0, 0, 0, 0, 0]);
    r
}

fn blocked_reply(q: &[u8], qend: usize, qtype: u16, nxdomain: bool) -> Vec<u8> {
    let mut r = reply_base(q, qend, if nxdomain { 3 } else { 0 });
    if nxdomain {
        return r;
    }
    let addr_len = match qtype {
        1 => 4,
        28 => 16,
        _ => return r, // no data for other types
    };
    r.extend_from_slice(&[0xC0, 0x0C]);
    r.extend_from_slice(&qtype.to_be_bytes());
    r.extend_from_slice(&[0, 1]);
    r.extend_from_slice(&BLOCKED_TTL.to_be_bytes());
    r.extend_from_slice(&(addr_len as u16).to_be_bytes());
    r.extend(core::iter::repeat(0u8).take(addr_len));
    wr16(&mut r, 6, 1);
    r
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

impl Dns {
    fn ensure_key(&mut self) {
        if self.keyed {
            return;
        }
        let mut k = [0u8; 16];
        if rng_fill(&mut k) != 0 {
            k = *b"YesOS-DNS-nokey!"; // no entropy yet: still correct, just unkeyed
        }
        self.key = (u64::from_le_bytes(k[..8].try_into().unwrap()), u64::from_le_bytes(k[8..].try_into().unwrap()));
        self.keyed = true;
        let doh: Vec<String> = DOH_PROVIDERS.iter().map(|s| String::from(*s)).collect();
        self.doh_h = sorted_hashes(self.key, &doh);
        self.allow_h = sorted_hashes(self.key, &self.allow);
        self.block_h = sorted_hashes(self.key, &self.block);
    }

    /// Why `name` is blocked (list index / SRC_*), or None. Allowlist wins.
    fn verdict(&self, name: &[u8]) -> (bool, u8) {
        let hs = suffix_hashes(self.key, name);
        if hs.is_empty() {
            return (false, SRC_NONE);
        }
        if in_set(&self.allow_h, &hs) {
            return (false, SRC_CUSTOM);
        }
        if in_set(&self.block_h, &hs) {
            return (true, SRC_CUSTOM);
        }
        for (i, l) in self.lists.iter().enumerate() {
            if l.enabled && in_set(&l.hashes, &hs) {
                return (true, i as u8);
            }
        }
        if self.doh && in_set(&self.doh_h, &hs) {
            return (true, SRC_DOH);
        }
        (false, SRC_NONE)
    }

    fn src_name(&self, src: u8) -> &str {
        match src {
            SRC_CUSTOM => "personal",
            SRC_DOH => "dns-cifrado",
            SRC_CANARY => "canario-firefox",
            i if (i as usize) < self.lists.len() => &self.lists[i as usize].name,
            _ => "",
        }
    }

    fn log_push(&mut self, t: u64, client: u32, name: &[u8], qtype: u16, outcome: Outcome, src: u8, ms: u32) {
        if !self.log_on {
            return;
        }
        if self.log.len() >= LOG_MAX {
            self.log.pop_front();
        }
        let name = String::from(core::str::from_utf8(name).unwrap_or("?"));
        self.log.push_back(LogEntry { t, client, name, qtype, outcome, src, ms });
    }

    fn rate_ok(&mut self, ip: u32, now: u64, limit: u32) -> bool {
        if let Some(w) = self.windows.iter_mut().find(|w| w.ip == ip) {
            if now.saturating_sub(w.start) >= 60_000 {
                w.start = now;
                w.count = 0;
            }
            w.count += 1;
            return w.count <= limit;
        }
        if self.windows.len() >= RATE_CLIENTS {
            let oldest = (0..self.windows.len()).min_by_key(|&i| self.windows[i].start).unwrap_or(0);
            self.windows.swap_remove(oldest);
        }
        self.windows.push(Window { ip, start: now, count: 1 });
        true
    }

    fn cache_key(&self, name: &[u8], qtype: u16, qclass: u16) -> u64 {
        let mut k = Vec::with_capacity(name.len() + 4);
        k.extend_from_slice(name);
        k.extend_from_slice(&qtype.to_be_bytes());
        k.extend_from_slice(&qclass.to_be_bytes());
        sip(self.key, &k)
    }

    fn cache_get(&self, name: &[u8], qtype: u16, qclass: u16, client_edns: bool, now: u64) -> Option<(&CacheEntry, u32)> {
        let e = self.cache.get(&self.cache_key(name, qtype, qclass))?;
        if e.name != name || e.qtype != qtype || e.qclass != qclass || e.expires <= now {
            return None;
        }
        if !client_edns && (e.has_opt || e.resp.len() > 512) {
            return None;
        }
        Some((e, ((e.expires - now + 999) / 1000) as u32))
    }

    fn cache_put(&mut self, name: Vec<u8>, qtype: u16, qclass: u16, resp: &[u8], scan: RecordScan, rcode: u8, now: u64) {
        let ttl = if rd16(resp, 6) > 0 && rcode == 0 {
            if scan.min_ttl == u32::MAX { 0 } else { scan.min_ttl.min(MAX_TTL) }
        } else if rcode == 0 || rcode == 3 {
            scan.neg_ttl.min(NEG_TTL_MAX)
        } else {
            0
        };
        if ttl == 0 {
            return;
        }
        if self.cache.len() >= CACHE_MAX {
            self.cache.retain(|_, e| e.expires > now);
            if self.cache.len() >= CACHE_MAX {
                if let Some(k) = self.cache.iter().min_by_key(|(_, e)| e.expires).map(|(k, _)| *k) {
                    self.cache.remove(&k);
                }
            }
        }
        let mut stored = Vec::from(resp);
        wr16(&mut stored, 0, 0);
        let key = self.cache_key(&name, qtype, qclass);
        self.cache.insert(key, CacheEntry {
            name, qtype, qclass, resp: stored, ttl_offs: scan.ttl_offs, has_opt: scan.has_opt,
            expires: now + ttl as u64 * 1000,
        });
    }

    fn send(&self, ip: u32, mac: Option<&[u8; 6]>, sport: u16, dport: u16, data: &[u8]) -> bool {
        let m = mac.map(|m| m.as_ptr()).unwrap_or(core::ptr::null());
        unsafe { net_udp_send(ip, m, sport, dport, data.as_ptr(), data.len()) }
    }

    fn reply_to(&self, to: &ReplyTo, payload: &[u8]) {
        match to {
            ReplyTo::Direct { ip, mac, port } => {
                self.send(*ip, Some(mac), DNS_PORT, *port, payload);
            }
            ReplyTo::Bridge { port, l2, pppoe_len, server, client, client_port } => {
                let ip_len = 20 + 8 + payload.len();
                if l2.len() + ip_len > 1514 {
                    return;
                }
                let mut f = Vec::with_capacity(l2.len() + ip_len);
                f.extend_from_slice(l2);
                if let Some(o) = pppoe_len {
                    wr16(&mut f, *o, (2 + ip_len) as u16);
                }
                let ip0 = f.len();
                f.extend_from_slice(&[0x45, 0]);
                f.extend_from_slice(&(ip_len as u16).to_be_bytes());
                f.extend_from_slice(&[0, 0, 0x40, 0, 64, 17, 0, 0]);
                f.extend_from_slice(&server.to_be_bytes());
                f.extend_from_slice(&client.to_be_bytes());
                let mut sum: u32 = 0;
                for i in (ip0..ip0 + 20).step_by(2) {
                    sum += u16::from_be_bytes([f[i], f[i + 1]]) as u32;
                }
                while sum > 0xFFFF {
                    sum = (sum & 0xFFFF) + (sum >> 16);
                }
                wr16(&mut f, ip0 + 10, !(sum as u16));
                f.extend_from_slice(&DNS_PORT.to_be_bytes());
                f.extend_from_slice(&client_port.to_be_bytes());
                f.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
                f.extend_from_slice(&[0, 0]); // UDP checksum optional over IPv4
                f.extend_from_slice(payload);
                unsafe { net_port_send(*port, f.as_ptr(), f.len()) };
            }
        }
    }

    fn fresh_port(&self) -> u16 {
        for _ in 0..16 {
            let p = 49152 + (random_u32() % 16384) as u16;
            if !self.pending.iter().any(|q| q.port == p) {
                return p;
            }
        }
        0
    }

    fn transmit(&mut self, i: usize, now: u64) {
        let n = self.upstreams.len();
        if n == 0 {
            return;
        }
        // The primary first; each retry moves on to the next server.
        let up = self.pending[i].tries as usize % n;
        let (ip, uport) = self.upstreams[up];
        let port = self.fresh_port();
        let qid = random_u32() as u16;
        let p = &mut self.pending[i];
        p.up = up;
        p.port = port;
        p.qid = qid;
        wr16(&mut p.query, 0, qid);
        p.sent = now;
        p.tries += 1;
        let q = core::mem::take(&mut p.query);
        let ok = port != 0 && self.send(ip, None, port, uport, &q);
        let p = &mut self.pending[i];
        p.query = q;
        p.sent_ok = ok;
    }

    fn on_query(&mut self, ip: u32, to: ReplyTo, q: &[u8], now: u64) {
        if !is_private(ip) {
            self.stats.refused += 1;
            return;
        }
        let limit = if matches!(to, ReplyTo::Bridge { .. }) { RATE_PER_MIN_BRIDGE } else { RATE_PER_MIN };
        if !self.rate_ok(ip, now, limit) {
            self.stats.rate_dropped += 1;
            return;
        }
        if q.len() < 12 || q[2] & 0x80 != 0 {
            self.stats.malformed += 1;
            return;
        }
        let reply = |s: &Self, r: &[u8]| s.reply_to(&to, r);
        if (q[2] >> 3) & 0x0F != 0 {
            self.stats.malformed += 1;
            reply(self, &reply_base(q, 12, 4)); // NOTIMP
            return;
        }
        if rd16(q, 4) != 1 || rd16(q, 6) != 0 || rd16(q, 8) != 0 || rd16(q, 10) > 2 {
            self.stats.malformed += 1;
            reply(self, &reply_base(q, 12, 1)); // FORMERR
            return;
        }
        let (name, o) = match read_qname(q, 12) {
            Some(x) if x.1 + 4 <= q.len() => x,
            _ => {
                self.stats.malformed += 1;
                reply(self, &reply_base(q, 12, 1));
                return;
            }
        };
        let qend = o + 4;
        let qtype = rd16(q, o);
        let qclass = rd16(q, o + 2);
        // Additional section: find EDNS and clamp its UDP size (no IP fragments here).
        let mut fwd = Vec::from(q);
        let mut edns = false;
        let mut a = qend;
        for _ in 0..rd16(q, 10) {
            let Some(n) = skip_name(q, a) else { break };
            if n + 10 > q.len() {
                a = usize::MAX;
                break;
            }
            if rd16(q, n) == 41 {
                edns = true;
                if rd16(q, n + 2) > EDNS_MAX {
                    wr16(&mut fwd, n + 2, EDNS_MAX);
                }
            }
            a = n + 10 + rd16(q, n + 8) as usize;
        }
        if a > q.len() {
            self.stats.malformed += 1;
            reply(self, &reply_base(q, 12, 1));
            return;
        }
        self.stats.queries += 1;
        self.ensure_key();

        if self.enabled && !name.is_empty() {
            if name == CANARY {
                self.stats.blocked += 1;
                reply(self, &blocked_reply(q, qend, qtype, true));
                self.log_push(now, ip, &name, qtype, Outcome::Blocked, SRC_CANARY, 0);
                return;
            }
            let (blocked, src) = self.verdict(&name);
            if blocked {
                self.stats.blocked += 1;
                reply(self, &blocked_reply(q, qend, qtype, false));
                self.log_push(now, ip, &name, qtype, Outcome::Blocked, src, 0);
                return;
            }
        }
        if let Some((e, remaining)) = self.cache_get(&name, qtype, qclass, edns, now) {
            let mut r = e.resp.clone();
            for &off in &e.ttl_offs {
                r[off as usize..off as usize + 4].copy_from_slice(&remaining.to_be_bytes());
            }
            r[..2].copy_from_slice(&q[..2]);
            r[12..qend].copy_from_slice(&q[12..qend]); // the client's own spelling (0x20)
            self.stats.cached += 1;
            reply(self, &r);
            self.log_push(now, ip, &name, qtype, Outcome::Cached, SRC_NONE, 0);
            return;
        }
        if self.upstreams.is_empty() || self.pending.len() >= MAX_PENDING {
            self.stats.failed += 1;
            reply(self, &reply_base(q, qend, 2)); // SERVFAIL
            self.log_push(now, ip, &name, qtype, Outcome::Failed, SRC_NONE, 0);
            return;
        }
        self.pending.push(Pending {
            qid: 0, port: 0, up: 0, client_ip: ip, to: to.clone(),
            client_id: rd16(q, 0), name, qtype, qclass, query: fwd,
            sent: now, sent_ok: false, start: now, tries: 0,
        });
        let i = self.pending.len() - 1;
        self.transmit(i, now);
    }

    fn on_answer(&mut self, ip: u32, sport: u16, dport: u16, r: &[u8], now: u64) -> bool {
        let Some(i) = self.pending.iter().position(|p| p.port == dport) else { return false };
        let p = &self.pending[i];
        let (uip, uport) = self.upstreams.get(p.up).copied().unwrap_or((0, 0));
        let same_q = r.len() >= 12 && read_qname(r, 12)
            .filter(|(n, o)| *n == p.name && o + 4 <= r.len() && rd16(r, *o) == p.qtype && rd16(r, o + 2) == p.qclass)
            .is_some();
        if ip != uip || sport != uport || r.len() < 12 || r[2] & 0x80 == 0 || rd16(r, 0) != p.qid
            || rd16(r, 4) != 1 || !same_q {
            self.stats.spoofed += 1;
            return true; // ours, but not a valid answer: dropped
        }
        let p = self.pending.swap_remove(i);
        let rcode = r[3] & 0x0F;
        let truncated = r[2] & 0x02 != 0;
        let qend = read_qname(r, 12).map(|(_, o)| o + 4).unwrap_or(12);
        if !truncated {
            if let Some(scan) = scan_records(r, qend) {
                self.cache_put(p.name.clone(), p.qtype, p.qclass, r, scan, rcode, now);
            }
        }
        let mut out = Vec::from(r);
        wr16(&mut out, 0, p.client_id);
        let qlen = qend.min(p.query.len());
        out[12..qlen].copy_from_slice(&p.query[12..qlen]);
        self.reply_to(&p.to, &out);
        self.stats.forwarded += 1;
        self.log_push(p.start, p.client_ip, &p.name, p.qtype, Outcome::Forwarded, SRC_NONE, (now - p.start) as u32);
        true
    }

    fn poll(&mut self, now: u64) {
        let mut i = 0;
        while i < self.pending.len() {
            let p = &self.pending[i];
            let wait = if p.sent_ok { UPSTREAM_TIMEOUT_MS } else { ARP_RETRY_MS };
            if now.saturating_sub(p.sent) < wait {
                i += 1;
                continue;
            }
            if p.tries < MAX_TRIES && !self.upstreams.is_empty() {
                self.transmit(i, now);
                i += 1;
                continue;
            }
            let p = self.pending.swap_remove(i);
            let qend = read_qname(&p.query, 12).map(|(_, o)| o + 4).unwrap_or(12);
            let mut r = reply_base(&p.query, qend, 2);
            wr16(&mut r, 0, p.client_id);
            self.reply_to(&p.to, &r);
            self.stats.failed += 1;
            self.log_push(p.start, p.client_ip, &p.name, p.qtype, Outcome::Failed, SRC_NONE, (now - p.start) as u32);
        }
    }

    // -- configuration --------------------------------------------------

    fn set_custom(&mut self, allow: bool, name: &[u8], add: bool) -> Result<String, (i32, String)> {
        let d = norm_domain(name).ok_or((400, String::from("Invalid domain (example: ads.example.com).")))?;
        let d = String::from_utf8(d).unwrap_or_default();
        let which = if allow { "the allowlist" } else { "the blocklist" };
        let v = if allow { &mut self.allow } else { &mut self.block };
        let pos = v.iter().position(|x| *x == d);
        if add {
            if pos.is_some() {
                return Err((409, alloc::format!("'{}' is already in {}.", d, which)));
            }
            if v.len() >= MAX_CUSTOM {
                return Err((409, alloc::format!("At most {} domains in {}.", MAX_CUSTOM, which)));
            }
            v.push(d.clone());
            v.sort();
        } else {
            match pos {
                Some(p) => { v.remove(p); }
                None => return Err((404, alloc::format!("'{}' is not in {}.", d, which))),
            }
        }
        self.ensure_key();
        let key = self.key;
        if allow { self.allow_h = sorted_hashes(key, &self.allow) } else { self.block_h = sorted_hashes(key, &self.block) }
        Ok(alloc::format!("'{}' {} {}.", d, if add { "added to" } else { "removed from" }, which))
    }

    fn set_upstreams(&mut self, value: &[u8]) -> Result<String, (i32, String)> {
        let mut ups = Vec::new();
        for tok in value.split(|&c| c == b' ' || c == b',').filter(|t| !t.is_empty()) {
            let (ip, port) = parse_endpoint(tok)
                .ok_or((400, String::from("Invalid server: use IP or IP:port (for example 192.168.1.1).")))?;
            if !is_private(ip) {
                return Err((400, String::from("The air-gap firewall does not allow DNS servers on the Internet: use one on your LAN (for example your router).")));
            }
            if ups.len() >= MAX_UPSTREAMS {
                return Err((400, alloc::format!("At most {} servers.", MAX_UPSTREAMS)));
            }
            ups.push((ip, port));
        }
        if ups.is_empty() {
            return Err((400, String::from("Give at least one DNS server.")));
        }
        self.upstreams = ups;
        self.upstream_auto = false;
        self.cache.clear();
        Ok(String::from("Servidores DNS actualizados."))
    }

    fn config_text(&self) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(b"# YesOS DNS filter\nenabled ");
        o.push(if self.enabled { b'1' } else { b'0' });
        o.extend_from_slice(b"\nlog ");
        o.push(if self.log_on { b'1' } else { b'0' });
        o.extend_from_slice(b"\ndoh ");
        o.push(if self.doh { b'1' } else { b'0' });
        o.push(b'\n');
        for &(ip, port) in self.upstreams.iter().filter(|_| !self.upstream_auto) {
            o.extend_from_slice(b"upstream ");
            push_ip(&mut o, ip);
            o.push(b':');
            push_num(&mut o, port as u64);
            o.push(b'\n');
        }
        for l in &self.lists {
            o.extend_from_slice(b"list ");
            o.extend_from_slice(l.name.as_bytes());
            o.extend_from_slice(if l.enabled { b" 1\n" } else { b" 0\n" });
        }
        for d in &self.allow {
            o.extend_from_slice(b"allow ");
            o.extend_from_slice(d.as_bytes());
            o.push(b'\n');
        }
        for d in &self.block {
            o.extend_from_slice(b"block ");
            o.extend_from_slice(d.as_bytes());
            o.push(b'\n');
        }
        o
    }

    fn config_load(&mut self, text: &[u8]) {
        self.upstreams.clear();
        self.upstream_auto = true;
        self.allow.clear();
        self.block.clear();
        self.lists.clear();
        for line in text.split(|&c| c == b'\n') {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let mut it = line.split(|&c| c == b' ').filter(|t| !t.is_empty());
            let (Some(k), v) = (it.next(), it.next().unwrap_or(b"")) else { continue };
            match k {
                b"enabled" => self.enabled = v != b"0",
                b"log" => self.log_on = v != b"0",
                b"doh" => self.doh = v == b"1",
                b"upstream" => {
                    if let Some((ip, port)) = parse_endpoint(v) {
                        if is_private(ip) && self.upstreams.len() < MAX_UPSTREAMS {
                            self.upstreams.push((ip, port));
                            self.upstream_auto = false;
                        }
                    }
                }
                b"list" => {
                    if valid_list_name(v) && self.lists.len() < MAX_LISTS && !self.lists.iter().any(|l| l.name.as_bytes() == v) {
                        let enabled = it.next() != Some(b"0");
                        self.lists.push(List { name: String::from_utf8(v.to_vec()).unwrap_or_default(), enabled, hashes: Vec::new(), loaded: false });
                    }
                }
                b"allow" | b"block" => {
                    if let Some(d) = norm_domain(v) {
                        let d = String::from_utf8(d).unwrap_or_default();
                        let target = if k == b"allow" { &mut self.allow } else { &mut self.block };
                        if target.len() < MAX_CUSTOM && !target.contains(&d) {
                            target.push(d);
                        }
                    }
                }
                _ => {}
            }
        }
        self.allow.sort();
        self.block.sort();
        if self.keyed {
            self.allow_h = sorted_hashes(self.key, &self.allow);
            self.block_h = sorted_hashes(self.key, &self.block);
        }
        self.cache.clear();
    }

    /// Parses a list (hosts file, one domain per line or `||domain^`).
    fn parse_list(&mut self, data: &[u8]) -> Vec<u64> {
        self.ensure_key();
        let key = self.key;
        let mut out = Vec::new();
        for line in data.split(|&c| c == b'\n') {
            let line = match line.iter().position(|&c| c == b'#') {
                Some(h) => &line[..h],
                None => line,
            };
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let mut toks = line.split(|&c| c == b' ' || c == b'\t').filter(|t| !t.is_empty());
            let Some(first) = toks.next() else { continue };
            if first.starts_with(b"!") || first.starts_with(b"[") || first.starts_with(b"@@") {
                continue;
            }
            let mut push = |d: &[u8]| {
                if matches!(d, b"localhost" | b"localhost.localdomain" | b"local" | b"broadcasthost") {
                    return;
                }
                if let Some(n) = norm_domain(d) {
                    if !n.iter().all(|&c| c.is_ascii_digit() || c == b'.') {
                        out.push(sip(key, &n));
                    }
                }
            };
            if let Some(d) = first.strip_prefix(b"||").and_then(|d| d.strip_suffix(b"^")) {
                push(d);
            } else if parse_ip(first).is_some() || first.contains(&b':') {
                for t in toks {
                    push(t);
                }
            } else if !first.contains(&b'|') && !first.contains(&b'$') && !first.contains(&b'/') {
                push(first);
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    fn json(&self, now: u64) -> Vec<u8> {
        let mut o = Vec::with_capacity(32 * 1024);
        let b = |o: &mut Vec<u8>, k: &str, v: bool| {
            o.extend_from_slice(b"\"");
            o.extend_from_slice(k.as_bytes());
            o.extend_from_slice(if v { b"\":true," } else { b"\":false," });
        };
        let n = |o: &mut Vec<u8>, k: &str, v: u64| {
            o.extend_from_slice(b"\"");
            o.extend_from_slice(k.as_bytes());
            o.extend_from_slice(b"\":");
            push_num(o, v);
            o.push(b',');
        };
        let s = |o: &mut Vec<u8>, v: &[u8]| {
            o.push(b'"');
            for &c in v {
                match c {
                    b'"' | b'\\' | b'<' | b'>' | b'&' => { o.extend_from_slice(b"\\u00"); o.push(b"0123456789abcdef"[(c >> 4) as usize]); o.push(b"0123456789abcdef"[(c & 15) as usize]); }
                    0x20..=0x7e => o.push(c),
                    _ => {}
                }
            }
            o.push(b'"');
        };
        o.push(b'{');
        b(&mut o, "enabled", self.enabled);
        b(&mut o, "log_enabled", self.log_on);
        b(&mut o, "doh", self.doh);
        b(&mut o, "upstream_auto", self.upstream_auto);
        o.extend_from_slice(b"\"upstreams\":[");
        for (i, &(ip, port)) in self.upstreams.iter().enumerate() {
            if i > 0 { o.push(b','); }
            let mut t = Vec::new();
            push_ip(&mut t, ip);
            if port != DNS_PORT { t.push(b':'); push_num(&mut t, port as u64); }
            s(&mut o, &t);
        }
        o.extend_from_slice(b"],\"lists\":[");
        for (i, l) in self.lists.iter().enumerate() {
            if i > 0 { o.push(b','); }
            o.extend_from_slice(b"{\"name\":");
            s(&mut o, l.name.as_bytes());
            o.push(b',');
            b(&mut o, "enabled", l.enabled);
            b(&mut o, "loaded", l.loaded);
            o.extend_from_slice(b"\"domains\":");
            push_num(&mut o, l.hashes.len() as u64);
            o.push(b'}');
        }
        for (key, v) in [("allow", &self.allow), ("block", &self.block)] {
            o.extend_from_slice(b"],\"");
            o.extend_from_slice(key.as_bytes());
            o.extend_from_slice(b"\":[");
            for (i, d) in v.iter().enumerate() {
                if i > 0 { o.push(b','); }
                s(&mut o, d.as_bytes());
            }
        }
        o.extend_from_slice(b"],\"stats\":{");
        let st = &self.stats;
        for (k, v) in [("queries", st.queries), ("blocked", st.blocked), ("cached", st.cached), ("forwarded", st.forwarded),
                       ("failed", st.failed), ("rate_dropped", st.rate_dropped), ("malformed", st.malformed),
                       ("refused", st.refused), ("spoofed", st.spoofed)] {
            n(&mut o, k, v);
        }
        o.pop();
        o.extend_from_slice(b"},");
        n(&mut o, "cache_entries", self.cache.len() as u64);
        n(&mut o, "pending", self.pending.len() as u64);
        n(&mut o, "list_domains", self.lists.iter().filter(|l| l.enabled).map(|l| l.hashes.len() as u64).sum());
        // Top blocked domains and clients, from the in-RAM log only.
        let mut dom: BTreeMap<&str, u32> = BTreeMap::new();
        let mut cli: BTreeMap<u32, u32> = BTreeMap::new();
        for e in &self.log {
            *cli.entry(e.client).or_insert(0) += 1;
            if e.outcome == Outcome::Blocked {
                *dom.entry(e.name.as_str()).or_insert(0) += 1;
            }
        }
        let mut dv: Vec<(&str, u32)> = dom.into_iter().collect();
        dv.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        o.extend_from_slice(b"\"top_blocked\":[");
        for (i, (d, c)) in dv.iter().take(10).enumerate() {
            if i > 0 { o.push(b','); }
            o.push(b'[');
            s(&mut o, d.as_bytes());
            o.push(b',');
            push_num(&mut o, *c as u64);
            o.push(b']');
        }
        let mut cv: Vec<(u32, u32)> = cli.into_iter().collect();
        cv.sort_by(|a, b| b.1.cmp(&a.1));
        o.extend_from_slice(b"],\"top_clients\":[");
        for (i, (ip, c)) in cv.iter().take(10).enumerate() {
            if i > 0 { o.push(b','); }
            o.extend_from_slice(b"[\"");
            push_ip(&mut o, *ip);
            o.extend_from_slice(b"\",");
            push_num(&mut o, *c as u64);
            o.push(b']');
        }
        o.extend_from_slice(b"],\"log\":[");
        for (i, e) in self.log.iter().rev().take(LOG_JSON).enumerate() {
            if i > 0 { o.push(b','); }
            o.push(b'{');
            n(&mut o, "age_s", now.saturating_sub(e.t) / 1000);
            o.extend_from_slice(b"\"client\":\"");
            push_ip(&mut o, e.client);
            o.extend_from_slice(b"\",\"name\":");
            s(&mut o, e.name.as_bytes());
            o.extend_from_slice(b",\"type\":\"");
            o.extend_from_slice(type_name(e.qtype).as_bytes());
            o.extend_from_slice(b"\",\"status\":\"");
            o.extend_from_slice(match e.outcome {
                Outcome::Blocked => b"blocked" as &[u8],
                Outcome::Cached => b"cached",
                Outcome::Forwarded => b"forwarded",
                Outcome::Failed => b"failed",
            });
            o.extend_from_slice(b"\",\"by\":");
            s(&mut o, self.src_name(e.src).as_bytes());
            o.extend_from_slice(b",\"ms\":");
            push_num(&mut o, e.ms as u64);
            o.push(b'}');
        }
        o.extend_from_slice(b"]}");
        o
    }
}

// ---------------------------------------------------------------------------
// C interface (kernel/dnsblock.c)
// ---------------------------------------------------------------------------

unsafe fn bytes<'a>(p: *const u8, len: usize) -> &'a [u8] {
    if p.is_null() || len == 0 { &[] } else { slice::from_raw_parts(p, len) }
}

unsafe fn cstr<'a>(p: *const u8) -> &'a [u8] {
    if p.is_null() {
        return &[];
    }
    let mut n = 0;
    while *p.add(n) != 0 && n < 4096 {
        n += 1;
    }
    slice::from_raw_parts(p, n)
}

fn copy_out(src: &[u8], out: *mut u8, max: usize) -> i32 {
    if out.is_null() || src.len() + 1 > max {
        return -2;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(src.as_ptr(), out, src.len());
        *out.add(src.len()) = 0;
    }
    src.len() as i32
}

/// Every UDP datagram the NAS receives. Returns 1 if it was DNS traffic
/// (a query to port 53 or an answer to one of our upstream ports).
#[no_mangle]
pub extern "C" fn yc_dns_udp(src_ip: u32, src_mac: *const u8, sport: u16, dport: u16,
                             data: *const u8, len: usize, now_ms: u64) -> i32 {
    if src_mac.is_null() || len > 4096 {
        return 0;
    }
    let pkt = unsafe { bytes(data, len) };
    let mut mac = [0u8; 6];
    mac.copy_from_slice(unsafe { slice::from_raw_parts(src_mac, 6) });
    DNS.with(|d| {
        if dport == DNS_PORT {
            d.on_query(src_ip, ReplyTo::Direct { ip: src_ip, mac, port: sport }, pkt, now_ms);
            1
        } else if dport >= 49152 && d.on_answer(src_ip, sport, dport, pkt, now_ms) {
            1
        } else {
            0
        }
    })
}

#[cfg(feature = "intercept")]
/// A DNS query crossing the bridge towards the Internet (UDP 53, IPv4).
/// Returns 1 when the DNS filter took it (answered or will answer), 0 when
/// the bridge should forward it unchanged (e.g. the client is not private).
#[no_mangle]
pub extern "C" fn yc_dns_intercept(port: u32, frame: *const u8, len: usize, now_ms: u64) -> i32 {
    if frame.is_null() || len < 14 {
        return 0;
    }
    let f = unsafe { bytes(frame, len) };
    let crate::frames::Parsed::Ip { l2, tcp: false, src: crate::frames::Addr::V4(client), dst: crate::frames::Addr::V4(server),
                                sport, dport: 53, l4, ports: true, udp_len } = crate::frames::parse(f) else { return 0 };
    if l2.v6 || udp_len < 8 || l4 + udp_len > f.len() || !is_private(client) {
        return 0;
    }
    let payload = &f[l4 + 8..l4 + udp_len];
    let mut hdr = Vec::from(&f[..l2.l3]);
    let (dst_mac, src_mac) = (f[0..6].to_vec(), f[6..12].to_vec());
    hdr[0..6].copy_from_slice(&src_mac);   // back to the client ...
    hdr[6..12].copy_from_slice(&dst_mac);  // ... from the MAC it sent to
    let to = ReplyTo::Bridge { port, l2: hdr, pppoe_len: l2.pppoe_len, server, client, client_port: sport };
    DNS.with(|d| d.on_query(client, to, payload, now_ms));
    1
}

#[no_mangle]
pub extern "C" fn yc_dns_poll(now_ms: u64) {
    DNS.with(|d| {
        if !d.pending.is_empty() {
            d.poll(now_ms);
        }
    });
}

#[no_mangle]
pub extern "C" fn yc_dns_config_load(text: *const u8, len: usize) {
    let t = unsafe { bytes(text, len) };
    DNS.with(|d| d.config_load(t));
}

#[no_mangle]
pub extern "C" fn yc_dns_set_default_upstream(ip: u32) {
    DNS.with(|d| {
        if d.upstream_auto && is_private(ip) && d.upstreams != [(ip, DNS_PORT)] {
            d.upstreams = alloc::vec![(ip, DNS_PORT)];
            d.cache.clear();
        }
    });
}

#[no_mangle]
pub extern "C" fn yc_dns_config_text(out: *mut u8, max: usize) -> i32 {
    let t = DNS.with(|d| d.config_text());
    copy_out(&t, out, max)
}

/// Name of list `i` (for loading its file), or -1 past the end.
#[no_mangle]
pub extern "C" fn yc_dns_list_name(i: u32, out: *mut u8, max: usize) -> i32 {
    let n = DNS.with(|d| d.lists.get(i as usize).map(|l| l.name.clone()));
    match n {
        Some(n) => copy_out(n.as_bytes(), out, max),
        None => -1,
    }
}

/// Loads (or replaces) a list. Returns the number of domains, 0 if the
/// data holds none (nothing changed), -1 bad name, -2 too many lists.
#[no_mangle]
pub extern "C" fn yc_dns_list_load(name: *const u8, data: *const u8, len: usize, create: bool) -> i32 {
    let name = unsafe { cstr(name) };
    let data = unsafe { bytes(data, len) };
    if !valid_list_name(name) {
        return -1;
    }
    DNS.with(|d| {
        let exists = d.lists.iter().position(|l| l.name.as_bytes() == name);
        if exists.is_none() && (!create || d.lists.len() >= MAX_LISTS) {
            return if create { -2 } else { -1 };
        }
        let hashes = d.parse_list(data);
        if hashes.is_empty() {
            return 0;
        }
        let count = hashes.len() as i32;
        match exists {
            Some(i) => {
                d.lists[i].hashes = hashes;
                d.lists[i].loaded = true;
            }
            None => d.lists.push(List { name: String::from_utf8(name.to_vec()).unwrap_or_default(), enabled: true, hashes, loaded: true }),
        }
        d.cache.clear();
        count
    })
}

#[no_mangle]
pub extern "C" fn yc_dns_list_remove(name: *const u8) -> i32 {
    let name = unsafe { cstr(name) };
    DNS.with(|d| match d.lists.iter().position(|l| l.name.as_bytes() == name) {
        Some(i) => {
            d.lists.remove(i);
            // log entries refer to lists by index
            for e in d.log.iter_mut() {
                if (e.src as usize) == i { e.src = SRC_NONE } else if (e.src as usize) > i && e.src < SRC_CUSTOM { e.src -= 1 }
            }
            0
        }
        None => -1,
    })
}

/// Panel and console actions. Returns an HTTP-like status, message in `msg`.
#[no_mangle]
pub extern "C" fn yc_dns_action(action: *const u8, name: *const u8, value: *const u8, msg: *mut u8, max: usize) -> i32 {
    let (action, name, value) = unsafe { (cstr(action), cstr(name), cstr(value)) };
    let on = matches!(value, b"1" | b"on" | b"true");
    let off = matches!(value, b"0" | b"off" | b"false");
    let r: Result<String, (i32, String)> = DNS.with(|d| match action {
        b"dns_enable" if on || off => {
            d.enabled = on;
            Ok(String::from(if on { "DNS blocking enabled." } else { "DNS blocking disabled: names are still resolved, without filtering." }))
        }
        b"dns_doh" if on || off => {
            d.doh = on;
            Ok(String::from(if on { "Known encrypted DNS servers are blocked." } else { "Encrypted DNS servers are no longer blocked." }))
        }
        b"dns_log" if on || off => {
            d.log_on = on;
            if off { d.log.clear(); }
            Ok(String::from(if on { "Query log enabled (in memory only)." } else { "Query log disabled and cleared." }))
        }
        b"dns_log" if value == b"clear" => {
            d.log.clear();
            Ok(String::from("Query log cleared."))
        }
        b"dns_cache_clear" => {
            d.cache.clear();
            Ok(String::from("DNS cache cleared."))
        }
        b"dns_upstreams" if value == b"auto" => {
            d.upstream_auto = true;
            Ok(String::from("Automatic DNS server: the network gateway."))
        }
        b"dns_upstreams" => d.set_upstreams(value),
        b"dns_allow" | b"dns_block" if value == b"add" || value == b"del" => d.set_custom(action == b"dns_allow", name, value == b"add"),
        b"dns_list" if on || off => match d.lists.iter_mut().find(|l| l.name.as_bytes() == name) {
            Some(l) => {
                l.enabled = on;
                let n = l.name.clone();
                d.cache.clear();
                Ok(alloc::format!("List '{}' {}.", n, if on { "enabled" } else { "disabled" }))
            }
            None => Err((404, String::from("No such list."))),
        },
        b"dns_test" => {
            let Some(n) = norm_domain(name) else { return Err((400, String::from("Invalid domain."))) };
            d.ensure_key();
            let ns = core::str::from_utf8(&n).unwrap_or("?");
            if n == CANARY {
                return Ok(alloc::format!("'{}': blocked (the signal that tells Firefox not to use its encrypted DNS).", ns));
            }
            let (blocked, src) = d.verdict(&n);
            Ok(if blocked {
                let by = match src {
                    SRC_CUSTOM => String::from("your blocked domains"),
                    SRC_DOH => String::from("the encrypted DNS list"),
                    _ => alloc::format!("the list '{}'", d.src_name(src)),
                };
                if d.enabled {
                    alloc::format!("'{}': BLOCKED by {}.", ns, by)
                } else {
                    alloc::format!("'{}': {} would block it, but the filter is disabled.", ns, by)
                }
            } else if src == SRC_CUSTOM {
                alloc::format!("'{}': allowed (your allowlist).", ns)
            } else {
                alloc::format!("'{}': not blocked.", ns)
            })
        }
        _ => Err((400, String::from("Invalid action or value."))),
    });
    let (code, text) = match r {
        Ok(t) => (200, t),
        Err((c, t)) => (c, t),
    };
    let tb = text.as_bytes();
    let n = tb.len().min(max.saturating_sub(1));
    if !msg.is_null() && max > 0 {
        let mut cut = n;
        while cut > 0 && cut < tb.len() && (tb[cut] & 0xC0) == 0x80 {
            cut -= 1; // keep UTF-8 whole
        }
        copy_out(&tb[..cut], msg, max);
    }
    code
}

#[no_mangle]
pub extern "C" fn yc_dns_json(out: *mut u8, max: usize, now_ms: u64) -> i32 {
    let j = DNS.with(|d| d.json(now_ms));
    copy_out(&j, out, max)
}

/// Console: the most recent queries of the in-RAM log (newest first), plus
/// the lists. Empty log when it is off.
#[no_mangle]
pub extern "C" fn yc_dns_log_text(out: *mut u8, max: usize, now_ms: u64, count: u32) -> i32 {
    let t = DNS.with(|d| {
        let mut o = String::new();
        for l in &d.lists {
            o.push_str(&alloc::format!("  list {:<20} {} {} domains\n", l.name, if l.enabled { "ON " } else { "off" }, l.hashes.len()));
        }
        if !d.log_on {
            o.push_str("  query log is off\n");
        } else if d.log.is_empty() {
            o.push_str("  no queries logged\n");
        }
        for e in d.log.iter().rev().take(count as usize) {
            let status = match e.outcome {
                Outcome::Blocked => "blocked",
                Outcome::Cached => "cached",
                Outcome::Forwarded => "forwarded",
                Outcome::Failed => "failed",
            };
            let ip = e.client;
            o.push_str(&alloc::format!("  {:>5}s ago  {}.{}.{}.{:<4} {:<5} {:<9} {:<16} {}\n",
                now_ms.saturating_sub(e.t) / 1000, ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255,
                type_name(e.qtype), status, d.src_name(e.src), e.name));
        }
        o
    });
    copy_out(t.as_bytes(), out, max)
}

/// One-line summary for the console.
#[no_mangle]
pub extern "C" fn yc_dns_status(out: *mut u8, max: usize) -> i32 {
    let t = DNS.with(|d| {
        let s = &d.stats;
        alloc::format!(
            "filter {} | lists {} ({} domains) | allow {} block {} | queries {} blocked {} cached {} forwarded {} failed {} | dropped: rate {} malformed {} refused {} spoofed {} | cache {} | log {} ({})",
            if d.enabled { "ON" } else { "OFF" }, d.lists.len(),
            d.lists.iter().filter(|l| l.enabled).map(|l| l.hashes.len()).sum::<usize>(),
            d.allow.len(), d.block.len(), s.queries, s.blocked, s.cached, s.forwarded, s.failed,
            s.rate_dropped, s.malformed, s.refused, s.spoofed, d.cache.len(),
            if d.log_on { "on" } else { "off" }, d.log.len())
    });
    copy_out(t.as_bytes(), out, max)
}
