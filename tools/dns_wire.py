#!/usr/bin/env python3
"""
DNS on the wire for the YesOS DNS filter tests: query builder and parser,
a UDP client, and Upstream, a fake resolver on the host that records every
query it receives (the guest reaches it as 10.0.2.2:<port>).
"""
import random
import socket
import struct
import threading


# ---------------------------------------------------------------------------
# DNS wire helpers
# ---------------------------------------------------------------------------

def qname(name):
    out = b""
    for label in name.strip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\0"


def query(name, qtype=1, qid=None, edns=None, flags=0x0100):
    qid = random.randint(0, 65535) if qid is None else qid
    ar = 1 if edns else 0
    pkt = struct.pack(">HHHHHH", qid, flags, 1, 0, 0, ar) + qname(name) + struct.pack(">HH", qtype, 1)
    if edns:
        pkt += b"\0" + struct.pack(">HHIH", 41, edns, 0, 0)
    return qid, pkt


def skip_name(p, o):
    while True:
        n = p[o]
        if n == 0:
            return o + 1
        if n & 0xC0 == 0xC0:
            return o + 2
        o += 1 + n


def parse(p):
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", p[:12])
    o = 12
    qn = []
    if qd:
        while p[o]:
            qn.append(p[o + 1:o + 1 + p[o]].decode())
            o += 1 + p[o]
        o += 5
    answers = []
    for _ in range(an):
        o = skip_name(p, o)
        rtype, _, ttl, rdlen = struct.unpack(">HHIH", p[o:o + 10])
        rdata = p[o + 10:o + 10 + rdlen]
        answers.append((rtype, ttl, socket.inet_ntop(socket.AF_INET6 if rtype == 28 else socket.AF_INET, rdata)
                        if rtype in (1, 28) else rdata))
        o += 10 + rdlen
    return {"id": qid, "rcode": flags & 15, "tc": bool(flags & 0x200), "qname": ".".join(qn),
            "answers": answers, "an": an}


def ask(port, name, qtype=1, timeout=8, edns=None):
    qid, pkt = query(name, qtype, edns=edns)
    return exchange(port, pkt, qid, timeout)


def exchange(port, pkt, qid=None, timeout=8):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, ("127.0.0.1", port))
        while True:
            data, _ = s.recvfrom(4096)
            r = parse(data)
            if qid is None or r["id"] == qid:
                return r
    except (socket.timeout, OSError):
        return None
    finally:
        s.close()


def addr(r):
    return [a[2] for a in r["answers"]] if r else None


# ---------------------------------------------------------------------------
# Fake upstream resolver on the host
# ---------------------------------------------------------------------------

class Upstream:
    RECORDS = {"example.org": "93.184.216.34", "good.ads.blocked.test": "10.9.9.9", "ads.blocked.test": "6.6.6.6",
               "mine.example": "7.7.7.7", "dns.google": "8.8.8.8", "spoof.test": "1.2.3.4",
               "use-application-dns.net": "9.9.9.9"}

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.seen = []        # (lowercase name, qtype, edns size or None)
        self.running = True
        threading.Thread(target=self.loop, daemon=True).start()

    def count(self, name):
        return sum(1 for n, _, _ in self.seen if n == name)

    def loop(self):
        while self.running:
            try:
                data, peer = self.sock.recvfrom(4096)
            except OSError:
                return
            try:
                self.answer(data, peer)
            except Exception as e:   # never let a bad packet kill the server
                print("upstream error:", e)

    def answer(self, data, peer):
        qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
        o = 12
        labels = []
        while data[o]:
            labels.append(data[o + 1:o + 1 + data[o]])
            o += 1 + data[o]
        qend = o + 5
        qtype = struct.unpack(">H", data[o + 1:o + 3])[0]
        name = b".".join(labels).decode().lower()
        edns = None
        if ar:
            ro = skip_name(data, qend)
            if struct.unpack(">H", data[ro:ro + 2])[0] == 41:
                edns = struct.unpack(">H", data[ro + 2:ro + 4])[0]
        self.seen.append((name, qtype, edns))
        question = data[12:qend]
        if name.startswith("dead."):
            return
        hdr = lambda rid, rc, n_an, n_ns=0: struct.pack(">HHHHHH", rid, 0x8180 | rc, 1, n_an, n_ns, 0)
        if name == "spoof.test":
            # wrong ID, then right ID with another question, then the real answer
            self.sock.sendto(hdr(qid ^ 0x5555, 0, 1) + question + self.rr_a("6.6.6.6"), peer)
            other = qname("evil.test") + struct.pack(">HH", 1, 1)
            self.sock.sendto(hdr(qid, 0, 1) + other + self.rr_a("6.6.6.6"), peer)
        if name in self.RECORDS and qtype == 1:
            self.sock.sendto(hdr(qid, 0, 1) + question + self.rr_a(self.RECORDS[name]), peer)
        elif name.startswith("nx."):
            soa = (b"\xc0\x0c" + struct.pack(">HHI", 6, 1, 300) +
                   struct.pack(">H", 22) + b"\0\0" + struct.pack(">IIIII", 1, 2, 3, 4, 60))
            self.sock.sendto(hdr(qid, 3, 0, 1) + question + soa, peer)
        else:
            self.sock.sendto(hdr(qid, 0, 0) + question, peer)   # no data

    @staticmethod
    def rr_a(ip, ttl=300):
        return b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, ttl, 4) + socket.inet_aton(ip)

    def close(self):
        self.running = False
        self.sock.close()
