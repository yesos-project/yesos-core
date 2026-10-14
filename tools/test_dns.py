#!/usr/bin/env python3
"""
DNS filter engine test (core module `dns`), on the core self-test image, driven
from the console. A fake upstream resolver runs on the host (the guest reaches
it as 10.0.2.2:<port>) and records every query it receives, so the test knows
exactly what was forwarded. Checks:
  forwarding and caching (TTL, the client's 0x20 spelling, negative cache, the
  EDNS clamp to 1232); lists copied onto the disk and loaded with
  `dns list add` (hosts / plain / ||domain^ formats, bad names and empty lists
  refused); blocking of subdomains, A / AAAA / other types; allowlist
  precedence; personal block list; list on/off; filter on/off; the Firefox
  canary and the DoH list; anti-spoofing (wrong ID, wrong question); dead
  upstream -> SERVFAIL; primary / alternate failover; malformed packets
  (FORMERR, no crash); public upstreams refused; `dns log` (RAM only, off
  clears it); a 100,000-domain list; persistence across a reboot; the
  per-client rate limit; fsck.

Usage: python3 tools/test_dns.py      (after `make`; non-zero exit on failure)
"""
import os
import random
import shutil
import socket
import struct
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import yesos_harness as harness  # noqa: E402
import redsea_fsck  # noqa: E402
import redsea_injector  # noqa: E402
from dns_wire import qname, query, ask, exchange, addr, Upstream  # noqa: E402

failures = []

LIST = """# test list (hosts format, comments, junk)
0.0.0.0 ads.blocked.test
127.0.0.1 tracker.example  # inline comment
0.0.0.0 localhost
plain-domain.test
||adblock-style.test^
! adblock comment
[Adblock Plus 2.0]
@@||exception.test^
||with-modifier.test^$third-party
not a domain at all !!
0.0.0.0 a.b.c.multi.test second.multi.test
192.168.1.1
"""


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label, flush=True)
    if not cond:
        failures.append(label)
    return cond


def free_port(kind=socket.SOCK_DGRAM):
    s = socket.socket(socket.AF_INET, kind)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def boot(disk, dns_port):
    orig = harness.subprocess.Popen

    def popen(cmd, *a, **kw):
        cmd = [c + f",hostfwd=udp:127.0.0.1:{dns_port}-:53" if c.startswith("user,id=net0") else c for c in cmd]
        return orig(cmd, *a, **kw)

    harness.subprocess.Popen = popen
    try:
        vm = harness.YesOS(disk, free_port())
    finally:
        harness.subprocess.Popen = orig
    return vm, vm.wait_for("YesOS [", 240)


def console(vm, line, wait=2):
    m = vm.send(line, wait)
    return vm.since(m)


def stat(vm, name):
    """A counter from the `dns` status line."""
    line = console(vm, "dns", 1)
    i = line.find(f" {name} ")
    return int(line[i + len(name) + 2:].split()[0].rstrip("|")) if i >= 0 else -1


def inject(disk, name, data):
    with open(os.devnull, "w") as null:
        old = sys.stdout
        sys.stdout = null
        try:
            redsea_injector.inject_bytes(disk, data, name)
        finally:
            sys.stdout = old


def main():
    if not os.path.exists(harness.KERNEL):
        print(f"{harness.KERNEL} not found: run `make` first")
        sys.exit(2)
    tmp = tempfile.mkdtemp(prefix="yesos_dns_")
    disk = os.path.join(tmp, "disk.img")
    with open(os.devnull, "w") as null:
        old = sys.stdout
        sys.stdout = null
        try:
            redsea_injector.format_disk(disk, total_mb=96)
        finally:
            sys.stdout = old
    inject(disk, "SYS/DNSLIST/test.txt", LIST.encode())
    inject(disk, "SYS/DNSLIST/empty.txt", b"# nothing\nfoo\n")
    big = "\n".join(f"0.0.0.0 bulk{i}.ads{i % 97}.example" for i in range(100_000)).encode()
    inject(disk, "SYS/DNSLIST/big.txt", big)
    up = Upstream()
    dns_port = free_port()
    try:
        vm, ok = boot(disk, dns_port)
        try:
            check(ok and "[DNS] Filter listening on UDP 53" in vm.output(), "DNS filter starts at boot (core self-test image)")
            r = console(vm, "dns upstream 1.1.1.1")
            check("error" in r and "LAN" in r, "public upstream refused (the system never talks to the Internet)")
            r = console(vm, f"dns upstream 10.0.2.2:{up.port}")
            check("error" not in r, "upstream set to the fake resolver")

            # --- forwarding and cache ------------------------------------
            r = ask(dns_port, "example.org")
            check(r and r["rcode"] == 0 and addr(r) == ["93.184.216.34"], f"name resolved through the upstream ({addr(r)})")
            r2 = ask(dns_port, "ExAmPlE.org")
            check(r2 and addr(r2) == ["93.184.216.34"] and up.count("example.org") == 1,
                  f"second query answered from the cache (upstream asked {up.count('example.org')} time)")
            check(r2 and r2["qname"] == "ExAmPlE.org", "cached answer keeps the client's spelling (0x20)")
            ask(dns_port, "nx.example.org")
            r = ask(dns_port, "nx.example.org")
            check(r and r["rcode"] == 3 and up.count("nx.example.org") == 1, "NXDOMAIN cached (negative cache, SOA minimum)")
            ask(dns_port, "edns.example.org", edns=4096)
            ed = [e for n, _, e in up.seen if n == "edns.example.org"]
            check(ed == [1232], f"EDNS buffer clamped to 1232 bytes for the upstream ({ed})")

            # --- lists ----------------------------------------------------
            check("error" in console(vm, "dns list add Bad_Name!"), "bad list name refused")
            check("no contiene dominios" in console(vm, "dns list add empty"), "list without domains refused")
            check("error" in console(vm, "dns list add missing"), "a list that is not on the disk is reported")
            r = console(vm, "dns list add test")
            check("6 dominios" in r, f"list loaded: exactly the 6 valid domains parsed ({r.strip()[-60:]})")
            before = len(up.seen)
            check(addr(ask(dns_port, "ads.blocked.test")) == ["0.0.0.0"], "listed domain blocked with 0.0.0.0")
            check(addr(ask(dns_port, "deep.sub.ads.blocked.test")) == ["0.0.0.0"], "subdomain of a listed domain blocked")
            check(addr(ask(dns_port, "ads.blocked.test", 28)) == ["::"], "AAAA blocked with ::")
            r = ask(dns_port, "ads.blocked.test", 15)
            check(r and r["rcode"] == 0 and r["an"] == 0, "other types blocked with no data")
            for d in ("tracker.example", "plain-domain.test", "adblock-style.test", "a.b.c.multi.test", "second.multi.test"):
                check(addr(ask(dns_port, d)) == ["0.0.0.0"], f"list format parsed: {d} blocked")
            check(len(up.seen) == before, "blocked names never reach the upstream")
            check(addr(ask(dns_port, "blocked.test")) != ["0.0.0.0"], "the parent of a listed domain is not blocked")
            check(addr(ask(dns_port, "exception.test")) != ["0.0.0.0"], "adblock exceptions and modifiers are not treated as blocks")

            console(vm, "dns allow good.ads.blocked.test")
            check(addr(ask(dns_port, "good.ads.blocked.test")) == ["10.9.9.9"], "allowlist wins over the list")
            r = console(vm, "dns test good.ads.blocked.test")
            check("permitido" in r, "dns test: allowlist reported")
            r = console(vm, "dns test x.ads.blocked.test")
            check("BLOQUEADO" in r and "'test'" in r, "dns test: names the list that blocks")
            console(vm, "dns block mine.example")
            check(addr(ask(dns_port, "mine.example")) == ["0.0.0.0"], "personal block list")
            check("error" in console(vm, "dns block not_a_domain"), "invalid domain refused")
            console(vm, "dns list off test")
            off = addr(ask(dns_port, "ads.blocked.test"))
            console(vm, "dns list on test")
            check(off == ["6.6.6.6"] and addr(ask(dns_port, "ads.blocked.test")) == ["0.0.0.0"], "list switched off and on")
            console(vm, "dns off")
            off = addr(ask(dns_port, "ads.blocked.test"))
            console(vm, "dns on")
            check(off == ["6.6.6.6"], "filter off: it still resolves, without blocking")
            r = ask(dns_port, "use-application-dns.net")
            check(r and r["rcode"] == 3, "Firefox DoH canary answered NXDOMAIN")
            check(addr(ask(dns_port, "dns.google")) == ["8.8.8.8"], "DoH providers not blocked by default")
            console(vm, "dns doh on")
            check(addr(ask(dns_port, "dns.google")) == ["0.0.0.0"], "DoH provider list blocks dns.google")

            # --- spoofing, timeouts, failover, malformed -------------------
            r = ask(dns_port, "spoof.test")
            check(r and addr(r) == ["1.2.3.4"] and stat(vm, "spoofed") >= 2,
                  "forged answers (wrong ID, wrong question) dropped, the real one used")
            t0 = time.time()
            r = ask(dns_port, "dead.example.org", timeout=15)
            el = time.time() - t0
            check(r and r["rcode"] == 2 and 3 < el < 10, f"dead upstream -> SERVFAIL after retries ({el:.1f} s)")
            check(up.count("dead.example.org") == 3, f"3 attempts with fresh ID and port ({up.count('dead.example.org')})")
            closed = free_port()
            console(vm, f"dns upstream 10.0.2.2:{up.port} 10.0.2.2:{closed}")
            t0 = time.time()
            rs = [ask(dns_port, f"fast{i}.example.org") for i in range(8)]
            el = time.time() - t0
            check(all(x and x["rcode"] == 0 for x in rs) and el < 3, f"primary answers: the alternate is never used ({el:.1f} s for 8)")
            console(vm, f"dns upstream 10.0.2.2:{closed} 10.0.2.2:{up.port}")
            t0 = time.time()
            r = ask(dns_port, "failover.example.org", timeout=10)
            el = time.time() - t0
            check(r and r["rcode"] == 0 and 1.2 < el < 4, f"primary down: the alternate answers after one timeout ({el:.1f} s)")
            console(vm, f"dns upstream 10.0.2.2:{up.port}")
            rnd = random.Random(7)
            bad = [b"", b"\0" * 5, query("x.test", flags=0x8100)[1],
                   b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\xc0\x0c\x00\x01\x00\x01",
                   b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x40" + b"a" * 64 + b"\0\0\x01\0\x01"]
            bad += [bytes(rnd.getrandbits(8) for _ in range(rnd.randint(1, 600))) for _ in range(300)]
            bad += [query("fuzz.test")[1][:k] for k in range(1, 30)]
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for b in bad:
                s.sendto(b, ("127.0.0.1", dns_port))
                time.sleep(0.002)
            s.close()
            two = struct.pack(">HHHHHH", 77, 0x0100, 2, 0, 0, 0) + qname("a.test") + b"\0\1\0\1" + qname("b.test") + b"\0\1\0\1"
            r = exchange(dns_port, two, 77)
            check(r and r["rcode"] == 1, "two questions -> FORMERR")
            check(addr(ask(dns_port, "example.org")) == ["93.184.216.34"], f"{len(bad)} malformed packets later, still answering")
            check(stat(vm, "malformed") >= 30, "malformed packets counted")

            # --- log ---------------------------------------------------------
            log = console(vm, "dns log", 3)
            check(all(w in log for w in ("blocked", "cached", "forwarded", "failed")), "dns log shows every outcome")
            check(any("blocked" in ln and " test " in ln and "ads.blocked.test" in ln for ln in log.splitlines()),
                  "dns log says which list blocked")
            check("list test" in log and "ON" in log, "dns log lists the lists")
            console(vm, "dns log off")
            ask(dns_port, "example.org")
            check("query log is off" in console(vm, "dns log"), "log off: cleared and nothing recorded")
            console(vm, "dns log on")

            # --- big list -----------------------------------------------------
            t0 = time.time()
            r = console(vm, "dns list add big", 4)
            el = time.time() - t0
            check("100000 dominios" in r, f"100,000-domain list ({len(big) // 1024} KiB) loaded")
            check(addr(ask(dns_port, f"bulk99999.ads{99999 % 97}.example")) == ["0.0.0.0"], "lookup in the big list")
        finally:
            vm.stop()

        # --- persistence --------------------------------------------------
        vm, ok = boot(disk, dns_port)
        try:
            out = vm.output()
            check(ok and "2 list(s), 100006 domains" in out, "after reboot both lists are loaded again")
            check("no queries logged" in console(vm, "dns log"), "the query log was only in RAM")
            check(addr(ask(dns_port, "x.ads.blocked.test")) == ["0.0.0.0"] and addr(ask(dns_port, "mine.example")) == ["0.0.0.0"]
                  and addr(ask(dns_port, "dns.google")) == ["0.0.0.0"] and addr(ask(dns_port, "good.ads.blocked.test")) == ["10.9.9.9"],
                  "lists, block and allow lists, DoH setting and upstream kept")
            r = console(vm, "dns list delete big")
            check("eliminada" in r and addr(ask(dns_port, "bulk7.ads7.example")) != ["0.0.0.0"], "list deleted: it no longer blocks")
            # rate limit last: it locks this client out for a minute
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for i in range(1100):
                s.sendto(query("ads.blocked.test", qid=i)[1], ("127.0.0.1", dns_port))
                if i % 50 == 0:
                    time.sleep(0.05)
            s.close()
            time.sleep(2)
            check(stat(vm, "rate") > 0, f"per-client limit: {stat(vm, 'rate')} queries over 1000/min dropped")
            m = vm.send("fsck", 1)
            vm.wait_for("data: ", 300, m)
            check("fsck: CLEAN" in vm.since(m), "kernel fsck clean")
        finally:
            vm.stop()
        r = redsea_fsck.fsck(disk)
        check(not r["errors"], "host fsck clean")
    finally:
        up.close()
        shutil.rmtree(tmp, ignore_errors=True)
    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED")
        sys.exit(1)
    print("All checks passed")


if __name__ == "__main__":
    main()
