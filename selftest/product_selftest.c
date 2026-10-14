// ============================================================================
// YesOS core self-test image: the core with every optional module that the
// core's own tests exercise (vault, packages, dns) and no product services.
// The DNS filter answers on UDP 53 so tools/test_dns.py can test the engine.
// Built by `make` in the core repository; used by `make test` there.
// ============================================================================

#include "product.h"
#include "kprintf.h"
#include "virtio_net.h"
#include "netcfg.h"
#include "dnsblock.h"

const char* const PRODUCT_NAME = "YesOS core self-test";

static Bool dns_udp(const NetUdpDatagram* d) {
    return dnsblock_udp(d->src_ip, d->src_mac, d->src_port, d->dst_port, d->data, d->len);
}

U0 product_early_init(U0) {
}

U0 product_init(U0) {
    dnsblock_init();
    net_register_udp(0, dns_udp);   // queries on 53 + upstream answers
    netcfg_on_change(dnsblock_refresh_upstream);
}

U0 product_boot_summary(U0) {
    kprintf(" [ OK ] SELF-TEST        : core + vault + packages + dns, no product services\n");
}

U0 product_poll(U0) {
    dnsblock_poll();
}
