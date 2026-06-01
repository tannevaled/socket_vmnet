/* Offline unit test for the connection tracker.
 *
 *   clang -I.. -O0 -g ../conntrack.c conntrack_test.c -o conntrack_test && ./conntrack_test
 */
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "conntrack.h"

static int failures = 0;
static void check(const char *name, bool got, bool want) {
  if (got != want) {
    fprintf(stderr, "FAIL: %s (got %d, want %d)\n", name, got, want);
    failures++;
  } else {
    fprintf(stderr, "ok:   %s\n", name);
  }
}

static const uint8_t MAC_A[6] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01};
static const uint8_t MAC_B[6] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x02};

#define IP(a, b, c, d) (((uint32_t)(a) << 24) | ((b) << 16) | ((c) << 8) | (d))

static size_t v4(uint8_t *buf, uint8_t proto, uint32_t sip, uint32_t dip, uint16_t sp,
                 uint16_t dp) {
  memcpy(buf, MAC_B, 6);
  memcpy(buf + 6, MAC_A, 6);
  buf[12] = 0x08;
  buf[13] = 0x00;
  uint8_t *ip = buf + 14;
  memset(ip, 0, 20);
  ip[0] = 0x45;
  ip[9] = proto;
  ip[12] = (uint8_t)(sip >> 24);
  ip[13] = (uint8_t)(sip >> 16);
  ip[14] = (uint8_t)(sip >> 8);
  ip[15] = (uint8_t)sip;
  ip[16] = (uint8_t)(dip >> 24);
  ip[17] = (uint8_t)(dip >> 16);
  ip[18] = (uint8_t)(dip >> 8);
  ip[19] = (uint8_t)dip;
  uint8_t *l4 = ip + 20;
  l4[0] = (uint8_t)(sp >> 8);
  l4[1] = (uint8_t)sp;
  l4[2] = (uint8_t)(dp >> 8);
  l4[3] = (uint8_t)dp;
  return 14 + 20 + 4;
}

static size_t v6(uint8_t *buf, uint8_t nh, const char *sip, const char *dip, uint16_t sp,
                 uint16_t dp) {
  memcpy(buf, MAC_B, 6);
  memcpy(buf + 6, MAC_A, 6);
  buf[12] = 0x86;
  buf[13] = 0xDD;
  uint8_t *ip6 = buf + 14;
  memset(ip6, 0, 40);
  ip6[0] = 0x60;
  ip6[6] = nh;
  inet_pton(AF_INET6, sip, ip6 + 8);
  inet_pton(AF_INET6, dip, ip6 + 24);
  uint8_t *l4 = ip6 + 40;
  l4[0] = (uint8_t)(sp >> 8);
  l4[1] = (uint8_t)sp;
  l4[2] = (uint8_t)(dp >> 8);
  l4[3] = (uint8_t)dp;
  return 14 + 40 + 4;
}

int main(void) {
  uint8_t f[128];
  size_t n;

  /* Return traffic of a recorded flow is established (normalized 5-tuple). */
  {
    struct conntrack *ct = conntrack_new(16, 30, 10);
    n = v4(f, 6, IP(192, 168, 1, 2), IP(8, 8, 8, 8), 40000, 443);
    check("new flow not established", conntrack_established(ct, f, n, 100), false);
    conntrack_record(ct, f, n, 100);
    /* reverse direction (server -> client) */
    n = v4(f, 6, IP(8, 8, 8, 8), IP(192, 168, 1, 2), 443, 40000);
    check("reverse is established", conntrack_established(ct, f, n, 101), true);
    conntrack_free(ct);
  }

  /* Expiry (TCP timeout 30s). */
  {
    struct conntrack *ct = conntrack_new(16, 30, 10);
    n = v4(f, 6, IP(10, 0, 0, 1), IP(10, 0, 0, 2), 1234, 80);
    conntrack_record(ct, f, n, 1000);
    n = v4(f, 6, IP(10, 0, 0, 2), IP(10, 0, 0, 1), 80, 1234);
    check("established at timeout boundary", conntrack_established(ct, f, n, 1030), true);
    check("expired past timeout", conntrack_established(ct, f, n, 2000), false);
    conntrack_free(ct);
  }

  /* UDP uses its own (shorter) timeout. */
  {
    struct conntrack *ct = conntrack_new(16, 30, 10);
    n = v4(f, 17, IP(10, 0, 0, 1), IP(10, 0, 0, 2), 5353, 53);
    conntrack_record(ct, f, n, 0);
    n = v4(f, 17, IP(10, 0, 0, 2), IP(10, 0, 0, 1), 53, 5353);
    check("udp expired after 10s", conntrack_established(ct, f, n, 11), false);
    conntrack_free(ct);
  }

  /* Non-TCP/UDP and non-IP are never tracked. */
  {
    struct conntrack *ct = conntrack_new(16, 30, 10);
    n = v4(f, 1, IP(1, 1, 1, 1), IP(2, 2, 2, 2), 0, 0); /* icmp */
    conntrack_record(ct, f, n, 0);
    check("icmp never established", conntrack_established(ct, f, n, 0), false);
    memset(f, 0, sizeof(f));
    f[12] = 0x08;
    f[13] = 0x06; /* ARP */
    conntrack_record(ct, f, 60, 0);
    check("arp never established", conntrack_established(ct, f, 60, 0), false);
    check("NULL ct not established", conntrack_established(NULL, f, 60, 0), false);
    conntrack_free(ct);
  }

  /* Eviction when over capacity. */
  {
    struct conntrack *ct = conntrack_new(2, 1000, 1000);
    size_t n1 = v4(f, 6, IP(1, 0, 0, 1), IP(9, 0, 0, 1), 1, 80);
    conntrack_record(ct, f, n1, 1);
    uint8_t f2[128];
    size_t n2 = v4(f2, 6, IP(1, 0, 0, 2), IP(9, 0, 0, 1), 2, 80);
    conntrack_record(ct, f2, n2, 2);
    uint8_t f3[128];
    size_t n3 = v4(f3, 6, IP(1, 0, 0, 3), IP(9, 0, 0, 1), 3, 80);
    conntrack_record(ct, f3, n3, 3); /* evicts the oldest (flow 1) */
    check("oldest flow evicted", conntrack_established(ct, f, n1, 4), false);
    check("newest flow kept", conntrack_established(ct, f3, n3, 4), true);
    conntrack_free(ct);
  }

  /* IPv6 flow + refresh-in-place on re-record. */
  {
    struct conntrack *ct = conntrack_new(16, 30, 10);
    n = v6(f, 6, "2001:db8::2", "2001:db8::1", 40000, 443);
    conntrack_record(ct, f, n, 100);
    conntrack_record(ct, f, n, 120); /* refresh existing */
    n = v6(f, 6, "2001:db8::1", "2001:db8::2", 443, 40000);
    check("v6 reverse established after refresh", conntrack_established(ct, f, n, 140), true);
    conntrack_free(ct);
  }

  /* Degenerate inputs: capacity 0, NULL handles, untrackable/runt frames. */
  {
    struct conntrack *ct = conntrack_new(0, 30, 10); /* clamped to 1 */
    check("capacity 0 clamped", ct != NULL, true);
    conntrack_record(NULL, f, 0, 0); /* NULL ct: no-op */
    conntrack_record(ct, f, 8, 0);   /* runt frame (len<14): ignored */
    check("runt not established", conntrack_established(ct, f, 8, 0), false);
    /* short IPv4 and short IPv6 headers */
    memset(f, 0, sizeof(f));
    f[12] = 0x08;
    f[13] = 0x00;
    check("short v4 not established", conntrack_established(ct, f, 14 + 10, 0), false);
    n = v4(f, 6, IP(1, 1, 1, 1), IP(2, 2, 2, 2), 1, 2);
    f[14] = 0x44; /* IHL=4 (<20 bytes) */
    check("bad-ihl v4 not established", conntrack_established(ct, f, n, 0), false);
    f[12] = 0x86;
    f[13] = 0xDD;
    check("short v6 not established", conntrack_established(ct, f, 14 + 20, 0), false);
    conntrack_free(ct);
    conntrack_free(NULL); /* NULL free: no-op */
  }

#ifdef CT_FAULT_INJECT
  /* conntrack_new allocation failures (struct, then flows array). */
  {
    extern int ct_alloc_budget;
    ct_alloc_budget = 0;
    check("ct_new struct alloc fail", conntrack_new(16, 30, 10) == NULL, true);
    ct_alloc_budget = 1;
    check("ct_new flows alloc fail", conntrack_new(16, 30, 10) == NULL, true);
    ct_alloc_budget = -1;
  }
#endif

  if (failures == 0) {
    fprintf(stderr, "\nAll conntrack tests passed.\n");
    return 0;
  }
  fprintf(stderr, "\n%d conntrack test(s) FAILED.\n", failures);
  return 1;
}
