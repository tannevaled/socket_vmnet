/* Offline unit test for the stateless ACL engine.
 *
 *   clang -I.. -O2 -Wall -Wextra ../acl.c acl_test.c -o acl_test && ./acl_test
 *
 * Exercises the JSON parser and the matcher; needs neither vmnet nor root. */
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "acl.h"

bool debug = false; /* referenced by log.h via acl.c */

static int failures = 0;

static void check(const char *name, bool got, bool want) {
  if (got != want) {
    fprintf(stderr, "FAIL: %s (got %d, want %d)\n", name, got, want);
    failures++;
  } else {
    fprintf(stderr, "ok:   %s\n", name);
  }
}

static struct acl *load_json(const char *json) {
  char path[] = "/tmp/acl_test_XXXXXX.json";
  /* mkstemps keeps the .json suffix; fall back to a fixed path if unavailable */
  FILE *fp = fopen("/tmp/acl_test_input.json", "wb");
  (void)path;
  if (fp == NULL)
    return NULL;
  fwrite(json, 1, strlen(json), fp);
  fclose(fp);
  return acl_load("/tmp/acl_test_input.json");
}

static const uint8_t MAC_A[6] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01};
static const uint8_t MAC_B[6] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x02};

/* Build an ethernet + IPv4 + TCP/UDP frame. proto is 6 (tcp) or 17 (udp). */
static size_t build_ip(uint8_t *buf, const uint8_t smac[6], const uint8_t dmac[6], uint8_t proto,
                       uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) {
  memcpy(buf, dmac, 6);
  memcpy(buf + 6, smac, 6);
  buf[12] = 0x08;
  buf[13] = 0x00; /* IPv4 */
  uint8_t *ip = buf + 14;
  memset(ip, 0, 20);
  ip[0] = 0x45; /* version 4, IHL 5 */
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
  l4[0] = (uint8_t)(sport >> 8);
  l4[1] = (uint8_t)sport;
  l4[2] = (uint8_t)(dport >> 8);
  l4[3] = (uint8_t)dport;
  return 14 + 20 + 4;
}

#define IP(a, b, c, d) (((uint32_t)(a) << 24) | ((b) << 16) | ((c) << 8) | (d))

int main(void) {
  uint8_t f[128];
  size_t n;

  /* 1. No rules, default allow. */
  {
    struct acl *acl = load_json("{}");
    n = build_ip(f, MAC_A, MAC_B, 6, IP(192, 168, 105, 2), IP(8, 8, 8, 8), 12345, 22);
    check("empty-acl allows", acl_allows(acl, ACL_EGRESS, f, n), true);
    acl_destroy(acl);
  }

  /* 2. Deny egress to TCP/22; allow others; ingress unaffected (dir mismatch). */
  {
    struct acl *acl = load_json("{\"default_action\":\"allow\",\"rules\":["
                                "{\"action\":\"deny\",\"direction\":\"egress\","
                                "\"proto\":\"tcp\",\"dst_port\":22}]}");
    n = build_ip(f, MAC_A, MAC_B, 6, IP(192, 168, 105, 2), IP(8, 8, 8, 8), 12345, 22);
    check("deny tcp/22 egress", acl_allows(acl, ACL_EGRESS, f, n), false);
    check("ssh ingress still allowed", acl_allows(acl, ACL_INGRESS, f, n), true);
    n = build_ip(f, MAC_A, MAC_B, 6, IP(192, 168, 105, 2), IP(8, 8, 8, 8), 12345, 80);
    check("tcp/80 egress allowed", acl_allows(acl, ACL_EGRESS, f, n), true);
    acl_destroy(acl);
  }

  /* 3. default deny, allow only TCP/443 egress. */
  {
    struct acl *acl = load_json("{\"default_action\":\"deny\",\"rules\":["
                                "{\"action\":\"allow\",\"direction\":\"egress\","
                                "\"proto\":\"tcp\",\"dst_port\":443}]}");
    n = build_ip(f, MAC_A, MAC_B, 6, IP(192, 168, 105, 2), IP(1, 1, 1, 1), 33333, 443);
    check("default-deny allows 443", acl_allows(acl, ACL_EGRESS, f, n), true);
    n = build_ip(f, MAC_A, MAC_B, 6, IP(192, 168, 105, 2), IP(1, 1, 1, 1), 33333, 8080);
    check("default-deny blocks 8080", acl_allows(acl, ACL_EGRESS, f, n), false);
    acl_destroy(acl);
  }

  /* 4. Per-source-MAC + dst CIDR targeting. */
  {
    struct acl *acl = load_json("{\"default_action\":\"allow\",\"rules\":["
                                "{\"action\":\"deny\",\"src_mac\":\"de:ad:be:ef:00:01\","
                                "\"dst_cidr\":\"10.0.0.0/8\"}]}");
    n = build_ip(f, MAC_A, MAC_B, 6, IP(192, 168, 105, 2), IP(10, 1, 2, 3), 1, 53);
    check("MAC-A to 10/8 denied", acl_allows(acl, ACL_EGRESS, f, n), false);
    n = build_ip(f, MAC_B, MAC_A, 6, IP(192, 168, 105, 3), IP(10, 1, 2, 3), 1, 53);
    check("MAC-B to 10/8 allowed", acl_allows(acl, ACL_EGRESS, f, n), true);
    n = build_ip(f, MAC_A, MAC_B, 6, IP(192, 168, 105, 2), IP(8, 8, 8, 8), 1, 53);
    check("MAC-A to 8.8.8.8 allowed", acl_allows(acl, ACL_EGRESS, f, n), true);
    acl_destroy(acl);
  }

  /* 5. Port range [1000,2000]. */
  {
    struct acl *acl = load_json("{\"default_action\":\"allow\",\"rules\":["
                                "{\"action\":\"deny\",\"proto\":\"udp\","
                                "\"dst_port\":[1000,2000]}]}");
    n = build_ip(f, MAC_A, MAC_B, 17, IP(192, 168, 105, 2), IP(8, 8, 8, 8), 1, 1500);
    check("udp/1500 in range denied", acl_allows(acl, ACL_EGRESS, f, n), false);
    n = build_ip(f, MAC_A, MAC_B, 17, IP(192, 168, 105, 2), IP(8, 8, 8, 8), 1, 2500);
    check("udp/2500 out of range allowed", acl_allows(acl, ACL_EGRESS, f, n), true);
    acl_destroy(acl);
  }

  /* 6. Non-IPv4 (ARP) is always allowed, even under default deny. */
  {
    struct acl *acl = load_json("{\"default_action\":\"deny\"}");
    memset(f, 0, sizeof(f));
    memcpy(f + 6, MAC_A, 6);
    f[12] = 0x08;
    f[13] = 0x06; /* ARP */
    check("ARP allowed under default-deny", acl_allows(acl, ACL_EGRESS, f, 60), true);
    n = build_ip(f, MAC_A, MAC_B, 6, IP(192, 168, 105, 2), IP(8, 8, 8, 8), 1, 80);
    check("IPv4 blocked under default-deny", acl_allows(acl, ACL_EGRESS, f, n), false);
    acl_destroy(acl);
  }

  /* 7. Malformed JSON fails to load. */
  {
    struct acl *acl = load_json("{\"rules\": [ {\"action\": ");
    check("malformed JSON rejected", acl == NULL, true);
    acl_destroy(acl);
  }

  if (failures == 0) {
    fprintf(stderr, "\nAll ACL tests passed.\n");
    return 0;
  }
  fprintf(stderr, "\n%d ACL test(s) FAILED.\n", failures);
  return 1;
}
