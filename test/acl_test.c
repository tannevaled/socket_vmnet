/* Offline unit test for the stateless ACL engine.
 *
 *   clang -I.. -O0 -g -fprofile-instr-generate -fcoverage-mapping \
 *       ../acl.c acl_test.c -o acl_test && ./acl_test
 *
 * Exercises the JSON parser and the matcher; needs neither vmnet nor root.
 * Aims for full line coverage of acl.c (the defensive malloc-failure branches
 * cannot be hit without fault injection). */
#include <arpa/inet.h>
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

static struct acl *load_json(const char *json) { return acl_parse(json, strlen(json)); }

#ifdef ACL_FAULT_INJECT
extern int acl_alloc_budget;
#endif

static const uint8_t MAC_A[6] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01};
static const uint8_t MAC_B[6] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x02};

/* Build an ethernet + IPv4 + L4 frame. proto is 6 (tcp), 17 (udp) or 1 (icmp).
 * If l4 is false, no transport header is appended (truncated). */
static size_t build_ip(uint8_t *buf, const uint8_t smac[6], const uint8_t dmac[6], uint8_t proto,
                       uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, bool l4,
                       uint8_t ihl_words) {
  memcpy(buf, dmac, 6);
  memcpy(buf + 6, smac, 6);
  buf[12] = 0x08;
  buf[13] = 0x00; /* IPv4 */
  uint8_t *ip = buf + 14;
  size_t ihl = (size_t)ihl_words * 4;
  memset(ip, 0, ihl);
  ip[0] = (uint8_t)(0x40 | ihl_words);
  ip[9] = proto;
  ip[12] = (uint8_t)(sip >> 24);
  ip[13] = (uint8_t)(sip >> 16);
  ip[14] = (uint8_t)(sip >> 8);
  ip[15] = (uint8_t)sip;
  ip[16] = (uint8_t)(dip >> 24);
  ip[17] = (uint8_t)(dip >> 16);
  ip[18] = (uint8_t)(dip >> 8);
  ip[19] = (uint8_t)dip;
  if (!l4)
    return 14 + ihl;
  uint8_t *l4p = ip + ihl;
  l4p[0] = (uint8_t)(sport >> 8);
  l4p[1] = (uint8_t)sport;
  l4p[2] = (uint8_t)(dport >> 8);
  l4p[3] = (uint8_t)dport;
  return 14 + ihl + 4;
}

/* Build an ethernet + IPv6 + L4 frame. nh is the next-header (6/17/58/...). */
static size_t build_ip6(uint8_t *buf, const uint8_t smac[6], const uint8_t dmac[6], uint8_t nh,
                        const char *sip, const char *dip, uint16_t sport, uint16_t dport, bool l4) {
  memcpy(buf, dmac, 6);
  memcpy(buf + 6, smac, 6);
  buf[12] = 0x86;
  buf[13] = 0xDD;
  uint8_t *ip6 = buf + 14;
  memset(ip6, 0, 40);
  ip6[0] = 0x60; /* version 6 */
  ip6[6] = nh;
  inet_pton(AF_INET6, sip, ip6 + 8);
  inet_pton(AF_INET6, dip, ip6 + 24);
  if (!l4)
    return 14 + 40;
  uint8_t *l4p = ip6 + 40;
  l4p[0] = (uint8_t)(sport >> 8);
  l4p[1] = (uint8_t)sport;
  l4p[2] = (uint8_t)(dport >> 8);
  l4p[3] = (uint8_t)dport;
  return 14 + 40 + 4;
}

#define IP(a, b, c, d) (((uint32_t)(a) << 24) | ((b) << 16) | ((c) << 8) | (d))
#define TCP(buf, sm, dm, sip, dip, sp, dp) build_ip(buf, sm, dm, 6, sip, dip, sp, dp, true, 5)

int main(void) {
  uint8_t f[128];
  size_t n;

  /* ---- JSON parser coverage ---- */

  /* All string escapes (in an ignored "c" key). */
  {
    struct acl *acl =
        load_json("{\"c\":\"\\\"\\\\\\/\\b\\f\\n\\r\\t\",\"default_action\":\"deny\"}");
    check("escapes parse, default deny", acl != NULL, true);
    acl_destroy(acl);
  }
  /* \u escapes: 1-byte (A), 2-byte (e-acute), 3-byte (CJK); upper + lower hex. */
  {
    struct acl *acl = load_json("{\"c\":\"\\u0041\\u00E9\\u4e2D\"}");
    check("\\u escapes parse", acl != NULL, true);
    acl_destroy(acl);
  }
  /* numbers, bool, null, nested array as ignored values. */
  {
    struct acl *acl = load_json("{\"a\":true,\"b\":false,\"n\":null,\"arr\":[1,2,[3]],\"f\":1.5}");
    check("scalars/array parse", acl != NULL, true);
    acl_destroy(acl);
  }
  /* Root is an array: jget on a non-object returns NULL -> 0 rules. */
  {
    struct acl *acl = load_json("[]");
    check("array root loads empty", acl != NULL, true);
    n = TCP(f, MAC_A, MAC_B, IP(1, 2, 3, 4), IP(5, 6, 7, 8), 1, 2);
    check("array-root allows", acl_allows(acl, ACL_EGRESS, f, n), true);
    acl_destroy(acl);
  }
  /* Empty rules array. */
  {
    struct acl *acl = load_json("{\"rules\":[]}");
    check("empty rules loads", acl != NULL, true);
    acl_destroy(acl);
  }

  /* Malformed JSON variants -> load fails. */
  check("invalid escape", load_json("{\"c\":\"\\x\"}") == NULL, true);
  check("short \\u", load_json("{\"c\":\"\\u12\"}") == NULL, true);
  check("bad \\u hex", load_json("{\"c\":\"\\uzzzz\"}") == NULL, true);
  check("unterminated string", load_json("{\"c\":\"abc") == NULL, true);
  check("bad literal", load_json("{\"x\":tru}") == NULL, true);
  check("missing value", load_json("{\"x\":}") == NULL, true);
  check("missing colon", load_json("{\"x\" 1}") == NULL, true);
  check("trailing junk after key", load_json("{\"x\":1 \"y\":2}") == NULL, true);
  check("array missing close", load_json("{\"a\":[1,2") == NULL, true);
  check("array bad sep", load_json("{\"a\":[1 2]}") == NULL, true);
  check("array bad element", load_json("{\"a\":[tru]}") == NULL, true);
  check("non-string key", load_json("{123:1}") == NULL, true);
  check("object missing close", load_json("{\"x\":1") == NULL, true);
  check("empty input", load_json("") == NULL, true);
  check("nonexistent file", acl_load("/tmp/does/not/exist.json") == NULL, true);

  /* ---- rule field parsing coverage ---- */

  check("missing action", load_json("{\"rules\":[{}]}") == NULL, true);
  check("bad action", load_json("{\"rules\":[{\"action\":\"x\"}]}") == NULL, true);
  check("rule not object", load_json("{\"rules\":[123]}") == NULL, true);
  check("bad default_action",
        load_json("{\"default_action\":\"x\",\"rules\":[{\"action\":\"allow\"}]}") == NULL, true);
  check("bad direction",
        load_json("{\"rules\":[{\"action\":\"allow\",\"direction\":\"x\"}]}") == NULL, true);
  check("bad src_mac", load_json("{\"rules\":[{\"action\":\"allow\",\"src_mac\":\"zz\"}]}") == NULL,
        true);
  check("bad dst_mac", load_json("{\"rules\":[{\"action\":\"allow\",\"dst_mac\":\"zz\"}]}") == NULL,
        true);
  check("mac out of range",
        load_json("{\"rules\":[{\"action\":\"allow\",\"src_mac\":\"de:ad:be:ef:00:1ff\"}]}") ==
            NULL,
        true);
  check("bad src_cidr",
        load_json("{\"rules\":[{\"action\":\"allow\",\"src_cidr\":\"999.0.0.0/8\"}]}") == NULL,
        true);
  check("cidr bits>32",
        load_json("{\"rules\":[{\"action\":\"allow\",\"dst_cidr\":\"10.0.0.0/40\"}]}") == NULL,
        true);
  check("cidr too few octets",
        load_json("{\"rules\":[{\"action\":\"allow\",\"src_cidr\":\"10.0.0/8\"}]}") == NULL, true);
  check("bad proto", load_json("{\"rules\":[{\"action\":\"allow\",\"proto\":\"sctp\"}]}") == NULL,
        true);
  check("bad port type",
        load_json("{\"rules\":[{\"action\":\"allow\",\"dst_port\":\"x\"}]}") == NULL, true);
  check("port array wrong arity",
        load_json("{\"rules\":[{\"action\":\"allow\",\"dst_port\":[1]}]}") == NULL, true);

  /* Valid rule with every field set + direction/proto variants + cidr/0. */
  {
    struct acl *acl =
        load_json("{\"default_action\":\"allow\",\"rules\":["
                  "{\"action\":\"deny\",\"direction\":\"any\",\"src_mac\":\"de:ad:be:ef:00:01\","
                  "\"dst_mac\":\"de:ad:be:ef:00:02\",\"src_cidr\":\"0.0.0.0/0\","
                  "\"dst_cidr\":\"10.0.0.0/8\",\"proto\":\"tcp\","
                  "\"src_port\":[1,65535],\"dst_port\":80}]}");
    check("full rule loads", acl != NULL, true);
    n = TCP(f, MAC_A, MAC_B, IP(192, 168, 1, 1), IP(10, 0, 0, 5), 1000, 80);
    check("full rule matches (egress)", acl_allows(acl, ACL_EGRESS, f, n), false);
    check("full rule matches (ingress, dir any)", acl_allows(acl, ACL_INGRESS, f, n), false);
    acl_destroy(acl);
  }

  /* ---- matcher branch coverage ---- */

  /* default deny + allow icmp ingress. */
  {
    struct acl *acl =
        load_json("{\"default_action\":\"deny\",\"rules\":["
                  "{\"action\":\"allow\",\"direction\":\"ingress\",\"proto\":\"icmp\"}]}");
    n = build_ip(f, MAC_A, MAC_B, 1, IP(1, 1, 1, 1), IP(2, 2, 2, 2), 0, 0, false, 5);
    check("icmp ingress allowed", acl_allows(acl, ACL_INGRESS, f, n), true);
    check("icmp egress denied (default)", acl_allows(acl, ACL_EGRESS, f, n), false);
    acl_destroy(acl);
  }
  /* has_dport but icmp frame -> rule skipped, falls to default allow. */
  {
    struct acl *acl = load_json("{\"default_action\":\"allow\",\"rules\":["
                                "{\"action\":\"deny\",\"proto\":\"any\",\"dst_port\":80}]}");
    n = build_ip(f, MAC_A, MAC_B, 1, IP(1, 1, 1, 1), IP(2, 2, 2, 2), 0, 0, false, 5);
    check("dport rule skips portless icmp", acl_allows(acl, ACL_EGRESS, f, n), true);
    acl_destroy(acl);
  }
  /* src_port match. */
  {
    struct acl *acl = load_json("{\"default_action\":\"allow\",\"rules\":["
                                "{\"action\":\"deny\",\"src_port\":[5000,6000]}]}");
    n = TCP(f, MAC_A, MAC_B, IP(1, 1, 1, 1), IP(2, 2, 2, 2), 5500, 80);
    check("src_port in range denied", acl_allows(acl, ACL_EGRESS, f, n), false);
    n = TCP(f, MAC_A, MAC_B, IP(1, 1, 1, 1), IP(2, 2, 2, 2), 80, 80);
    check("src_port out of range allowed", acl_allows(acl, ACL_EGRESS, f, n), true);
    acl_destroy(acl);
  }
  /* Non-IPv4 / runt / malformed IPv4 are always allowed (default deny). */
  {
    struct acl *acl = load_json("{\"default_action\":\"deny\"}");
    /* ARP */
    memset(f, 0, sizeof(f));
    f[12] = 0x08;
    f[13] = 0x06;
    check("ARP allowed", acl_allows(acl, ACL_EGRESS, f, 60), true);
    /* runt (<14) */
    check("runt allowed", acl_allows(acl, ACL_EGRESS, f, 8), true);
    /* IPv4 ethertype but truncated IP header (<20) */
    f[12] = 0x08;
    f[13] = 0x00;
    check("short IP allowed", acl_allows(acl, ACL_EGRESS, f, 20), true);
    /* IHL < 20 (0x44 => 16 bytes) but enough total bytes to pass the iplen>=20
     * check, so the ihl<20 branch is the one that fires. */
    n = build_ip(f, MAC_A, MAC_B, 6, IP(1, 1, 1, 1), IP(2, 2, 2, 2), 1, 2, true, 4);
    check("bad IHL allowed", acl_allows(acl, ACL_EGRESS, f, n), true);
    /* tcp but no L4 header present -> ports unread, but a portless rule denies */
    acl_destroy(acl);
  }
  /* tcp frame, no L4 bytes -> sport/dport stay -1; a MAC rule still applies. */
  {
    struct acl *acl = load_json("{\"default_action\":\"allow\",\"rules\":["
                                "{\"action\":\"deny\",\"src_mac\":\"de:ad:be:ef:00:01\"}]}");
    n = build_ip(f, MAC_A, MAC_B, 6, IP(1, 1, 1, 1), IP(2, 2, 2, 2), 0, 0, false, 5);
    check("portless tcp matched by mac", acl_allows(acl, ACL_EGRESS, f, n), false);
    acl_destroy(acl);
  }
  /* udp proto + explicit egress direction. */
  {
    struct acl *acl = load_json("{\"default_action\":\"allow\",\"rules\":["
                                "{\"action\":\"deny\",\"direction\":\"egress\",\"proto\":\"udp\","
                                "\"dst_port\":53}]}");
    n = build_ip(f, MAC_A, MAC_B, 17, IP(1, 1, 1, 1), IP(8, 8, 8, 8), 1, 53, true, 5);
    check("udp/53 egress denied", acl_allows(acl, ACL_EGRESS, f, n), false);
    acl_destroy(acl);
  }

  /* Each present-but-non-matching field exercises its "continue". */
  {
    struct acl *acl =
        load_json("{\"default_action\":\"allow\",\"rules\":["
                  "{\"action\":\"deny\",\"src_mac\":\"de:ad:be:ef:00:02\"}," /* src_mac mismatch */
                  "{\"action\":\"deny\",\"dst_mac\":\"de:ad:be:ef:00:09\"}," /* dst_mac mismatch */
                  "{\"action\":\"deny\",\"src_cidr\":\"172.16.0.0/12\"},"    /* src_cidr mismatch */
                  "{\"action\":\"deny\",\"dst_cidr\":\"10.0.0.0/8\"},"       /* dst_cidr mismatch */
                  "{\"action\":\"deny\",\"proto\":\"udp\"}]}");              /* proto mismatch */
    n = TCP(f, MAC_A, MAC_B, IP(192, 168, 1, 1), IP(8, 8, 8, 8), 1, 80);
    check("all rules skipped -> default allow", acl_allows(acl, ACL_EGRESS, f, n), true);
    acl_destroy(acl);
  }

  /* String-escape error edges. */
  check("backslash at end", load_json("{\"c\":\"x\\") == NULL, true);
  check("truncated \\u", load_json("{\"c\":\"\\u1") == NULL, true);

  /* acl_load: a malformed file -> acl_parse fails inside the wrapper. */
  {
    FILE *fp = fopen("/tmp/acl_test_bad.json", "wb");
    if (fp != NULL) {
      fputs("{not json", fp);
      fclose(fp);
    }
    check("acl_load malformed file", acl_load("/tmp/acl_test_bad.json") == NULL, true);
  }

#ifdef ACL_FAULT_INJECT
  /* acl_load's own buffer allocation failing. */
  {
    FILE *fp = fopen("/tmp/acl_test_real2.json", "wb");
    if (fp != NULL) {
      fputs("{}", fp);
      fclose(fp);
    }
    acl_alloc_budget = 0;
    check("acl_load handles malloc failure", acl_load("/tmp/acl_test_real2.json") == NULL, true);
    acl_alloc_budget = -1;
  }
  /* Deterministic OOM at the number node's first allocation. */
  acl_alloc_budget = 0;
  check("number alloc failure", acl_parse("123", 3) == NULL, true);
  acl_alloc_budget = -1;
#endif

  /* ---- IPv6 ---- */

  /* deny egress to 2001:db8::/32 tcp/443; family-scoped. */
  {
    struct acl *acl = load_json("{\"default_action\":\"allow\",\"rules\":["
                                "{\"action\":\"deny\",\"direction\":\"egress\","
                                "\"dst_cidr\":\"2001:db8::/32\",\"proto\":\"tcp\","
                                "\"dst_port\":443}]}");
    n = build_ip6(f, MAC_A, MAC_B, 6, "2001:db8::2", "2001:db8::1", 5000, 443, true);
    check("v6 in-prefix tcp/443 denied", acl_allows(acl, ACL_EGRESS, f, n), false);
    n = build_ip6(f, MAC_A, MAC_B, 6, "2001:db8::2", "2001:dead::1", 5000, 443, true);
    check("v6 out-of-prefix allowed", acl_allows(acl, ACL_EGRESS, f, n), true);
    /* v4 frame must not match a v6 rule (family mismatch -> rule skipped). */
    n = TCP(f, MAC_A, MAC_B, IP(1, 1, 1, 1), IP(2, 2, 2, 2), 5000, 443);
    check("v4 frame skips v6 rule", acl_allows(acl, ACL_EGRESS, f, n), true);
    acl_destroy(acl);
  }

  /* v6 cidr rule does not match a v4 frame and vice versa. */
  {
    struct acl *acl = load_json("{\"default_action\":\"allow\",\"rules\":["
                                "{\"action\":\"deny\",\"src_cidr\":\"10.0.0.0/8\"}]}");
    n = build_ip6(f, MAC_A, MAC_B, 6, "10::1", "20::1", 1, 2, true);
    check("v6 frame skips v4 rule", acl_allows(acl, ACL_EGRESS, f, n), true);
    acl_destroy(acl);
  }

  /* icmpv6 proto + truncated v6 frame. */
  {
    struct acl *acl = load_json("{\"default_action\":\"deny\",\"rules\":["
                                "{\"action\":\"allow\",\"proto\":\"icmpv6\"}]}");
    n = build_ip6(f, MAC_A, MAC_B, 58, "fe80::1", "fe80::2", 0, 0, false);
    check("icmpv6 allowed", acl_allows(acl, ACL_EGRESS, f, n), true);
    /* truncated v6 (no full 40-byte header) -> allowed regardless of default. */
    check("short v6 allowed", acl_allows(acl, ACL_EGRESS, f, 14 + 20), true);
    acl_destroy(acl);
  }

  /* NULL acl always allows. */
  check("NULL acl allows", acl_allows(NULL, ACL_EGRESS, f, 14), true);

  /* src_port rule on a portless (icmp) frame: has_sport && sport<0 -> skip. */
  {
    struct acl *acl = load_json("{\"default_action\":\"allow\",\"rules\":["
                                "{\"action\":\"deny\",\"src_port\":22}]}");
    n = build_ip(f, MAC_A, MAC_B, 1, IP(1, 1, 1, 1), IP(2, 2, 2, 2), 0, 0, false, 5);
    check("src_port rule skips portless", acl_allows(acl, ACL_EGRESS, f, n), true);
    acl_destroy(acl);
  }

  /* acl_load: real file (covers the file-reading wrapper happy path). */
  {
    FILE *fp = fopen("/tmp/acl_test_real.json", "wb");
    if (fp != NULL) {
      fputs("{\"default_action\":\"deny\"}", fp);
      fclose(fp);
    }
    struct acl *acl = acl_load("/tmp/acl_test_real.json");
    check("acl_load reads a real file", acl != NULL, true);
    acl_destroy(acl);
  }
  /* acl_load: fopen failure path. */
  check("acl_load missing file", acl_load("/tmp/socket_vmnet/no/such.json") == NULL, true);

#ifdef ACL_FAULT_INJECT
  /* Sweep allocation failures across every site of a complex parse: each must
   * be handled gracefully (NULL, no crash/leak under ASan). This exercises the
   * defensive out-of-memory branches. */
  {
    const char *complex =
        "{\"default_action\":\"deny\",\"rules\":["
        "{\"action\":\"allow\",\"src_mac\":\"de:ad:be:ef:00:01\",\"dst_mac\":\"de:ad:be:ef:00:02\","
        "\"src_cidr\":\"0.0.0.0/0\",\"dst_cidr\":\"10.0.0.0/8\",\"proto\":\"tcp\","
        "\"src_port\":[1,2],\"dst_port\":80},{\"action\":\"deny\",\"arr\":[1,2,3]}]}";
    int ok = 0, failed = 0;
    for (int k = 0; k < 300; k++) {
      acl_alloc_budget = k;
      struct acl *a = acl_parse(complex, strlen(complex));
      if (a == NULL)
        failed++;
      else
        ok++;
      acl_destroy(a);
    }
    acl_alloc_budget = -1;
    check("alloc-fault sweep saw failures", failed > 0, true);
    check("alloc-fault sweep eventually succeeds", ok > 0, true);
  }
#endif

  if (failures == 0) {
    fprintf(stderr, "\nAll ACL tests passed.\n");
    return 0;
  }
  fprintf(stderr, "\n%d ACL test(s) FAILED.\n", failures);
  return 1;
}
