/* Offline unit test for the HCL->JSON policy compiler (hcl.c) and hcl_load.
 *
 *   clang -I.. -O0 -g ../hcl.c ../acl.c hcl_test.c -o hcl_test && ./hcl_test
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "acl.h"
#include "hcl.h"

bool debug = false; /* referenced by log.h */

static int failures = 0;
static void check(const char *name, bool ok) {
  if (!ok) {
    fprintf(stderr, "FAIL: %s\n", name);
    failures++;
  } else {
    fprintf(stderr, "ok:   %s\n", name);
  }
}

static char *to_json(const char *hcl) { return hcl_to_json(hcl, strlen(hcl)); }
static bool has(const char *hay, const char *needle) { return strstr(hay, needle) != NULL; }

/* Write a malformed policy and try to hcl_load it (covers the compile-failure
 * path of hcl_load). */
static struct acl *load_bad_hcl(void) {
  FILE *fp = fopen("/tmp/hcl_bad.hcl", "wb");
  if (fp) {
    fputs("widget {}\n", fp);
    fclose(fp);
  }
  return hcl_load("/tmp/hcl_bad.hcl");
}

#define IP(a, b, c, d) (((uint32_t)(a) << 24) | ((b) << 16) | ((c) << 8) | (d))
static const uint8_t MAC1[6] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01};
static const uint8_t MAC2[6] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x02};

static size_t tcp(uint8_t *buf, const uint8_t smac[6], uint16_t dport) {
  static const uint8_t dmac[6] = {0x02, 0, 0, 0, 0, 0x99};
  memcpy(buf, dmac, 6);
  memcpy(buf + 6, smac, 6);
  buf[12] = 0x08;
  buf[13] = 0x00;
  uint8_t *ip = buf + 14;
  memset(ip, 0, 20);
  ip[0] = 0x45;
  ip[9] = 6;
  uint32_t s = IP(192, 168, 1, 5), d = IP(8, 8, 8, 8);
  ip[12] = s >> 24;
  ip[13] = s >> 16;
  ip[14] = s >> 8;
  ip[15] = s;
  ip[16] = d >> 24;
  ip[17] = d >> 16;
  ip[18] = d >> 8;
  ip[19] = d;
  uint8_t *l4 = ip + 20;
  l4[0] = 0x30;
  l4[1] = 0x39; /* sport 12345 */
  l4[2] = (uint8_t)(dport >> 8);
  l4[3] = (uint8_t)dport;
  return 14 + 20 + 4;
}

int main(void) {
  /* Structure: default_action + global rule + expanded group rules. */
  {
    char *j =
        to_json("default_action = \"deny\"\n"
                "group \"web\" {\n"
                "  member_mac = [\"de:ad:be:ef:00:01\", \"de:ad:be:ef:00:02\"]\n"
                "  rule { action = \"allow\" direction = \"ingress\" proto = \"tcp\" "
                "dst_port = 443 }\n"
                "}\n"
                "rule { action = \"deny\" direction = \"egress\" dst_port = [1000, 2000] }\n");
    check("compiles", j != NULL);
    check("has default_action deny", has(j, "\"default_action\":\"deny\""));
    check("group expanded to dst_mac 01", has(j, "\"dst_mac\":\"de:ad:be:ef:00:01\""));
    check("group expanded to dst_mac 02", has(j, "\"dst_mac\":\"de:ad:be:ef:00:02\""));
    check("ingress direction", has(j, "\"direction\":\"ingress\""));
    check("port range preserved", has(j, "\"dst_port\":[1000,2000]"));
    /* and the JSON is accepted by acl_parse */
    struct acl *a = acl_parse(j, strlen(j));
    check("acl_parse accepts emitted JSON", a != NULL);
    acl_destroy(a);
    free(j);
  }

  /* Behavioral round-trip: group rule binds to member src MAC on egress. */
  {
    char *j = to_json("default_action = \"allow\"\n"
                      "group \"db\" {\n"
                      "  member_mac = [\"de:ad:be:ef:00:01\"]\n"
                      "  rule { action = \"deny\" direction = \"egress\" proto = \"tcp\" "
                      "dst_port = 22 }\n"
                      "}\n");
    struct acl *a = acl_parse(j, strlen(j));
    check("policy parsed", a != NULL);
    uint8_t f[64];
    size_t n = tcp(f, MAC1, 22);
    check("member MAC tcp/22 egress denied", !acl_allows(a, ACL_EGRESS, f, n));
    n = tcp(f, MAC2, 22);
    check("non-member tcp/22 egress allowed", acl_allows(a, ACL_EGRESS, f, n));
    n = tcp(f, MAC1, 80);
    check("member tcp/80 egress allowed", acl_allows(a, ACL_EGRESS, f, n));
    acl_destroy(a);
    free(j);
  }

  /* Comments and whitespace are ignored. */
  {
    char *j = to_json("# a comment\n// another\n/* block */ default_action = \"allow\"\n");
    check("comments ignored", j != NULL && has(j, "\"default_action\":\"allow\""));
    free(j);
  }

  /* hcl_load from a file. */
  {
    FILE *fp = fopen("/tmp/hcl_test.hcl", "wb");
    if (fp) {
      fputs("default_action = \"deny\"\nrule { action = \"allow\" proto = \"icmp\" }\n", fp);
      fclose(fp);
    }
    struct acl *a = hcl_load("/tmp/hcl_test.hcl");
    check("hcl_load reads + compiles", a != NULL);
    acl_destroy(a);
    check("hcl_load missing file", hcl_load("/tmp/no/such.hcl") == NULL);
  }

  /* A global rule exercising every field + a group with explicit egress and
   * ingress rules (covers all slot assignments and emit branches). */
  {
    char *j = to_json(
        "group \"g\" {\n"
        "  member_mac = [\"de:ad:be:ef:00:01\"]\n"
        "  rule { action = \"deny\" direction = \"egress\" dst_cidr = \"10.0.0.0/8\" }\n"
        "  rule { action = \"allow\" direction = \"ingress\" proto = \"tcp\" dst_port = 22 }\n"
        "}\n"
        "rule { action = \"deny\" src_mac = \"de:ad:be:ef:00:09\" "
        "dst_mac = \"de:ad:be:ef:00:0a\" src_cidr = \"192.168.0.0/16\" "
        "dst_cidr = \"0.0.0.0/0\" proto = \"udp\" src_port = 53 dst_port = [1, 2] }\n");
    check("all-fields rule compiles", j != NULL);
    check("egress binds src_mac",
          has(j, "\"direction\":\"egress\",\"src_mac\":\"de:ad:be:ef:00:01\""));
    check("ingress binds dst_mac",
          has(j, "\"direction\":\"ingress\",\"dst_mac\":\"de:ad:be:ef:00:01\""));
    check("global rule src_cidr", has(j, "\"src_cidr\":\"192.168.0.0/16\""));
    check("global rule proto udp", has(j, "\"proto\":\"udp\""));
    struct acl *a = acl_parse(j, strlen(j));
    check("all-fields acl_parse ok", a != NULL);
    acl_destroy(a);
    free(j);
  }

  /* Large policy: forces the output buffer to grow past its initial capacity. */
  {
    char hcl[4096];
    int off = snprintf(hcl, sizeof(hcl), "group \"big\" {\n  member_mac = [");
    for (int i = 0; i < 12; i++)
      off += snprintf(hcl + off, sizeof(hcl) - off, "%s\"02:00:00:00:00:%02x\"", i ? "," : "", i);
    off += snprintf(hcl + off, sizeof(hcl) - off,
                    "]\n  rule { action = \"deny\" direction = \"egress\" proto = \"tcp\" "
                    "dst_port = 22 }\n}\n");
    char *j = to_json(hcl);
    check("large policy compiles (buffer grows)", j != NULL && strlen(j) > 256);
    free(j);
  }

  /* Over-long tokens -> lexer error. */
  {
    char big[400];
    memset(big, 'a', sizeof(big));
    big[sizeof(big) - 1] = '\0';
    char hcl[512];
    snprintf(hcl, sizeof(hcl), "default_action = \"%s\"", big);
    check("err: string too long", to_json(hcl) == NULL);
    snprintf(hcl, sizeof(hcl), "%s = \"x\"", big);
    check("err: ident too long", to_json(hcl) == NULL);
  }

  /* More rule-level parse errors. */
  check("err: rule attr missing =", to_json("rule { action \"allow\" }") == NULL);
  check("err: rule attr missing value", to_json("rule { action = }") == NULL);
  check("err: rule attr value is block", to_json("rule { action = { } }") == NULL);
  check("err: list bad element", to_json("rule { dst_port = [ { ] }") == NULL);
  check("err: member entry not string", to_json("group \"g\" { member_mac = [1] }") == NULL);
  check("err: group body non-ident", to_json("group \"g\" { = }") == NULL);
  check("err: member_mac missing =", to_json("group \"g\" { member_mac [1] }") == NULL);
  check("err: group rule missing brace",
        to_json("group \"g\" { member_mac = [\"x\"] rule action = \"a\" }") == NULL);
  {
    char big[400];
    memset(big, '9', sizeof(big));
    big[sizeof(big) - 1] = '\0';
    char hcl[512];
    snprintf(hcl, sizeof(hcl), "rule { action = \"allow\" dst_port = %s }", big);
    check("err: number too long", to_json(hcl) == NULL);
  }
  check("err: hcl_load malformed file", load_bad_hcl() == NULL);

  /* Error cases. */
  check("err: unknown top keyword", to_json("widget {}") == NULL);
  check("err: missing = ", to_json("default_action \"deny\"") == NULL);
  check("err: default not string", to_json("default_action = 5") == NULL);
  check("err: unknown rule attr", to_json("rule { bogus = \"x\" }") == NULL);
  check("err: rule missing brace", to_json("rule action = \"allow\"") == NULL);
  check("err: group before member", to_json("group \"g\" { rule { action = \"deny\" } }") == NULL);
  check("err: member not list", to_json("group \"g\" { member_mac = \"x\" }") == NULL);
  check("err: unterminated string", to_json("default_action = \"den") == NULL);
  check("err: unknown group attr", to_json("group \"g\" { widget = 1 }") == NULL);

  if (failures == 0) {
    fprintf(stderr, "\nAll hcl tests passed.\n");
    return 0;
  }
  fprintf(stderr, "\n%d hcl test(s) FAILED.\n", failures);
  return 1;
}
