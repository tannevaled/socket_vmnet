/* Offline unit test for the firewall control plane (control.c).
 *
 * Drives control_handle() directly against a minimal struct state + a real
 * control object (control_start opens a UNIX socket under /tmp; no client ever
 * connects, we call the request handler in-process). Needs neither vmnet nor
 * root: control.c uses no vmnet symbols. */
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "control.h"
#include "daemon.h"

bool debug = false; /* referenced by log.h via control.c / c-fw */

static int failures = 0;

static void check(const char *name, bool ok) {
  fprintf(stderr, "%s: %s\n", ok ? "ok  " : "FAIL", name);
  if (!ok)
    failures++;
}

/* A response `r` is "successful" if it contains "ok":true. */
static bool has(const char *r, const char *needle) { return r != NULL && strstr(r, needle); }

/* Build an ethernet + IPv4 + TCP/UDP frame (60 bytes min). */
static size_t mkframe(uint8_t *b, uint8_t proto, uint32_t sip, uint32_t dip, uint16_t sp,
                      uint16_t dp) {
  memset(b, 0, 60);
  b[12] = 0x08;
  b[13] = 0x00; /* IPv4 */
  uint8_t *ip = b + 14;
  ip[0] = 0x45; /* v4, IHL 5 */
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
  return 60;
}

#define IP(a, b, c, d) (((uint32_t)(a) << 24) | ((b) << 16) | ((c) << 8) | (d))

static char *handle(struct control *c, const char *req) {
  return control_handle(c, req, strlen(req));
}

int main(void) {
  struct cli_options copt = {0}; /* acl_path NULL: reload should fail */
  struct state st = {0};
  st.sem = dispatch_semaphore_create(1);
  st.cliopt = &copt;

  struct control *ctl = control_start(&st, "/tmp/c-fw-control-test.sock");
  check("control_start", ctl != NULL);
  if (ctl == NULL)
    return 1;

  /* Seed a ruleset: default deny, allow tcp dst 80. */
  const char *seed = "{\"default_action\":\"deny\",\"rules\":["
                     "{\"action\":\"allow\",\"proto\":\"tcp\",\"dst_port\":80}]}";
  check("set_acl seed", control_set_acl_json(&st, seed, strlen(seed)));

  /* Exercise the matcher so the aggregate + per-rule counters move, and record
   * the decisions into the event ring as the data path would. */
  uint8_t f[60];
  size_t n = mkframe(f, 6, IP(10, 0, 0, 1), IP(8, 8, 8, 8), 1234, 80);
  int rule = -1;
  bool a1 = acl_check(st.acl, ACL_EGRESS, f, n, &rule);
  control_record_event(ctl, ACL_EGRESS, a1, rule, f, (uint32_t)n, 1000);
  check("allowed tcp/80", a1 && rule == 0);
  n = mkframe(f, 6, IP(10, 0, 0, 1), IP(8, 8, 8, 8), 1234, 81);
  rule = -1;
  bool a2 = acl_check(st.acl, ACL_EGRESS, f, n, &rule);
  control_record_event(ctl, ACL_EGRESS, a2, rule, f, (uint32_t)n, 1001);
  check("denied tcp/81 (default)", !a2 && rule == -1);

  char *r;

  r = handle(ctl, "{\"cmd\":\"get_stats\"}");
  check("get_stats ok", has(r, "\"ok\":true"));
  check("get_stats egress allow 1", has(r, "\"egress\":{\"allow\":1"));
  check("get_stats has rules+hits", has(r, "\"rules\":[{\"index\":0,\"hits\":1}]"));
  check("get_stats has conntrack", has(r, "\"conntrack\":{\"capacity\":"));
  free(r);

  r = handle(ctl, "{\"cmd\":\"get_events\",\"since\":0}");
  check("get_events ok", has(r, "\"ok\":true"));
  check("get_events next 2", has(r, "\"next\":2"));
  check("get_events allow verdict", has(r, "\"verdict\":\"allow\""));
  check("get_events deny verdict", has(r, "\"verdict\":\"deny\""));
  check("get_events dst ip", has(r, "\"dst\":\"8.8.8.8\""));
  check("get_events dport 80", has(r, "\"dport\":80"));
  free(r);

  r = handle(ctl, "{\"cmd\":\"get_events\",\"since\":2}");
  check("get_events since=next empty", has(r, "\"events\":[]"));
  free(r);

  r = handle(ctl, "{\"cmd\":\"get_rules\"}");
  check("get_rules ok", has(r, "\"ok\":true"));
  check("get_rules format json", has(r, "\"format\":\"json\""));
  check("get_rules has source", has(r, "default_action"));
  free(r);

  r = handle(ctl, "{\"cmd\":\"set_acl\",\"json\":\"{\\\"default_action\\\":\\\"allow\\\"}\"}");
  check("set_acl ok", has(r, "\"ok\":true"));
  check("set_acl rules 0", has(r, "\"rules\":0"));
  free(r);
  r = handle(ctl, "{\"cmd\":\"get_rules\"}");
  check("get_rules reflects swap", has(r, "allow") && !has(r, "dst_port"));
  free(r);

  r = handle(ctl, "{\"cmd\":\"set_acl\",\"json\":\"{ this is not json\"}");
  check("set_acl bad json fails", has(r, "\"ok\":false"));
  free(r);

  r = handle(ctl, "{\"cmd\":\"reset_stats\"}");
  check("reset_stats ok", has(r, "\"ok\":true"));
  free(r);
  r = handle(ctl, "{\"cmd\":\"get_stats\"}");
  check("stats zeroed after reset", has(r, "\"egress\":{\"allow\":0,\"deny\":0"));
  free(r);

  r = handle(ctl, "{\"cmd\":\"reload\"}");
  check("reload fails (no path)", has(r, "\"ok\":false"));
  free(r);

  r = handle(ctl, "{\"cmd\":\"frobnicate\"}");
  check("unknown command", has(r, "\"ok\":false") && has(r, "unknown command"));
  free(r);

  r = handle(ctl, "not even json");
  check("malformed request", has(r, "\"ok\":false"));
  free(r);

  control_stop(ctl);
  acl_destroy(st.acl);
  free(st.acl_json);

  if (failures) {
    fprintf(stderr, "\n%d control test(s) FAILED\n", failures);
    return 1;
  }
  fprintf(stderr, "\nAll control tests passed.\n");
  return 0;
}
