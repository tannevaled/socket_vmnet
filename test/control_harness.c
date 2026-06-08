/* Standalone control-plane server for cross-implementation (Go) compat tests.
 *
 *   control_harness <socket-path> <acl-file>
 *
 * Builds a minimal daemon state, seeds an ACL (default deny, allow tcp/80),
 * records a handful of synthetic allow/deny events into the ring, and serves
 * the real control.c protocol on <socket-path> until SIGTERM/SIGINT. The acl
 * file is written with the same ruleset so `reload` works. It needs neither
 * vmnet nor root: control.c uses no vmnet symbols.
 *
 * Built by `make control-harness`; driven by fw-ui's `go test -tags=compat`. */
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "acl.h"
#include "control.h"
#include "daemon.h"

bool debug = false; /* referenced by log.h */

static volatile sig_atomic_t stop_flag = 0;
static void on_sig(int s) {
  (void)s;
  stop_flag = 1;
}

/* ethernet + IPv4 + TCP frame, 10.0.0.s -> 8.8.8.d : sp -> dp */
static size_t mkframe(uint8_t *b, uint8_t s, uint8_t d, uint16_t sp, uint16_t dp) {
  memset(b, 0, 60);
  b[12] = 0x08;
  b[13] = 0x00;
  uint8_t *ip = b + 14;
  ip[0] = 0x45;
  ip[9] = 6; /* tcp */
  ip[12] = 10;
  ip[15] = s;
  ip[16] = 8;
  ip[17] = 8;
  ip[18] = 8;
  ip[19] = d;
  uint8_t *l4 = ip + 20;
  l4[0] = (uint8_t)(sp >> 8);
  l4[1] = (uint8_t)sp;
  l4[2] = (uint8_t)(dp >> 8);
  l4[3] = (uint8_t)dp;
  return 60;
}

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "usage: %s <socket-path> <acl-file>\n", argv[0]);
    return 2;
  }
  const char *sock = argv[1], *aclfile = argv[2];
  const char *seed = "{\"default_action\":\"deny\",\"rules\":["
                     "{\"action\":\"allow\",\"proto\":\"tcp\",\"dst_port\":80}]}";

  FILE *f = fopen(aclfile, "wb");
  if (f != NULL) {
    fputs(seed, f);
    fclose(f);
  }

  signal(SIGTERM, on_sig);
  signal(SIGINT, on_sig);

  static struct cli_options copt;
  memset(&copt, 0, sizeof copt);
  copt.acl_path = (char *)aclfile;

  static struct state st;
  memset(&st, 0, sizeof st);
  st.sem = dispatch_semaphore_create(1);
  st.cliopt = &copt;

  if (!control_set_acl_json(&st, seed, strlen(seed))) {
    fprintf(stderr, "seed failed\n");
    return 1;
  }
  st.control = control_start(&st, sock);
  if (st.control == NULL) {
    fprintf(stderr, "control_start failed\n");
    return 1;
  }

  uint8_t fr[60];
  int rule;
  for (int i = 0; i < 3; i++) { /* allowed tcp/80 */
    size_t n = mkframe(fr, 1, 1, 1234, 80);
    rule = -1;
    bool a = acl_check(st.acl, ACL_EGRESS, fr, n, &rule);
    control_record_event(st.control, ACL_EGRESS, a, rule, fr, (uint32_t)n, 1000 + (uint64_t)i);
  }
  for (int i = 0; i < 2; i++) { /* denied tcp/81 (default) */
    size_t n = mkframe(fr, 1, 1, 1234, 81);
    rule = -1;
    bool a = acl_check(st.acl, ACL_EGRESS, fr, n, &rule);
    control_record_event(st.control, ACL_EGRESS, a, rule, fr, (uint32_t)n, 2000 + (uint64_t)i);
  }

  printf("ready\n");
  fflush(stdout);
  while (!stop_flag)
    sleep(1);

  control_stop(st.control);
  acl_destroy(st.acl);
  free(st.acl_json);
  return 0;
}
