/* Offline unit test for cli_options_parse().
 *
 *   clang -I.. -DVERSION='"test"' -O0 -g ../cli.c cli_test.c -o cli_test && ./cli_test
 *
 * Successful parses are exercised in-process; paths that call exit() (errors,
 * --help, --version) are run in a forked child so the test survives. */
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "cli.h"

bool debug = false; /* referenced by log.h via cli.c */

static int failures = 0;
static void check(const char *name, bool ok) {
  if (!ok) {
    fprintf(stderr, "FAIL: %s\n", name);
    failures++;
  } else {
    fprintf(stderr, "ok:   %s\n", name);
  }
}

/* getopt keeps global state; reset it before every parse (macOS needs both). */
static void reset_getopt(void) {
  optind = 1;
  optreset = 1;
}

#define ARGV(...) ((char *[]){"socket_vmnet", __VA_ARGS__, NULL})
#define ARGC(...) ((int)(sizeof(ARGV(__VA_ARGS__)) / sizeof(char *) - 1))

static struct cli_options *parse(int argc, char **argv) {
  reset_getopt();
  return cli_options_parse(argc, argv);
}

/* Run a parse that is expected to exit(); return its exit status. */
static int parse_status(int argc, char **argv) {
  pid_t pid = fork();
  if (pid == 0) {
    freopen("/dev/null", "w", stderr);
    freopen("/dev/null", "w", stdout);
    reset_getopt();
    cli_options_parse(argc, argv);
    _exit(123); /* reached only if it did NOT exit on its own */
  }
  int st = 0;
  waitpid(pid, &st, 0);
  return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

int main(void) {
  /* Defaults. */
  {
    struct cli_options *o = parse(ARGC("/tmp/s.sock"), ARGV("/tmp/s.sock"));
    check("defaults: parsed", o != NULL);
    check("defaults: socket_path", strcmp(o->socket_path, "/tmp/s.sock") == 0);
    check("defaults: group=staff", strcmp(o->socket_group, "staff") == 0);
    check("defaults: mode=shared", o->vmnet_mode == VMNET_SHARED_MODE);
    check("defaults: interface_id generated", !uuid_is_null(o->vmnet_interface_id));
    check("defaults: not isolated", !o->isolated && !o->interface_per_vm && !o->stateful);
    cli_options_destroy(o);
  }

  /* Most options together. */
  {
    struct cli_options *o =
        parse(ARGC("--socket-group=admin", "--vmnet-mode=host", "--vmnet-gateway=192.168.105.1",
                   "--isolated", "--interface-per-vm", "--stateful", "--socket-dgram=/tmp/d.sock",
                   "--acl=/tmp/a.json", "-p", "/tmp/p.pid", "/tmp/s.sock"),
              ARGV("--socket-group=admin", "--vmnet-mode=host", "--vmnet-gateway=192.168.105.1",
                   "--isolated", "--interface-per-vm", "--stateful", "--socket-dgram=/tmp/d.sock",
                   "--acl=/tmp/a.json", "-p", "/tmp/p.pid", "/tmp/s.sock"));
    check("opts: parsed", o != NULL);
    check("opts: group", strcmp(o->socket_group, "admin") == 0);
    check("opts: mode=host", o->vmnet_mode == VMNET_HOST_MODE);
    check("opts: gateway", strcmp(o->vmnet_gateway, "192.168.105.1") == 0);
    check("opts: dhcp-end default .254", strcmp(o->vmnet_dhcp_end, "192.168.105.254") == 0);
    check("opts: mask default", strcmp(o->vmnet_mask, "255.255.255.0") == 0);
    check("opts: flags", o->isolated && o->interface_per_vm && o->stateful);
    check("opts: dgram", strcmp(o->socket_dgram_path, "/tmp/d.sock") == 0);
    check("opts: acl", strcmp(o->acl_path, "/tmp/a.json") == 0);
    check("opts: pidfile", strcmp(o->pidfile, "/tmp/p.pid") == 0);
    cli_options_destroy(o);
  }

  /* Explicit dhcp-end + mask + nat66 + bridged interface + UUIDs. */
  {
    struct cli_options *o = parse(ARGC("--vmnet-mode=bridged", "--vmnet-interface=en0",
                                       "--vmnet-nat66-prefix=fd00::", "/tmp/s.sock"),
                                  ARGV("--vmnet-mode=bridged", "--vmnet-interface=en0",
                                       "--vmnet-nat66-prefix=fd00::", "/tmp/s.sock"));
    check("bridged: parsed", o != NULL);
    check("bridged: mode", o->vmnet_mode == VMNET_BRIDGED_MODE);
    check("bridged: interface", strcmp(o->vmnet_interface, "en0") == 0);
    check("bridged: nat66", strcmp(o->vmnet_nat66_prefix, "fd00::") == 0);
    cli_options_destroy(o);
  }
  {
    struct cli_options *o = parse(
        ARGC("--vmnet-gateway=10.0.0.1", "--vmnet-dhcp-end=10.0.0.100", "--vmnet-mask=255.255.0.0",
             "--vmnet-interface-id=550e8400-e29b-41d4-a716-446655440000", "/tmp/s.sock"),
        ARGV("--vmnet-gateway=10.0.0.1", "--vmnet-dhcp-end=10.0.0.100", "--vmnet-mask=255.255.0.0",
             "--vmnet-interface-id=550e8400-e29b-41d4-a716-446655440000", "/tmp/s.sock"));
    check("explicit dhcp/mask/uuid parsed", o != NULL);
    check("explicit dhcp-end kept", strcmp(o->vmnet_dhcp_end, "10.0.0.100") == 0);
    check("explicit mask kept", strcmp(o->vmnet_mask, "255.255.0.0") == 0);
    cli_options_destroy(o);
  }
  {
    struct cli_options *o = parse(
        ARGC("--vmnet-mode=host", "--vmnet-network-identifier=550e8400-e29b-41d4-a716-446655440000",
             "/tmp/s.sock"),
        ARGV("--vmnet-mode=host", "--vmnet-network-identifier=550e8400-e29b-41d4-a716-446655440000",
             "/tmp/s.sock"));
    check("network-identifier parsed", o != NULL && !uuid_is_null(o->vmnet_network_identifier));
    cli_options_destroy(o);
  }

  /* --vmnet-mode=shared (the switch's shared case). */
  {
    struct cli_options *o = parse(ARGC("--vmnet-mode=shared", "/tmp/s.sock"),
                                  ARGV("--vmnet-mode=shared", "/tmp/s.sock"));
    check("mode=shared", o != NULL && o->vmnet_mode == VMNET_SHARED_MODE);
    cli_options_destroy(o);
  }

  /* Gateway invalid but dhcp-end explicit: skips the dhcp default, fails in the
   * validate section instead. */
  check("invalid gateway in validate",
        parse_status(ARGC("--vmnet-gateway=bad", "--vmnet-dhcp-end=10.0.0.9", "/tmp/s"),
                     ARGV("--vmnet-gateway=bad", "--vmnet-dhcp-end=10.0.0.9", "/tmp/s")) == 1);

  /* cli_options_destroy(NULL) is a no-op. */
  cli_options_destroy(NULL);
  check("destroy NULL ok", true);

  /* --help and --version exit(0). */
  check("--help exits 0", parse_status(ARGC("--help"), ARGV("--help")) == 0);
  check("-h exits 0", parse_status(ARGC("-h"), ARGV("-h")) == 0);
  check("--version exits 0", parse_status(ARGC("--version"), ARGV("--version")) == 0);
  check("-v exits 0", parse_status(ARGC("-v"), ARGV("-v")) == 0);

  /* Error paths exit(1). */
  {
    char *av[] = {"socket_vmnet", NULL};
    check("no socket arg", parse_status(1, av) == 1);
  }
  check("too many args", parse_status(ARGC("a", "b"), ARGV("a", "b")) == 1);
  check("unknown option", parse_status(ARGC("--bogus"), ARGV("--bogus")) == 1);
  check("bad vmnet-mode", parse_status(ARGC("--vmnet-mode=weird", "/tmp/s"),
                                       ARGV("--vmnet-mode=weird", "/tmp/s")) == 1);
  check("bad interface-id", parse_status(ARGC("--vmnet-interface-id=nope", "/tmp/s"),
                                         ARGV("--vmnet-interface-id=nope", "/tmp/s")) == 1);
  check("bad network-identifier",
        parse_status(ARGC("--vmnet-network-identifier=nope", "/tmp/s"),
                     ARGV("--vmnet-network-identifier=nope", "/tmp/s")) == 1);
  check("bridged without interface", parse_status(ARGC("--vmnet-mode=bridged", "/tmp/s"),
                                                  ARGV("--vmnet-mode=bridged", "/tmp/s")) == 1);
  check("dhcp-end without gateway", parse_status(ARGC("--vmnet-dhcp-end=10.0.0.9", "/tmp/s"),
                                                 ARGV("--vmnet-dhcp-end=10.0.0.9", "/tmp/s")) == 1);
  check("mask without gateway", parse_status(ARGC("--vmnet-mask=255.0.0.0", "/tmp/s"),
                                             ARGV("--vmnet-mask=255.0.0.0", "/tmp/s")) == 1);
  check("bridged conflicts gateway",
        parse_status(ARGC("--vmnet-mode=bridged", "--vmnet-interface=en0",
                          "--vmnet-gateway=10.0.0.1", "/tmp/s"),
                     ARGV("--vmnet-mode=bridged", "--vmnet-interface=en0",
                          "--vmnet-gateway=10.0.0.1", "/tmp/s")) == 1);
  check("invalid gateway address", parse_status(ARGC("--vmnet-gateway=not.an.ip", "/tmp/s"),
                                                ARGV("--vmnet-gateway=not.an.ip", "/tmp/s")) == 1);

#ifdef CLI_FAULT_INJECT
  /* calloc failure -> exit(EXIT_FAILURE). */
  {
    extern int cli_alloc_fail;
    pid_t pid = fork();
    if (pid == 0) {
      freopen("/dev/null", "w", stderr);
      reset_getopt();
      cli_alloc_fail = 1;
      cli_options_parse(1, (char *[]){"socket_vmnet", "/tmp/s", NULL});
      _exit(0);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    check("calloc failure exits 1", WIFEXITED(st) && WEXITSTATUS(st) == 1);
  }
#endif

  if (failures == 0) {
    fprintf(stderr, "\nAll cli tests passed.\n");
    return 0;
  }
  fprintf(stderr, "\n%d cli test(s) FAILED.\n", failures);
  return 1;
}
