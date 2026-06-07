#ifndef SOCKET_VMNET_DAEMON_H
#define SOCKET_VMNET_DAEMON_H

/* Shared between the daemon's event loop / connection handlers (main.c) and the
 * vmnet.framework glue (vmnet.c). */
#include <dispatch/dispatch.h>
#include <stdbool.h>
#include <stdint.h>
#include <vmnet/vmnet.h>

#include "acl.h"       /* libfw/c-fw: enum acl_dir, struct acl */
#include "cli.h"       /* struct cli_options */
#include "conntrack.h" /* struct conntrack */
#include "forward.h"   /* struct conn */

struct state {
  dispatch_semaphore_t sem;
  dispatch_queue_t vms_queue;
  dispatch_queue_t host_queue;
  struct conn *conns; // TODO: avoid O(N) lookup
  // When true, guest-to-guest frames are never forwarded directly between
  // clients. Guests can still reach the gateway/NAT (and the outside world),
  // but they cannot see each other. Set via --isolated.
  bool isolated;
  // When true, each client gets its own vmnet interface and the framework does
  // the L2 switching; the userspace MAC switch is then unused. Set via
  // --interface-per-vm.
  bool interface_per_vm;
  // Parsed options, used to build per-client vmnet interfaces. Not owned.
  struct cli_options *cliopt;
  // Optional stateless L3/L4 access-control list (--acl). NULL = allow all.
  struct acl *acl;
  // Optional connection tracker (--stateful). NULL = stateless.
  struct conntrack *ct;
  // Raw source text of the current ACL (JSON or HCL), for the control plane's
  // get_rules. Owned; swapped together with `acl`. NULL if no ACL.
  char *acl_json;
  // Optional stats+control plane (--control-socket). NULL = disabled.
  struct control *control;
};

/* main.c: ACL/conntrack admission check for one frame. */
bool frame_allowed(struct state *state, enum acl_dir dir, const void *buf, uint32_t len);

/* vmnet.c: vmnet.framework glue. */
bool vmnet_write_frame(interface_ref iface, void *body, uint32_t len);
interface_ref start(struct state *state, struct cli_options *cliopt);
bool start_conn_interface(struct state *state, struct conn *conn);
void stop(struct state *state, interface_ref iface);

#endif /* SOCKET_VMNET_DAEMON_H */
