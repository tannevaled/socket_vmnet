#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <grp.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <vmnet/vmnet.h>

#include "acl.h"      /* libfw/c-fw */
#include "acl_hcl.h"  /* libfw/c-fw (HCL front-end, via libhcl/c-hcl) */
#include "cli.h"
#include "conntrack.h" /* libfw/c-fw */
#include "forward.h"
#include "log.h"

#if __MAC_OS_X_VERSION_MAX_ALLOWED < 101500
#error "Requires macOS 10.15 or later"
#endif

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

bool debug = false;

static const char *vmnet_strerror(vmnet_return_t v) {
  switch (v) {
  case VMNET_SUCCESS:
    return "VMNET_SUCCESS";
  case VMNET_FAILURE:
    return "VMNET_FAILURE";
  case VMNET_MEM_FAILURE:
    return "VMNET_MEM_FAILURE";
  case VMNET_INVALID_ARGUMENT:
    return "VMNET_INVALID_ARGUMENT";
  case VMNET_SETUP_INCOMPLETE:
    return "VMNET_SETUP_INCOMPLETE";
  case VMNET_INVALID_ACCESS:
    return "VMNET_INVALID_ACCESS";
  case VMNET_PACKET_TOO_BIG:
    return "VMNET_PACKET_TOO_BIG";
  case VMNET_BUFFER_EXHAUSTED:
    return "VMNET_BUFFER_EXHAUSTED";
  case VMNET_TOO_MANY_PACKETS:
    return "VMNET_TOO_MANY_PACKETS";
  default:
    return "(unknown status)";
  }
}

static void print_vmnet_start_param(xpc_object_t param) {
  if (param == NULL)
    return;
  xpc_dictionary_apply(param, ^bool(const char *key, xpc_object_t value) {
    xpc_type_t t = xpc_get_type(value);
    if (t == XPC_TYPE_UINT64)
      INFOF("* %s: %lld", key, xpc_uint64_get_value(value));
    else if (t == XPC_TYPE_INT64)
      INFOF("* %s: %lld", key, xpc_int64_get_value(value));
    else if (t == XPC_TYPE_STRING)
      INFOF("* %s: %s", key, xpc_string_get_string_ptr(value));
    else if (t == XPC_TYPE_UUID) {
      char uuid_str[36 + 1];
      uuid_unparse(xpc_uuid_get_bytes(value), uuid_str);
      INFOF("* %s: %s", key, uuid_str);
    } else
      INFOF("* %s: (unknown type)", key);
    return true;
  });
}

// The connection bookkeeping, MAC switch and frame forwarding live in forward.c
// (vmnet-independent and unit-tested). struct conn / enum transport come from
// forward.h.
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
} _state;

// Load an ACL from a file, choosing the format by extension: a `.hcl` path is
// compiled by the built-in HCL parser, anything else is parsed as JSON.
static struct acl *load_acl_file(const char *path) {
  size_t n = strlen(path);
  if (n >= 4 && strcmp(path + n - 4, ".hcl") == 0)
    return acl_load_hcl(path);
  return acl_load(path);
}

// Decide whether a frame is permitted by the ACL, consulting the connection
// tracker first so that return traffic of an allowed flow passes. Safe to call
// with no ACL (returns true). Takes state->sem (guards acl swap + conntrack).
static bool frame_allowed(struct state *state, enum acl_dir dir, const void *buf, uint32_t len) {
  if (state->acl == NULL)
    return true;
  uint64_t now = (uint64_t)time(NULL);
  bool allow;
  dispatch_semaphore_wait(state->sem, DISPATCH_TIME_FOREVER);
  if (state->ct != NULL && conntrack_established(state->ct, buf, len, now)) {
    allow = true;
  } else {
    allow = acl_allows(state->acl, dir, buf, len);
    if (allow && state->ct != NULL)
      conntrack_record(state->ct, buf, len, now);
  }
  dispatch_semaphore_signal(state->sem);
  return allow;
}

// Allocate and register a stream connection (locks state->sem).
static struct conn *state_add_stream_conn(struct state *state, int socket_fd) {
  struct conn *conn = calloc(1, sizeof(*conn));
  conn->transport = TRANSPORT_STREAM;
  conn->socket_fd = socket_fd;
  dispatch_semaphore_wait(state->sem, DISPATCH_TIME_FOREVER);
  conn_list_append(&state->conns, conn);
  dispatch_semaphore_signal(state->sem);
  return conn;
}

static void state_remove_conn(struct state *state, struct conn *target) {
  dispatch_semaphore_wait(state->sem, DISPATCH_TIME_FOREVER);
  conn_list_remove(&state->conns, target);
  dispatch_semaphore_signal(state->sem);
}

static void _on_vmnet_packets_available(interface_ref iface, int64_t buf_count, int64_t max_bytes,
                                        struct state *state, struct conn *only) {
  DEBUGF("Receiving from VMNET (buffer for %lld packets, max: %lld "
         "bytes)",
         buf_count, max_bytes);
  // TODO: use prealloced pool
  struct vmpktdesc *pdv = calloc(buf_count, sizeof(struct vmpktdesc));
  if (pdv == NULL) {
    ERRORN("calloc(estim_count, sizeof(struct vmpktdesc)");
    goto done;
  }
  for (int i = 0; i < buf_count; i++) {
    pdv[i].vm_flags = 0;
    pdv[i].vm_pkt_size = max_bytes;
    pdv[i].vm_pkt_iovcnt = 1, pdv[i].vm_pkt_iov = malloc(sizeof(struct iovec));
    if (pdv[i].vm_pkt_iov == NULL) {
      ERRORN("malloc(sizeof(struct iovec))");
      goto done;
    }
    pdv[i].vm_pkt_iov->iov_base = malloc(max_bytes);
    if (pdv[i].vm_pkt_iov->iov_base == NULL) {
      ERRORN("malloc(max_bytes)");
      goto done;
    }
    pdv[i].vm_pkt_iov->iov_len = max_bytes;
  }
  int received_count = buf_count;
  vmnet_return_t read_status = vmnet_read(iface, pdv, &received_count);
  if (read_status != VMNET_SUCCESS) {
    ERRORF("vmnet_read: [%d] %s", read_status, vmnet_strerror(read_status));
    goto done;
  }

  DEBUGF("Received from VMNET: %d packets (buffer was prepared for %lld packets)", received_count,
         buf_count);
  for (int i = 0; i < received_count; i++) {
    uint8_t dest_mac[6], src_mac[6];
    assert(pdv[i].vm_pkt_iov[0].iov_len > 12);
    const char *packet = (const char *)pdv[i].vm_pkt_iov[0].iov_base;
    memcpy(dest_mac, packet, sizeof(dest_mac));
    memcpy(src_mac, packet + 6, sizeof(src_mac));
    DEBUGF("[Handler i=%d] Dest %02X:%02X:%02X:%02X:%02X:%02X, Src "
           "%02X:%02X:%02X:%02X:%02X:%02X,",
           i, dest_mac[0], dest_mac[1], dest_mac[2], dest_mac[3], dest_mac[4], dest_mac[5],
           src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
    void *body = pdv[i].vm_pkt_iov[0].iov_base;
    uint32_t body_len = (uint32_t)pdv[i].vm_pkt_size; // not vm_pkt_iov[0].iov_len

    // Phase 3: drop ingress frames denied by the ACL before delivering them.
    if (!frame_allowed(state, ACL_INGRESS, body, body_len)) {
      DEBUGF("[Handler i=%d] Dropped by ACL (ingress)", i);
      continue;
    }

    // --interface-per-vm (Phase 2): this interface belongs to a single client
    // and vmnet.framework already delivered only that client's frames, so there
    // is nothing to switch -- forward straight to it.
    if (only != NULL) {
      DEBUGF("[Handler i=%d] Delivering to per-vm socket %d: %u bytes", i, only->socket_fd,
             body_len);
      conn_send_frame(only, body, body_len);
      continue;
    }

    // Shared interface (Phase 1): switch the frame to the owning client (or
    // flood multicast/broadcast/unknown). This path carries traffic from vmnet
    // (NAT/external/bridged peers), so it is delivered regardless of --isolated;
    // isolation only governs direct guest-to-guest forwarding (see on_accept).
    dispatch_semaphore_wait(state->sem, DISPATCH_TIME_FOREVER);
    forward_switch(state->conns, NULL, dest_mac, body, body_len);
    dispatch_semaphore_signal(state->sem);
  }
done:
  if (pdv != NULL) {
    for (int i = 0; i < buf_count; i++) {
      if (pdv[i].vm_pkt_iov != NULL) {
        if (pdv[i].vm_pkt_iov->iov_base != NULL) {
          free(pdv[i].vm_pkt_iov->iov_base);
        }
        free(pdv[i].vm_pkt_iov);
      }
    }
    free(pdv);
  }
}

#define MAX_PACKET_COUNT_AT_ONCE 32
static void on_vmnet_packets_available(interface_ref iface, int64_t estim_count, int64_t max_bytes,
                                       struct state *state, struct conn *only) {
  int64_t q = estim_count / MAX_PACKET_COUNT_AT_ONCE;
  int64_t r = estim_count % MAX_PACKET_COUNT_AT_ONCE;
  DEBUGF("estim_count=%lld, dividing by MAX_PACKET_COUNT_AT_ONCE=%d; q=%lld, "
         "r=%lld",
         estim_count, MAX_PACKET_COUNT_AT_ONCE, q, r);
  for (int i = 0; i < q; i++) {
    _on_vmnet_packets_available(iface, MAX_PACKET_COUNT_AT_ONCE, max_bytes, state, only);
  }
  if (r > 0)
    _on_vmnet_packets_available(iface, r, max_bytes, state, only);
}

// Build the vmnet_start_interface parameter dictionary shared by the single
// shared interface and the per-VM interfaces.
static xpc_object_t build_start_dict(struct cli_options *cliopt, const uuid_t interface_id) {
  xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);
  xpc_dictionary_set_uint64(dict, vmnet_operation_mode_key, cliopt->vmnet_mode);
  if (cliopt->vmnet_interface != NULL) {
    xpc_dictionary_set_string(dict, vmnet_shared_interface_name_key, cliopt->vmnet_interface);
  }
  if (!uuid_is_null(cliopt->vmnet_network_identifier)) {
    xpc_dictionary_set_uuid(dict, vmnet_network_identifier_key, cliopt->vmnet_network_identifier);
  }
  if (cliopt->vmnet_gateway != NULL) {
    xpc_dictionary_set_string(dict, vmnet_start_address_key, cliopt->vmnet_gateway);
    xpc_dictionary_set_string(dict, vmnet_end_address_key, cliopt->vmnet_dhcp_end);
    xpc_dictionary_set_string(dict, vmnet_subnet_mask_key, cliopt->vmnet_mask);
  }
  xpc_dictionary_set_uuid(dict, vmnet_interface_id_key, interface_id);
  if (cliopt->vmnet_nat66_prefix != NULL) {
    xpc_dictionary_set_string(dict, vmnet_nat66_prefix_key, cliopt->vmnet_nat66_prefix);
  }
  // Hard, non-spoofable isolation: when each client owns its interface, the
  // framework itself prevents it from reaching the other interfaces.
  // Requires macOS 11+.
  if (cliopt->isolated && cliopt->interface_per_vm) {
    xpc_dictionary_set_bool(dict, vmnet_enable_isolation_key, true);
  }
  return dict;
}

// Start one vmnet interface and register its packets-available callback.
// When `only` is non-NULL the interface belongs to that single client (Phase 2)
// and received frames are forwarded straight to it; otherwise frames are
// switched across all connections by destination MAC (Phase 1, shared).
static interface_ref start_interface(struct state *state, const uuid_t interface_id,
                                     struct conn *only, uint64_t *max_bytes_out) {
  xpc_object_t dict = build_start_dict(state->cliopt, interface_id);
  dispatch_semaphore_t sem = dispatch_semaphore_create(0);

  __block interface_ref iface;
  __block vmnet_return_t status;
  __block uint64_t max_bytes = 0;
  iface = vmnet_start_interface(
      dict, state->host_queue, ^(vmnet_return_t x_status, xpc_object_t x_param) {
        status = x_status;
        if (x_status == VMNET_SUCCESS) {
          print_vmnet_start_param(x_param);
          max_bytes = xpc_dictionary_get_uint64(x_param, vmnet_max_packet_size_key);
        }
        dispatch_semaphore_signal(sem);
      });
  dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
  xpc_release(dict);
  if (status != VMNET_SUCCESS) {
    ERRORF("vmnet_start_interface: [%d] %s", status, vmnet_strerror(status));
    return NULL;
  }

  vmnet_interface_set_event_callback(
      iface, VMNET_INTERFACE_PACKETS_AVAILABLE, state->host_queue,
      ^(interface_event_t __attribute__((unused)) x_event_id, xpc_object_t x_event) {
        uint64_t estim_count =
            xpc_dictionary_get_uint64(x_event, vmnet_estimated_packets_available_key);
        on_vmnet_packets_available(iface, estim_count, max_bytes, state, only);
      });

  if (max_bytes_out != NULL)
    *max_bytes_out = max_bytes;
  return iface;
}

// The single shared interface (Phase 1 / default).
static interface_ref start(struct state *state, struct cli_options *cliopt) {
  INFOF("Initializing vmnet.framework (mode %d)", cliopt->vmnet_mode);
  if (cliopt->vmnet_interface != NULL) {
    INFOF("Using network interface \"%s\"", cliopt->vmnet_interface);
  }
  return start_interface(state, cliopt->vmnet_interface_id, NULL, NULL);
}

// Start a dedicated interface for a single client (Phase 2). Returns false on
// failure (already logged).
static bool start_conn_interface(struct state *state, struct conn *conn) {
  uuid_t interface_id;
  uuid_generate_random(interface_id);
  INFOF("Starting a dedicated vmnet interface for socket %d (mode %d)", conn->socket_fd,
        state->cliopt->vmnet_mode);
  uint64_t max_bytes = 0;
  interface_ref iface = start_interface(state, interface_id, conn, &max_bytes);
  if (iface == NULL)
    return false;
  conn->iface = iface;
  conn->max_bytes = max_bytes;
  return true;
}

static void stop(struct state *state, interface_ref iface) {
  if (iface == NULL) {
    return;
  }
  dispatch_semaphore_t sem = dispatch_semaphore_create(0);
  __block vmnet_return_t status;
  vmnet_stop_interface(iface, state->host_queue, ^(vmnet_return_t x_status) {
    status = x_status;
    dispatch_semaphore_signal(sem);
  });
  dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
  if (status != VMNET_SUCCESS) {
    ERRORF("vmnet_stop_interface: [%d] %s", status, vmnet_strerror(status));
  }
}

static int socket_bindlisten(const char *socket_path, const char *socket_group, int type) {
  int fd = -1;
  struct sockaddr_un addr = {0};

  unlink(socket_path); /* avoid EADDRINUSE */
  if ((fd = socket(PF_LOCAL, type, 0)) < 0) {
    ERRORN("socket");
    goto err;
  }
  addr.sun_family = PF_LOCAL;
  size_t socket_len = strlen(socket_path);
  if (socket_len + 1 > sizeof(addr.sun_path)) {
    ERRORF("the socket path is too long: %zu", socket_len);
    goto err;
  }
  strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    ERRORN("bind");
    goto err;
  }
  /* SOCK_DGRAM is connectionless: there is nothing to listen() for. */
  if (type == SOCK_STREAM && listen(fd, 0) < 0) {
    ERRORN("listen");
    goto err;
  }
  if (socket_group != NULL) {
    errno = 0;
    struct group *grp = getgrnam(socket_group); /* Do not free */
    if (grp == NULL) {
      if (errno != 0)
        ERRORN("getgrnam");
      else
        ERRORF("unknown group name \"%s\"", socket_group);
      goto err;
    }
    /* fchown can't be used (EINVAL) */
    if (chown(socket_path, -1, grp->gr_gid) < 0) {
      ERRORN("chown");
      goto err;
    }
    if (chmod(socket_path, 0770) < 0) {
      ERRORN("chmod");
      goto err;
    }
  }
  return fd;
err:
  if (fd >= 0)
    close(fd);
  return -1;
}

static void remove_pidfile(const char *pidfile) {
  if (unlink(pidfile) != 0) {
    ERRORF("Failed to remove pidfile: \"%s\": %s", pidfile, strerror(errno));
    return;
  }
  INFOF("Removed pidfile \"%s\" for process %d", pidfile, getpid());
}

static int create_pidfile(const char *pidfile) {
  int flags = O_WRONLY | O_CREAT | O_EXLOCK | O_TRUNC | O_NONBLOCK;
  int fd = open(pidfile, flags, 0644);
  if (fd == -1) {
    ERRORF("Failed to open pidfile: \"%s\": %s", pidfile, strerror(errno));
    return -1;
  }

  char pid[20];
  snprintf(pid, sizeof(pid), "%u", getpid());
  ssize_t n = write(fd, pid, strlen(pid));
  if (n != (ssize_t)strlen(pid)) {
    if (n < 0) {
      ERRORF("Failed to write pidfile: \"%s\": %s", pidfile, strerror(errno));
    } else {
      // Should never happen, but if it does errno is not set.
      ERRORF("Short write to pidfile: \"%s\"", pidfile);
    }
    remove_pidfile(pidfile);
    close(fd);
    return -1;
  }

  INFOF("Created pidfile \"%s\" for process %d", pidfile, getpid());
  return fd;
}

static int setup_signals(int kq) {
  struct kevent changes[] = {
      {.ident = SIGHUP,  .filter = EVFILT_SIGNAL, .flags = EV_ADD},
      {.ident = SIGINT,  .filter = EVFILT_SIGNAL, .flags = EV_ADD},
      {.ident = SIGTERM, .filter = EVFILT_SIGNAL, .flags = EV_ADD},
  };

  // Block signals we want to receive via kqueue.
  sigset_t mask;
  sigemptyset(&mask);
  for (size_t i = 0; i < ARRAY_SIZE(changes); i++) {
    sigaddset(&mask, changes[i].ident);
  }
  if (sigprocmask(SIG_BLOCK, &mask, NULL) != 0) {
    ERRORN("sigprocmask");
    return -1;
  }

  // We will receive EPIPE on the socket.
  signal(SIGPIPE, SIG_IGN);

  if (kevent(kq, changes, ARRAY_SIZE(changes), NULL, 0, NULL) != 0) {
    ERRORN("kevent");
    return -1;
  }
  return 0;
}

static int add_listen_fd(int kq, int fd) {
  struct kevent changes[] = {
      {.ident = fd, .filter = EVFILT_READ, .flags = EV_ADD},
  };
  if (kevent(kq, changes, ARRAY_SIZE(changes), NULL, 0, NULL) != 0) {
    ERRORN("kevent");
    return -1;
  }
  return 0;
}

// Write one ethernet frame from a client into a vmnet interface.
static bool vmnet_write_frame(interface_ref iface, void *body, uint32_t len) {
  struct iovec iov = {.iov_base = body, .iov_len = len};
  struct vmpktdesc pd = {
      .vm_pkt_size = len,
      .vm_pkt_iov = &iov,
      .vm_pkt_iovcnt = 1,
      .vm_flags = 0,
  };
  int written_count = pd.vm_pkt_iovcnt;
  vmnet_return_t status = vmnet_write(iface, &pd, &written_count);
  if (status != VMNET_SUCCESS) {
    ERRORF("vmnet_write: [%d] %s", status, vmnet_strerror(status));
    return false;
  }
  return true;
}

// Forward a guest's frame to the other guests sharing the single interface
// (Phase 1): switch to the owning client (or flood), never echoing the sender.
// vmnet does not loop same-network frames back to us. Locks state->sem.
static void forward_guest_to_guest(struct state *state, struct conn *sender, const void *body,
                                   uint32_t len, const uint8_t dest_mac[6]) {
  dispatch_semaphore_wait(state->sem, DISPATCH_TIME_FOREVER);
  forward_switch(state->conns, sender, dest_mac, body, len);
  dispatch_semaphore_signal(state->sem);
}

// Drain all currently-available datagrams from the SOCK_DGRAM listener (Phase
// 0). Runs inline in the main loop (single-threaded), so datagrams from a given
// peer keep their order. Each datagram is exactly one ethernet frame, with no
// uint32be length header.
static void on_dgram_readable(struct state *state, int dgram_fd, interface_ref shared_iface,
                              void *buf, size_t buf_len) {
  for (;;) {
    struct sockaddr_un peer = {0};
    socklen_t peer_len = sizeof(peer);
    ssize_t n = recvfrom(dgram_fd, buf, buf_len, MSG_DONTWAIT, (struct sockaddr *)&peer, &peer_len);
    if (n < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        break;
      ERRORN("recvfrom");
      break;
    }
    if (n == 0)
      continue;
    if (peer_len == 0 || peer.sun_family != AF_UNIX) {
      WARN("Dropping a datagram from an unbound peer; the client must bind a local address");
      continue;
    }
    uint32_t len = (uint32_t)n;

    uint8_t dest_mac[6] = {0}, src_mac[6] = {0};
    bool eth_parsed = len >= 12;
    if (eth_parsed) {
      memcpy(dest_mac, buf, sizeof(dest_mac));
      memcpy(src_mac, (const uint8_t *)buf + 6, sizeof(src_mac));
    }

    dispatch_semaphore_wait(state->sem, DISPATCH_TIME_FOREVER);
    struct conn *conn = conn_find_dgram(state->conns, dgram_fd, &peer, peer_len);
    bool created = false;
    if (conn == NULL) {
      conn = calloc(1, sizeof(*conn));
      conn->transport = TRANSPORT_DGRAM;
      conn->socket_fd = dgram_fd;
      memcpy(&conn->peer, &peer, peer_len);
      conn->peer_len = peer_len;
      conn_list_append(&state->conns, conn);
      created = true;
    }
    if (eth_parsed)
      conn_learn_mac(conn, src_mac);
    dispatch_semaphore_signal(state->sem);

    if (created) {
      INFOF("New datagram client (fd %d)", dgram_fd);
      // Per-VM mode: bring up this client's dedicated interface lazily.
      if (state->interface_per_vm && !start_conn_interface(state, conn)) {
        continue; // error already logged; the conn stays without an interface
      }
    }

    if (!frame_allowed(state, ACL_EGRESS, buf, len)) {
      DEBUGF("%s", "Datagram dropped by ACL (egress)");
      continue;
    }

    interface_ref iface = state->interface_per_vm ? conn->iface : shared_iface;
    if (iface == NULL)
      continue;
    if (!vmnet_write_frame(iface, buf, len))
      continue;

    if (!state->interface_per_vm && !state->isolated && eth_parsed)
      forward_guest_to_guest(state, conn, buf, len, dest_mac);
  }
}

static void on_accept(struct state *state, struct conn *conn, interface_ref shared_iface);

int main(int argc, char *argv[]) {
  debug = getenv("DEBUG") != NULL;
  int rc = 1;
  int listen_fd = -1;
  int dgram_fd = -1;
  int pidfile_fd = -1;
  int kq = -1;
  void *dgram_buf = NULL;
  __block interface_ref iface = NULL;

  struct state state = {0};

  struct cli_options *cliopt = cli_options_parse(argc, argv);
  assert(cliopt != NULL);
  if (geteuid() != 0) {
    WARN("Running without root. This is very unlikely to work: See README.md");
  }
  if (geteuid() != getuid()) {
    WARN("Seems running with SETUID. This is insecure and highly discouraged: See README.md");
  }

  kq = kqueue();
  if (kq == -1) {
    ERRORN("kqueue");
    goto done;
  }

  // Setup signals beofre creating the pidfile to ensure removal of the pidfile
  // when terminating by signal.
  if (setup_signals(kq)) {
    goto done;
  }

  if (cliopt->pidfile != NULL) {
    pidfile_fd = create_pidfile(cliopt->pidfile);
    if (pidfile_fd == -1) {
      goto done; // error already logged.
    }
  }

  DEBUGF("Opening socket \"%s\" (for UNIX group \"%s\")", cliopt->socket_path,
         cliopt->socket_group);
  listen_fd = socket_bindlisten(cliopt->socket_path, cliopt->socket_group, SOCK_STREAM);
  if (listen_fd < 0) {
    ERRORN("socket_bindlisten");
    goto done;
  }

  if (cliopt->socket_dgram_path != NULL) {
    DEBUGF("Opening datagram socket \"%s\" (for UNIX group \"%s\")", cliopt->socket_dgram_path,
           cliopt->socket_group);
    dgram_fd = socket_bindlisten(cliopt->socket_dgram_path, cliopt->socket_group, SOCK_DGRAM);
    if (dgram_fd < 0) {
      ERRORN("socket_bindlisten[dgram]");
      goto done;
    }
    dgram_buf = malloc(64 * 1024);
    if (dgram_buf == NULL) {
      ERRORN("malloc");
      goto done;
    }
  }

  state.cliopt = cliopt;
  state.isolated = cliopt->isolated;
  state.interface_per_vm = cliopt->interface_per_vm;
  if (state.isolated) {
    INFOF("%s", "Guest-to-guest isolation is enabled (--isolated)");
  }
  if (cliopt->acl_path != NULL) {
    state.acl = load_acl_file(cliopt->acl_path);
    if (state.acl == NULL) {
      // Error already logged. Fail closed: refuse to start rather than run
      // unfiltered when an ACL was explicitly requested.
      goto done;
    }
    if (cliopt->stateful) {
      // 4096 flows; TCP 120s, UDP 30s idle timeouts.
      state.ct = conntrack_new(4096, 120, 30);
      if (state.ct == NULL) {
        ERRORN("conntrack_new");
        goto done;
      }
      INFOF("%s", "Stateful filtering enabled (--stateful)");
    }
  } else if (cliopt->stateful) {
    WARN("--stateful has no effect without --acl");
  }

  state.sem = dispatch_semaphore_create(1);

  // Queue for vm connections, allowing processing vms requests in parallel.
  state.vms_queue =
      dispatch_queue_create("io.github.lima-vm.socket_vmnet.vms", DISPATCH_QUEUE_CONCURRENT);

  // Queue for processing vmnet events.
  state.host_queue =
      dispatch_queue_create("io.github.lima-vm.socket_vmnet.host", DISPATCH_QUEUE_SERIAL);

  if (state.interface_per_vm) {
    INFOF("%s", "Per-VM interface mode (--interface-per-vm): one vmnet interface per client");
  } else {
    iface = start(&state, cliopt);
    if (iface == NULL) {
      // Error already logged.
      goto done;
    }
  }

  if (add_listen_fd(kq, listen_fd)) {
    goto done;
  }
  if (dgram_fd != -1 && add_listen_fd(kq, dgram_fd)) {
    goto done;
  }

  while (1) {
    struct kevent events[1];
    int n = kevent(kq, NULL, 0, events, 1, NULL);
    if (n < 0) {
      ERRORN("kevent");
      goto done;
    }

    if (events[0].filter == EVFILT_SIGNAL) {
      if ((int)events[0].ident == SIGHUP && cliopt->acl_path != NULL) {
        // Hot-reload the ACL; keep the old ruleset (and connection state) if the
        // new file fails to parse.
        INFOF("%s", "Received SIGHUP, reloading ACL");
        struct acl *fresh = load_acl_file(cliopt->acl_path);
        if (fresh != NULL) {
          dispatch_semaphore_wait(state.sem, DISPATCH_TIME_FOREVER);
          struct acl *old = state.acl;
          state.acl = fresh;
          dispatch_semaphore_signal(state.sem);
          acl_destroy(old);
        } else {
          ERROR("acl: reload failed; keeping the previous ruleset");
        }
        continue;
      }
      INFOF("Received signal %s", strsignal(events[0].ident));
      break;
    }

    if (events[0].filter == EVFILT_READ) {
      if ((int)events[0].ident == dgram_fd) {
        on_dgram_readable(&state, dgram_fd, iface, dgram_buf, 64 * 1024);
      } else {
        int accept_fd = accept(listen_fd, NULL, NULL);
        if (accept_fd < 0) {
          ERRORN("accept");
          goto done;
        }
        struct conn *conn = state_add_stream_conn(&state, accept_fd);
        struct state *state_p = &state;
        dispatch_async(state.vms_queue, ^{
          on_accept(state_p, conn, iface);
        });
      }
    }
  }
  rc = 0;
done:
  DEBUGF("shutting down with rc=%d", rc);
  if (iface != NULL) {
    stop(&state, iface);
  }
  // Note: on signal-triggered shutdown, per-VM interfaces owned by still-active
  // stream connections are reclaimed by the OS on process exit (their reader
  // threads are blocked in read(2)). Graceful per-connection teardown on signal
  // is future work; the common path (client disconnect) is handled in on_accept.
  if (listen_fd != -1) {
    close(listen_fd);
  }
  if (dgram_fd != -1) {
    close(dgram_fd);
  }
  free(dgram_buf);
  acl_destroy(state.acl);
  conntrack_free(state.ct);
  if (pidfile_fd != -1) {
    remove_pidfile(cliopt->pidfile);
    close(pidfile_fd);
  }
  if (state.vms_queue != NULL)
    dispatch_release(state.vms_queue);
  if (state.host_queue != NULL)
    dispatch_release(state.host_queue);
  if (kq != -1) {
    close(kq);
  }
  cli_options_destroy(cliopt);
  return rc;
}

static void on_accept(struct state *state, struct conn *conn, interface_ref shared_iface) {
  int fd = conn->socket_fd;
  INFOF("Accepted a connection (fd %d)", fd);

  void *buf = NULL;
  interface_ref iface = shared_iface;
  if (state->interface_per_vm) {
    // Phase 2: bring up this client's dedicated interface; vmnet.framework then
    // switches its traffic and (with --isolated) isolates it from other clients.
    if (!start_conn_interface(state, conn)) {
      goto done; // error already logged
    }
    iface = conn->iface;
  }

  size_t buf_len = 64 * 1024;
  buf = malloc(buf_len);
  if (buf == NULL) {
    ERRORN("malloc");
    goto done;
  }
  for (uint64_t i = 0;; i++) {
    DEBUGF("[Socket-to-VMNET i=%lld] Receiving from the socket %d", i, fd);
    uint32_t header_be = 0;
    ssize_t header_received = read(fd, &header_be, 4);
    if (header_received < 0) {
      ERRORN("read[header]");
      goto done;
    }
    if (header_received == 0) {
      // EOF according to man page of read.
      INFOF("Connection closed by peer (fd %d)", fd);
      goto done;
    }
    uint32_t header = ntohl(header_be);
    assert(header <= buf_len);
    ssize_t received = read(fd, buf, header);
    if (received < 0) {
      ERRORN("read[body]");
      goto done;
    }
    if (received == 0) {
      // EOF according to man page of read.
      INFOF("Connection closed by peer (fd %d)", fd);
      goto done;
    }
    assert(received == header);
    DEBUGF("[Socket-to-VMNET i=%lld] Received from the socket %d: %ld bytes", i, fd, received);

    // Learn the guest's source MAC so that return traffic can be switched back
    // to this connection instead of flooded to every client.
    uint8_t dest_mac[6] = {0}, src_mac[6] = {0};
    bool eth_parsed = header >= 12;
    if (eth_parsed) {
      memcpy(dest_mac, buf, sizeof(dest_mac));
      memcpy(src_mac, (const uint8_t *)buf + 6, sizeof(src_mac));
      dispatch_semaphore_wait(state->sem, DISPATCH_TIME_FOREVER);
      conn_learn_mac(conn, src_mac);
      dispatch_semaphore_signal(state->sem);
    }

    // Phase 3: drop egress frames denied by the ACL (no vmnet write, no
    // guest-to-guest forwarding).
    if (!frame_allowed(state, ACL_EGRESS, buf, header)) {
      DEBUGF("[Socket-to-VMNET i=%lld] Dropped by ACL (egress)", i);
      continue;
    }

    DEBUGF("[Socket-to-VMNET i=%lld] Sending to VMNET: %u bytes", i, header);
    if (!vmnet_write_frame(iface, buf, header)) {
      goto done;
    }

    // Deliver guest-to-guest traffic between clients on the same network. In
    // --interface-per-vm mode this is handled by vmnet.framework, so we only do
    // it for the shared interface. With --isolated, guest-to-guest delivery is
    // disabled entirely: guests keep reaching the gateway/NAT (handled above by
    // vmnet_write) but cannot see each other.
    if (!state->interface_per_vm && !state->isolated && eth_parsed) {
      forward_guest_to_guest(state, conn, buf, header, dest_mac);
    }
  }
done:
  INFOF("Closing a connection (fd %d)", fd);
  if (conn->iface != NULL) {
    stop(state, conn->iface);
  }
  state_remove_conn(state, conn);
  close(fd);
  free(conn);
  free(buf);
}
