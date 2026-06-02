// vmnet.framework glue for the socket_vmnet daemon: starting/stopping vmnet
// interfaces, draining received packets into the userspace switch, and writing
// frames back out. The vmnet-independent event loop, sockets and connection
// bookkeeping live in main.c; shared state and prototypes are in daemon.h.
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <uuid/uuid.h>
#include <vmnet/vmnet.h>

#include "daemon.h"
#include "forward.h"
#include "log.h"

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
interface_ref start(struct state *state, struct cli_options *cliopt) {
  INFOF("Initializing vmnet.framework (mode %d)", cliopt->vmnet_mode);
  if (cliopt->vmnet_interface != NULL) {
    INFOF("Using network interface \"%s\"", cliopt->vmnet_interface);
  }
  return start_interface(state, cliopt->vmnet_interface_id, NULL, NULL);
}

// Start a dedicated interface for a single client (Phase 2). Returns false on
// failure (already logged).
bool start_conn_interface(struct state *state, struct conn *conn) {
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

void stop(struct state *state, interface_ref iface) {
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

// Write one ethernet frame from a client into a vmnet interface.
bool vmnet_write_frame(interface_ref iface, void *body, uint32_t len) {
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
