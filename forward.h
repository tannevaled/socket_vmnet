#ifndef SOCKET_VMNET_FORWARD_H
#define SOCKET_VMNET_FORWARD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>

// The vmnet-independent L2 switch: connection bookkeeping, MAC learning, and
// frame forwarding over client sockets. None of this touches vmnet.framework,
// so it is unit-testable with plain socketpairs (no root, no code signing).
//
// These functions do not lock; the caller (the daemon) serializes access to the
// connection list with its own mutex.

enum transport {
  TRANSPORT_STREAM, // legacy QEMU `-netdev socket`: uint32be length header
  TRANSPORT_DGRAM,  // QEMU `-netdev dgram` / VZ file handle: one datagram == one frame
};

struct conn {
  // Source MAC learned from the guest's egress frames, used to switch unicast
  // traffic to a single client instead of flooding every connection.
  uint8_t mac[6];
  bool mac_known;

  enum transport transport;
  // STREAM: the accepted per-client fd.
  // DGRAM:  the shared datagram listener fd; the client is identified by `peer`.
  int socket_fd;
  struct sockaddr_un peer; // DGRAM only: address to sendto()
  socklen_t peer_len;      // DGRAM only

  // Per-VM vmnet interface (--interface-per-vm), opaque here (really an
  // interface_ref); NULL with a single shared interface. Owned by the daemon.
  void *iface;
  uint64_t max_bytes;

  struct conn *next;
};

// True for multicast/broadcast destinations (the least-significant bit of the
// first octet is set), which must be flooded.
bool mac_is_multicast(const uint8_t mac[6]);

// Send one ethernet frame to a client. STREAM connections get the uint32be
// length header expected by the legacy QEMU protocol; DGRAM connections send
// the raw frame as one datagram.
void conn_send_frame(const struct conn *conn, const void *body, uint32_t len);

// Associate src_mac with conn (MAC learning). Multicast/broadcast sources are
// ignored.
void conn_learn_mac(struct conn *conn, const uint8_t src_mac[6]);

// Connection-list operations.
void conn_list_append(struct conn **head, struct conn *conn);
void conn_list_remove(struct conn **head, struct conn *target);
struct conn *conn_find_by_mac(struct conn *head, const uint8_t mac[6]);
struct conn *conn_find_dgram(struct conn *head, int fd, const struct sockaddr_un *peer,
                             socklen_t peer_len);

// Deliver `body` (len bytes) to the client owning dest_mac. Multicast/broadcast
// and not-yet-learned unicast are flooded, like a learning switch. `exclude`
// (when non-NULL) is never sent to -- the sender, for guest-to-guest delivery.
void forward_switch(struct conn *head, const struct conn *exclude, const uint8_t dest_mac[6],
                    const void *body, uint32_t len);

#endif /* SOCKET_VMNET_FORWARD_H */
