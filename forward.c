#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>

#include "forward.h"
#include "log.h"

bool mac_is_multicast(const uint8_t mac[6]) { return (mac[0] & 0x01) != 0; }

void conn_send_frame(const struct conn *conn, const void *body, uint32_t len) {
  if (conn->transport == TRANSPORT_DGRAM) {
    ssize_t written =
        sendto(conn->socket_fd, body, len, 0, (const struct sockaddr *)&conn->peer, conn->peer_len);
    if (written < 0) {
      ERRORN("sendto");
    }
    return;
  }
  uint32_t header_be = htonl(len);
  struct iovec iov[2] = {
      {.iov_base = &header_be,   .iov_len = 4  },
      {.iov_base = (void *)body, .iov_len = len},
  };
  ssize_t written = writev(conn->socket_fd, iov, 2);
  if (written < 0) {
    ERRORN("writev");
  }
}

void conn_learn_mac(struct conn *conn, const uint8_t src_mac[6]) {
  if (mac_is_multicast(src_mac))
    return;
  if (!conn->mac_known || memcmp(conn->mac, src_mac, sizeof(conn->mac)) != 0) {
    memcpy(conn->mac, src_mac, sizeof(conn->mac));
    conn->mac_known = true;
    DEBUGF("Learned MAC %02X:%02X:%02X:%02X:%02X:%02X on socket %d", src_mac[0], src_mac[1],
           src_mac[2], src_mac[3], src_mac[4], src_mac[5], conn->socket_fd);
  }
}

void conn_list_append(struct conn **head, struct conn *conn) {
  if (*head == NULL) {
    *head = conn;
  } else {
    struct conn *last;
    for (last = *head; last->next != NULL; last = last->next)
      ;
    last->next = conn;
  }
}

void conn_list_remove(struct conn **head, struct conn *target) {
  if (*head == target) {
    *head = target->next;
    return;
  }
  for (struct conn *c = *head; c != NULL && c->next != NULL; c = c->next) {
    if (c->next == target) {
      c->next = target->next;
      return;
    }
  }
}

struct conn *conn_find_by_mac(struct conn *head, const uint8_t mac[6]) {
  for (struct conn *c = head; c != NULL; c = c->next) {
    if (c->mac_known && memcmp(c->mac, mac, sizeof(c->mac)) == 0)
      return c;
  }
  return NULL;
}

struct conn *conn_find_dgram(struct conn *head, int fd, const struct sockaddr_un *peer,
                             socklen_t peer_len) {
  for (struct conn *c = head; c != NULL; c = c->next) {
    if (c->transport == TRANSPORT_DGRAM && c->socket_fd == fd && c->peer_len == peer_len &&
        memcmp(&c->peer, peer, peer_len) == 0)
      return c;
  }
  return NULL;
}

void forward_switch(struct conn *head, const struct conn *exclude, const uint8_t dest_mac[6],
                    const void *body, uint32_t len) {
  struct conn *target = NULL;
  bool flood = mac_is_multicast(dest_mac);
  if (!flood) {
    target = conn_find_by_mac(head, dest_mac);
    if (target == NULL)
      flood = true; // unknown unicast: flood until the MAC is learned
  }
  if (flood) {
    for (struct conn *c = head; c != NULL; c = c->next) {
      if (c != exclude)
        conn_send_frame(c, body, len);
    }
  } else if (target != exclude) {
    conn_send_frame(target, body, len);
  }
}
