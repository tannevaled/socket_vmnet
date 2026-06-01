/* Offline unit test for the vmnet-independent L2 switch (forward.c).
 *
 *   clang -I.. -O0 -g ../forward.c forward_test.c -o forward_test && ./forward_test
 *
 * Uses real socketpairs / unix-datagram sockets; no vmnet, no root. */
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "forward.h"

bool debug = false; /* referenced by log.h via forward.c */

static int failures = 0;
static void check(const char *name, bool ok) {
  if (!ok) {
    fprintf(stderr, "FAIL: %s\n", name);
    failures++;
  } else {
    fprintf(stderr, "ok:   %s\n", name);
  }
}

/* Read a length-prefixed (stream) frame if one is pending; returns body length
 * or -1 if nothing is queued. */
static int recv_stream(int fd, uint8_t *out, size_t cap) {
  uint32_t hdr = 0;
  ssize_t r = recv(fd, &hdr, 4, MSG_DONTWAIT);
  if (r != 4)
    return -1;
  uint32_t len = ntohl(hdr);
  if (len > cap)
    return -2;
  ssize_t b = recv(fd, out, len, MSG_DONTWAIT);
  return (b == (ssize_t)len) ? (int)len : -3;
}

static bool got_stream(int fd, const void *body, uint32_t len) {
  uint8_t buf[2048];
  int n = recv_stream(fd, buf, sizeof(buf));
  return n == (int)len && memcmp(buf, body, len) == 0;
}

static const uint8_t MAC_A[6] = {0x02, 0, 0, 0, 0, 0x0a};
static const uint8_t MAC_B[6] = {0x02, 0, 0, 0, 0, 0x0b};
static const uint8_t MAC_C[6] = {0x02, 0, 0, 0, 0, 0x0c};
static const uint8_t MAC_BCAST[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/* A stream conn backed by a socketpair; peer[i] is the readable far end. */
static int g_peer[8];
static int g_npeer;

static void make_stream(struct conn *c, const uint8_t mac[6]) {
  int sv[2];
  socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
  memset(c, 0, sizeof(*c));
  c->transport = TRANSPORT_STREAM;
  c->socket_fd = sv[0];
  memcpy(c->mac, mac, 6);
  c->mac_known = true;
  g_peer[g_npeer++] = sv[1];
}

int main(void) {
  /* mac_is_multicast */
  check("unicast not multicast", !mac_is_multicast(MAC_A));
  check("broadcast is multicast", mac_is_multicast(MAC_BCAST));

  /* MAC learning */
  {
    struct conn c;
    memset(&c, 0, sizeof(c));
    c.socket_fd = -1;
    conn_learn_mac(&c, MAC_BCAST); /* multicast source ignored */
    check("multicast source not learned", !c.mac_known);
    conn_learn_mac(&c, MAC_A);
    check("unicast source learned", c.mac_known && memcmp(c.mac, MAC_A, 6) == 0);
    conn_learn_mac(&c, MAC_A); /* idempotent */
    conn_learn_mac(&c, MAC_B); /* MAC move */
    check("MAC move updates", memcmp(c.mac, MAC_B, 6) == 0);
  }

  /* List ops + find */
  {
    struct conn a, b, d;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    memset(&d, 0, sizeof(d));
    memcpy(a.mac, MAC_A, 6);
    a.mac_known = true;
    memcpy(b.mac, MAC_B, 6);
    b.mac_known = true;
    struct conn *head = NULL;
    conn_list_append(&head, &a);
    conn_list_append(&head, &b);
    conn_list_append(&head, &d);
    check("find head", conn_find_by_mac(head, MAC_A) == &a);
    check("find middle", conn_find_by_mac(head, MAC_B) == &b);
    check("find missing", conn_find_by_mac(head, MAC_C) == NULL);
    conn_list_remove(&head, &b); /* middle */
    check("removed middle", conn_find_by_mac(head, MAC_B) == NULL);
    conn_list_remove(&head, &a); /* head */
    check("removed head", head == &d);
    conn_list_remove(&head, &a); /* not present: no-op */
    conn_list_remove(&head, &d); /* last */
    check("list empty", head == NULL);
  }

  /* conn_send_frame: stream framing (header + body round-trips). */
  {
    g_npeer = 0;
    struct conn c;
    make_stream(&c, MAC_A);
    const char *msg = "hello-frame";
    conn_send_frame(&c, msg, (uint32_t)strlen(msg));
    check("stream frame round-trips", got_stream(g_peer[0], msg, (uint32_t)strlen(msg)));
    close(c.socket_fd);
    close(g_peer[0]);
  }

  /* conn_send_frame: datagram (raw, no header) via bound unix-dgram sockets. */
  {
    unlink("/tmp/fwd_a.sock");
    unlink("/tmp/fwd_b.sock");
    int a = socket(AF_UNIX, SOCK_DGRAM, 0);
    int b = socket(AF_UNIX, SOCK_DGRAM, 0);
    struct sockaddr_un aa = {0}, bb = {0};
    aa.sun_family = AF_UNIX;
    strcpy(aa.sun_path, "/tmp/fwd_a.sock");
    bb.sun_family = AF_UNIX;
    strcpy(bb.sun_path, "/tmp/fwd_b.sock");
    bind(a, (struct sockaddr *)&aa, sizeof(aa));
    bind(b, (struct sockaddr *)&bb, sizeof(bb));
    struct conn c;
    memset(&c, 0, sizeof(c));
    c.transport = TRANSPORT_DGRAM;
    c.socket_fd = a; /* send from a ... */
    c.peer = bb;     /* ... to b */
    c.peer_len = sizeof(bb);
    const char *msg = "dgram-raw";
    conn_send_frame(&c, msg, (uint32_t)strlen(msg));
    uint8_t buf[64];
    ssize_t n = recv(b, buf, sizeof(buf), MSG_DONTWAIT);
    check("dgram frame raw (no header)",
          n == (ssize_t)strlen(msg) && memcmp(buf, msg, strlen(msg)) == 0);
    close(a);
    close(b);
    unlink("/tmp/fwd_a.sock");
    unlink("/tmp/fwd_b.sock");
  }

  /* forward_switch: unicast to the owning conn only. */
  {
    g_npeer = 0;
    struct conn a, b, c;
    make_stream(&a, MAC_A);
    make_stream(&b, MAC_B);
    make_stream(&c, MAC_C);
    struct conn *head = NULL;
    conn_list_append(&head, &a);
    conn_list_append(&head, &b);
    conn_list_append(&head, &c);
    const char *m = "unicast";
    forward_switch(head, NULL, MAC_B, m, (uint32_t)strlen(m));
    check("unicast -> B only", !got_stream(g_peer[0], m, strlen(m)) &&
                                   got_stream(g_peer[1], m, strlen(m)) &&
                                   !got_stream(g_peer[2], m, strlen(m)));

    /* broadcast floods everyone except the excluded sender (A). */
    const char *bc = "bcast";
    forward_switch(head, &a, MAC_BCAST, bc, (uint32_t)strlen(bc));
    check("bcast floods all but sender", !got_stream(g_peer[0], bc, strlen(bc)) &&
                                             got_stream(g_peer[1], bc, strlen(bc)) &&
                                             got_stream(g_peer[2], bc, strlen(bc)));

    /* unknown unicast also floods (excluding the sender). */
    const uint8_t MAC_UNK[6] = {0x02, 0, 0, 0, 0, 0xff};
    const char *uk = "unknown";
    forward_switch(head, &b, MAC_UNK, uk, (uint32_t)strlen(uk));
    check("unknown unicast floods but sender", got_stream(g_peer[0], uk, strlen(uk)) &&
                                                   !got_stream(g_peer[1], uk, strlen(uk)) &&
                                                   got_stream(g_peer[2], uk, strlen(uk)));

    /* unicast to the excluded conn delivers nothing. */
    const char *self = "self";
    forward_switch(head, &b, MAC_B, self, (uint32_t)strlen(self));
    check("unicast to excluded is dropped", !got_stream(g_peer[1], self, strlen(self)));

    close(a.socket_fd);
    close(b.socket_fd);
    close(c.socket_fd);
    for (int i = 0; i < 3; i++)
      close(g_peer[i]);
  }

  /* conn_find_dgram */
  {
    struct conn c;
    memset(&c, 0, sizeof(c));
    c.transport = TRANSPORT_DGRAM;
    c.socket_fd = 7;
    c.peer.sun_family = AF_UNIX;
    strcpy(c.peer.sun_path, "/tmp/peer.sock");
    c.peer_len = sizeof(c.peer);
    struct conn *head = NULL;
    conn_list_append(&head, &c);
    check("find dgram hit", conn_find_dgram(head, 7, &c.peer, c.peer_len) == &c);
    struct sockaddr_un other = {0};
    other.sun_family = AF_UNIX;
    strcpy(other.sun_path, "/tmp/other.sock");
    check("find dgram miss (addr)", conn_find_dgram(head, 7, &other, sizeof(other)) == NULL);
    check("find dgram miss (fd)", conn_find_dgram(head, 8, &c.peer, c.peer_len) == NULL);
  }

  if (failures == 0) {
    fprintf(stderr, "\nAll forward tests passed.\n");
    return 0;
  }
  fprintf(stderr, "\n%d forward test(s) FAILED.\n", failures);
  return 1;
}
