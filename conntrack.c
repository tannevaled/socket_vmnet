#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "conntrack.h"

#ifdef CT_FAULT_INJECT
/* Test-only allocation fault injection (see acl.c for the same pattern). */
int ct_alloc_budget = -1;
static bool ct_should_fail(void) {
  if (ct_alloc_budget < 0)
    return false;
  if (ct_alloc_budget == 0) {
    ct_alloc_budget = -1;
    return true;
  }
  ct_alloc_budget--;
  return false;
}
static void *ct_calloc(size_t a, size_t b) { return ct_should_fail() ? NULL : calloc(a, b); }
#define calloc ct_calloc
#endif

/* A normalized flow: an endpoint is (16-byte address, port). The two endpoints
 * are stored in a canonical order (lexicographically smaller first) so that a
 * frame and its reply map to the same key. */
struct endpoint {
  uint8_t addr[16];
  uint16_t port;
};

struct flow {
  bool used;
  int family; /* 4 or 6 */
  uint8_t proto;
  struct endpoint lo, hi;
  uint64_t last_seen;
};

struct conntrack {
  struct flow *flows;
  size_t cap;
  uint32_t tcp_timeout;
  uint32_t udp_timeout;
};

struct conntrack *conntrack_new(size_t capacity, uint32_t tcp_timeout, uint32_t udp_timeout) {
  if (capacity == 0)
    capacity = 1;
  struct conntrack *ct = calloc(1, sizeof(*ct));
  if (ct == NULL)
    return NULL;
  ct->flows = calloc(capacity, sizeof(*ct->flows));
  if (ct->flows == NULL) {
    free(ct);
    return NULL;
  }
  ct->cap = capacity;
  ct->tcp_timeout = tcp_timeout;
  ct->udp_timeout = udp_timeout;
  return ct;
}

void conntrack_free(struct conntrack *ct) {
  if (ct == NULL)
    return;
  free(ct->flows);
  free(ct);
}

/* Extract a normalized TCP/UDP flow key from an ethernet frame. Returns false
 * for anything that is not tracked (non-IP, non-TCP/UDP, truncated). */
static bool flow_key(const uint8_t *frame, size_t len, int *family, uint8_t *proto,
                     struct endpoint *a, struct endpoint *b) {
  if (len < 14)
    return false;
  uint16_t ethertype = (uint16_t)((frame[12] << 8) | frame[13]);
  const uint8_t *l3 = frame + 14;
  size_t l3len = len - 14;
  const uint8_t *src, *dst, *l4;

  if (ethertype == 0x0800) {
    if (l3len < 20)
      return false;
    size_t ihl = (size_t)(l3[0] & 0x0F) * 4;
    if (ihl < 20 || l3len < ihl + 4)
      return false;
    *family = 4;
    *proto = l3[9];
    src = l3 + 12;
    dst = l3 + 16;
    l4 = l3 + ihl;
    memset(a->addr, 0, 16);
    memset(b->addr, 0, 16);
    memcpy(a->addr, src, 4);
    memcpy(b->addr, dst, 4);
  } else if (ethertype == 0x86DD) {
    if (l3len < 40 + 4)
      return false;
    *family = 6;
    *proto = l3[6];
    src = l3 + 8;
    dst = l3 + 24;
    l4 = l3 + 40;
    memcpy(a->addr, src, 16);
    memcpy(b->addr, dst, 16);
  } else {
    return false;
  }
  if (*proto != 6 && *proto != 17)
    return false;
  a->port = (uint16_t)((l4[0] << 8) | l4[1]);
  b->port = (uint16_t)((l4[2] << 8) | l4[3]);
  return true;
}

static int endpoint_cmp(const struct endpoint *x, const struct endpoint *y) {
  int c = memcmp(x->addr, y->addr, 16);
  if (c != 0)
    return c;
  return (int)x->port - (int)y->port;
}

/* Fill lo/hi in canonical order. */
static void normalize(const struct endpoint *a, const struct endpoint *b, struct endpoint *lo,
                      struct endpoint *hi) {
  if (endpoint_cmp(a, b) <= 0) {
    *lo = *a;
    *hi = *b;
  } else {
    *lo = *b;
    *hi = *a;
  }
}

static bool flow_match(const struct flow *f, int family, uint8_t proto, const struct endpoint *lo,
                       const struct endpoint *hi) {
  return f->used && f->family == family && f->proto == proto && endpoint_cmp(&f->lo, lo) == 0 &&
         endpoint_cmp(&f->hi, hi) == 0;
}

static uint32_t timeout_for(const struct conntrack *ct, uint8_t proto) {
  return proto == 6 ? ct->tcp_timeout : ct->udp_timeout;
}

static bool expired(const struct conntrack *ct, const struct flow *f, uint64_t now) {
  return now > f->last_seen + timeout_for(ct, f->proto);
}

bool conntrack_established(struct conntrack *ct, const uint8_t *frame, size_t len, uint64_t now) {
  if (ct == NULL)
    return false;
  int family;
  uint8_t proto;
  struct endpoint a, b, lo, hi;
  if (!flow_key(frame, len, &family, &proto, &a, &b))
    return false;
  normalize(&a, &b, &lo, &hi);
  for (size_t i = 0; i < ct->cap; i++) {
    struct flow *f = &ct->flows[i];
    if (flow_match(f, family, proto, &lo, &hi)) {
      if (expired(ct, f, now)) {
        f->used = false;
        return false;
      }
      f->last_seen = now;
      return true;
    }
  }
  return false;
}

void conntrack_record(struct conntrack *ct, const uint8_t *frame, size_t len, uint64_t now) {
  if (ct == NULL)
    return;
  int family;
  uint8_t proto;
  struct endpoint a, b, lo, hi;
  if (!flow_key(frame, len, &family, &proto, &a, &b))
    return;
  normalize(&a, &b, &lo, &hi);

  /* Refresh an existing entry, or claim a free/expired one, else evict the
   * least-recently-seen slot. */
  struct flow *victim = NULL;
  for (size_t i = 0; i < ct->cap; i++) {
    struct flow *f = &ct->flows[i];
    if (flow_match(f, family, proto, &lo, &hi)) {
      f->last_seen = now;
      return;
    }
    if (!f->used || expired(ct, f, now)) {
      if (victim == NULL || !f->used)
        victim = f;
    } else if (victim != NULL && victim->used && f->last_seen < victim->last_seen) {
      victim = f;
    } else if (victim == NULL) {
      victim = f;
    }
  }
  if (victim == NULL)
    victim = &ct->flows[0];
  victim->used = true;
  victim->family = family;
  victim->proto = proto;
  victim->lo = lo;
  victim->hi = hi;
  victim->last_seen = now;
}
