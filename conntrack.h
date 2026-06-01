#ifndef SOCKET_VMNET_CONNTRACK_H
#define SOCKET_VMNET_CONNTRACK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// A small stateless-rule companion: a connection tracker so that the return
// traffic of an allowed flow is permitted without an explicit reverse rule.
// Only TCP and UDP are tracked (by normalized 5-tuple); other protocols are
// never "established". Time is supplied by the caller (seconds) so the logic is
// deterministic and unit-testable.
struct conntrack;

struct conntrack *conntrack_new(size_t capacity, uint32_t tcp_timeout, uint32_t udp_timeout);
void conntrack_free(struct conntrack *ct);

// True if the frame belongs to a flow already recorded and not expired at
// `now`. Refreshes the flow's last-seen time on a hit.
bool conntrack_established(struct conntrack *ct, const uint8_t *frame, size_t len, uint64_t now);

// Record (insert or refresh) the frame's flow as of `now`.
void conntrack_record(struct conntrack *ct, const uint8_t *frame, size_t len, uint64_t now);

#endif /* SOCKET_VMNET_CONNTRACK_H */
