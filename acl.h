#ifndef SOCKET_VMNET_ACL_H
#define SOCKET_VMNET_ACL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// A stateless L3/L4 access-control list, loaded from the compact JSON emitted
// by the `hcl2acl` helper. Rules are evaluated first-match-wins; if no rule
// matches, the list's default action applies.
//
// This is intentionally stateless: there is no connection tracking, so a rule
// that allows egress does not implicitly allow the return traffic. Stateful
// security groups (conntrack) are a planned follow-up.
struct acl;

// Direction of a frame relative to a guest:
//   ACL_EGRESS  - a frame a guest is sending (socket -> vmnet / other guests)
//   ACL_INGRESS - a frame being delivered to guests (vmnet -> socket)
enum acl_dir {
  ACL_EGRESS,
  ACL_INGRESS,
};

// Load and compile an ACL from a JSON file. Returns NULL on error (logged).
struct acl *acl_load(const char *path);

// Parse and compile an ACL from an in-memory JSON buffer (no filesystem
// access). Returns NULL on error (logged). Used by acl_load and by tests.
struct acl *acl_parse(const char *json, size_t len);

// Return true if `frame` (a full ethernet frame of `len` bytes) is permitted in
// the given direction. Non-IPv4 frames (e.g. ARP, IPv6) are always allowed in
// this first version; see ACL.md.
bool acl_allows(const struct acl *acl, enum acl_dir dir, const uint8_t *frame, size_t len);

// Named acl_destroy (not acl_free) to avoid clashing with the POSIX
// acl_free(void *) declared in <sys/acl.h>.
void acl_destroy(struct acl *acl);

#endif /* SOCKET_VMNET_ACL_H */
