#ifndef SOCKET_VMNET_HCL_H
#define SOCKET_VMNET_HCL_H

#include <stddef.h>

// A small parser for the declarative HCL subset used by ACL policies (blocks,
// labels, attributes, and scalar/list values -- no expressions, functions or
// interpolation). It compiles that to the compact ACL JSON consumed by acl.c,
// so the daemon can read .hcl directly without the Go hcl2acl helper.
struct acl;

// Translate HCL policy text to ACL JSON. Returns a malloc'd, NUL-terminated
// JSON string (caller frees), or NULL on a parse error (logged).
char *hcl_to_json(const char *src, size_t len);

// Load and compile an HCL policy file (hcl_to_json + acl_parse).
struct acl *hcl_load(const char *path);

#endif /* SOCKET_VMNET_HCL_H */
