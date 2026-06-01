# ACL: targeted L3/L4 filtering (Phase 3)

`socket_vmnet --acl=PATH` applies a **stateless** access-control list to guest
traffic. Because the daemon is the chokepoint for every frame (guest↔guest and
guest↔external), it can filter on L2/L3/L4 fields without touching the guests
and without `pf` (which would require manipulating global, root-only host
firewall state — at odds with the rootless-client model). The daemon already
runs as root for `vmnet`, so the ACL adds no privilege and is scoped to its own
traffic.

This first version is **stateless**: there is no connection tracking, so an
allow rule does **not** implicitly permit the return traffic. Stateful security
groups (conntrack) are a planned follow-up.

## Authoring: HCL → JSON

Write policy in HCL and compile it to the JSON the daemon loads, using the
`contrib/hcl2acl` helper:

```console
$ go run ./contrib/hcl2acl example.hcl > example.acl.json
$ sudo socket_vmnet --acl=example.acl.json --interface-per-vm /var/run/socket_vmnet
```

HCL groups VMs by MAC and lets you attach rules to a group; the helper expands
each group rule over its members into flat, MAC-matched rules (egress rules bind
to the member's source MAC, ingress rules to the destination MAC):

```hcl
default_action = "allow"

group "web" {
  member_mac = ["de:ad:be:ef:00:01", "de:ad:be:ef:00:02"]

  rule {
    action    = "allow"
    direction = "ingress"
    proto     = "tcp"
    dst_port  = 443
  }
  rule {
    action    = "deny"
    direction = "egress"
    dst_cidr  = "10.0.0.0/8"
  }
}

rule { # global, no group binding
  action    = "deny"
  direction = "egress"
  proto     = "tcp"
  dst_port  = 25
}
```

## JSON schema (what the C daemon consumes)

```json
{
  "default_action": "allow",
  "rules": [
    {
      "action":    "deny",
      "direction": "egress",
      "src_mac":   "de:ad:be:ef:00:01",
      "dst_mac":   "de:ad:be:ef:00:02",
      "src_cidr":  "192.168.105.0/24",
      "dst_cidr":  "10.0.0.0/8",
      "proto":     "tcp",
      "src_port":  12345,
      "dst_port":  [1000, 2000]
    }
  ]
}
```

| field | values | notes |
| --- | --- | --- |
| `default_action` | `allow` (default) \| `deny` | applied when no rule matches |
| `action` | `allow` \| `deny` | required |
| `direction` | `egress` \| `ingress` \| `any` (default) | egress = guest→; ingress = →guest |
| `src_mac`, `dst_mac` | `aa:bb:cc:dd:ee:ff` | optional ethernet match |
| `src_cidr`, `dst_cidr` | `a.b.c.d/n` | optional IPv4 match |
| `proto` | `tcp` \| `udp` \| `icmp` \| `any` (default) | |
| `src_port`, `dst_port` | `N` or `[min, max]` | only for tcp/udp |

Rules are evaluated **first-match-wins**; the first rule whose every present
field matches decides the verdict. If none match, `default_action` applies.

## Enforcement model

| point | direction checked | on deny |
| --- | --- | --- |
| client → vmnet (`on_accept`, `on_dgram`) | `egress` | frame dropped (no vmnet write, no guest-to-guest) |
| vmnet → client (`_on_vmnet_packets_available`) | `ingress` | frame not delivered |

If `--acl` is given and the file fails to parse, the daemon **refuses to start**
(fail-closed) rather than running unfiltered.

## Limitations (v1)

- **Stateless.** No conntrack; allow egress does not auto-allow the reply. Write
  explicit ingress rules, or use `default_action = "allow"` with targeted denies.
- **IPv4 only.** Non-IPv4 frames (ARP, IPv6) are always allowed so basic
  networking keeps working; IPv6 filtering is a follow-up.
- **No fragments / no L4 options.** Ports are read from the first L4 header; IP
  fragments after the first are treated as having no ports.
- **Reload requires restart.** No live reload yet (SIGHUP is a follow-up).
