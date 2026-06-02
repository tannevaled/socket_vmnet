# ACL: targeted L3/L4 filtering (Phase 3)

`socket_vmnet --acl=PATH` applies a **stateless** access-control list to guest
traffic. Because the daemon is the chokepoint for every frame (guest↔guest and
guest↔external), it can filter on L2/L3/L4 fields without touching the guests
and without `pf` (which would require manipulating global, root-only host
firewall state — at odds with the rootless-client model). The daemon already
runs as root for `vmnet`, so the ACL adds no privilege and is scoped to its own
traffic.

Filtering is **stateless by default** (each frame judged on its own); pass
`--stateful` to additionally track TCP/UDP flows so the return traffic of an
allowed flow is permitted automatically (see [Stateful mode](#stateful-mode---stateful)).
Both IPv4 and IPv6 are matched.

## Authoring: HCL

The daemon reads HCL directly -- pass a `.hcl` path to `--acl` and the built-in
parser compiles it (a `.json` path is parsed as JSON instead):

```console
$ sudo socket_vmnet --acl=example.hcl --interface-per-vm /var/run/socket_vmnet
```

(The `contrib/hcl2acl` Go helper, which emits the JSON form, remains available
for pipelines that prefer to pre-compile: `go run ./contrib/hcl2acl example.hcl
> example.acl.json`. It is no longer required at runtime.)

HCL groups VMs by MAC and lets you attach rules to a group; each group rule is
expanded over its members into flat, MAC-matched rules (egress rules bind to the
member's source MAC, ingress rules to the destination MAC):

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
| `src_cidr`, `dst_cidr` | `a.b.c.d/n` or `2001:db8::/32` | IPv4 or IPv6; only matches frames of the same family |
| `proto` | `tcp` \| `udp` \| `icmp` \| `icmpv6` \| `any` (default) | |
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

## Stateful mode (`--stateful`)

By default the ACL is stateless: an `allow` on egress does **not** implicitly
permit the reply. With `--stateful`, the daemon tracks TCP/UDP flows by
normalized 5-tuple, so once a flow is allowed in one direction its return
traffic is permitted automatically (idle timeouts: TCP 120 s, UDP 30 s):

```bash
socket_vmnet --acl=policy.acl.json --stateful /var/run/socket_vmnet
```

This lets you write a default-deny egress policy without having to enumerate
ephemeral-port ingress rules for the replies. Connection state survives a SIGHUP
reload. ICMP is not tracked.

## Live reload (SIGHUP)

Send `SIGHUP` to reload the ACL file in place without dropping connections:

```bash
kill -HUP "$(cat /var/run/socket_vmnet.pid)"
```

If the new file fails to parse, the previous ruleset (and connection state) is
kept and an error is logged.

## Limitations

- **No fragments / no L4 options.** Ports are read from the first L4 header; IP
  fragments after the first are treated as having no ports.
- **IPv6 extension headers.** For IPv6 only the fixed 40-byte header is parsed;
  if the next header is an extension header, transport ports are not matched.
- **`icmp` vs `icmpv6`.** `proto = "icmp"` matches IPv4 ICMP (1); use
  `proto = "icmpv6"` (58) for IPv6.

## Testing the ACL integration

### Offline smoke (no root)

`make test.acl` builds the daemon and runs `test/acl_smoke.sh`, which exercises
the real daemon load path — `main.c`'s `load_acl_file` → libfw/c-fw
`acl_load_hcl` (via libhcl/c-hcl) for `.hcl`, `acl_load` (via the built-in JSON
parser) for `.json`. The daemon only *warns* when run without root and loads the
ACL **before** it touches vmnet.framework, so the smoke can assert:

- a valid `.hcl` / `.json` ruleset is reported as `acl: loaded N rule(s)` and
  the run proceeds to the (expected) `vmnet_start_interface` failure;
- a malformed ruleset fails closed (`failed to compile`) and never reaches
  vmnet.

This is run as part of `make test`. It does **not** move any frames — it proves
the parse/load wiring, not the datapath.

### Live test (needs root + a Lima guest)

The datapath itself — frames actually filtered as they flow through a guest —
requires `vmnet.framework`, which needs **root** and a code-signed binary, plus
a real VM. This cannot run in CI/sandbox; do it manually:

```bash
# 1. Build + install (signs the binary, installs the launchd helper).
make
sudo make install                      # or: install.bin install.launchd

# 2. Author a policy and start the daemon with it (root, via launchd or directly).
sudo socket_vmnet --acl=/etc/socket_vmnet/acl.hcl \
                  --vmnet-gateway=192.168.105.1 \
                  /var/run/socket_vmnet

# 3. Point a Lima VM at the socket and boot it.
#    In the lima.yaml networks: stanza:
#      networks:
#        - socket: "/var/run/socket_vmnet"
limactl start ./lima.yaml

# 4. From inside the guest, verify the policy:
#    - an "allow" destination succeeds, a "deny" one times out / is refused;
#    - return traffic of an allowed flow passes (with --stateful);
#    - `kill -HUP $(cat /var/run/socket_vmnet.pid)` hot-reloads the ruleset.
```

Frames not matched by any rule fall through to `default_action`. See the
`--stateful` and SIGHUP sections above for conntrack and live-reload behavior.
