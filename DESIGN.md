# Design: per-VM isolation and a datagram transport

This document describes the redesign that addresses
[lima-vm/socket_vmnet#77][issue-77] ("Consider one vmnet interface per VM,
datagram-based interface"), and the adjacent issues
[#58][issue-58] (bad scaling due to flooding) and [#13][issue-13]
(`VZFileHandleNetworkDeviceAttachment` support).

It is organized in three phases. **All three are now implemented in this
branch and build cleanly with `-Wall -Wextra -pedantic` + `clang-format`.**
None of it has been exercised at runtime yet: `vmnet` is gated behind SIP and
requires an Apple-Developer-signed binary, so the behavior must be validated on
real, code-signed macOS hardware (see [Validation](#validation)).

## Problem

`socket_vmnet` runs a single shared `vmnet` interface and multiplexes every
connected client onto it. Three costs follow:

1. **Flooding / scaling ([#58][issue-58]).** Every frame from `vmnet`, and every
   frame a guest sends, is copied to *all* clients — O(N) duplication, and idle
   guests burn CPU dropping traffic that is not theirs. Measured: throughput
   collapses from 3.52 Gbps (1 VM) to 0.81 Gbps (4 VMs); ~145% of 437% CPU is
   spent on unrelated packets.
2. **No isolation.** All guests share one L2 segment and the daemon floods
   between them, so any guest can observe/inject another guest's traffic.
3. **Transport tax.** The legacy QEMU stream protocol length-prefixes each
   packet (`uint32be`), forcing two `read(2)`s per packet. That same header is
   why Apple's `VZFileHandleNetworkDeviceAttachment` (header-less datagrams) is
   incompatible today ([#13][issue-13]).

## Phase 1 — switched forwarding + userspace isolation

Turns the daemon's fan-out into a learning ethernet switch.

- `struct conn` learns its source MAC (`mac[6]` + `mac_known`), filling the
  pre-existing `// TODO: uint8_t mac[6];`.
- `conn_learn_mac()` records `src_mac -> connection` on every guest egress frame.
- Both forwarding paths (`vmnet -> clients` and guest-to-guest) now flood
  multicast/broadcast, switch known unicast to the single owning connection, and
  flood unknown unicast until the MAC is learned — standard switch behavior,
  factored into `forward_guest_to_guest()`.
- `--isolated` disables direct guest-to-guest delivery; guests still reach the
  gateway/NAT (that traffic flows through `vmnet_write` and the `vmnet ->
  clients` path) but cannot see each other.

Removes the O(N) duplication of [#58][issue-58] without changing the wire
protocol or the single-interface model. MAC learning is **spoofable**; hard
isolation is Phase 2. The MAC lookup is O(N) (matching the existing
`// TODO: avoid O(N) lookup`); a MAC-keyed hash table is an obvious follow-up.

## Phase 0 — datagram transport

A second, header-less endpoint selected with `--socket-dgram=PATH`, alongside
the positional `SOCK_STREAM` socket (which keeps the legacy protocol).

- One datagram == one ethernet frame, **no `uint32be` length header**. This is
  what `VZFileHandleNetworkDeviceAttachment` expects (resolving the [#13][issue-13]
  mismatch) and what QEMU's `-netdev dgram` (7.2+) speaks.
- Model: the daemon `bind(2)`s one `SOCK_DGRAM` unix socket and tracks peers by
  their bound address. `recvfrom` learns the peer; `sendto` replies. A `struct
  conn` is created lazily per distinct peer (`TRANSPORT_DGRAM`), and rides the
  same MAC-switch and per-VM-interface machinery as stream connections.
- Datagrams are drained inline in the main `kqueue` loop (`on_dgram_readable`),
  single-threaded, so a peer's frames keep their order.

> **No `recvmmsg`/`sendmmsg`.** Those are Linux-only; macOS/BSD lack them. The
> datagram win here is the elimination of the length header (one `recvfrom` per
> frame instead of two `read`s), not vectorized batching. `vmnet_read`/
> `vmnet_write` still batch on the framework side.

### Limitations

- **Clients must bind a local address.** Replies use `sendto` to the peer's
  address; datagrams from an unbound peer are dropped with a warning. QEMU
  `-netdev dgram,local.type=unix,...` and a VZ launcher both bind.
- **No per-peer teardown.** Datagram sockets have no EOF, so a `conn` persists
  until daemon shutdown (no idle GC yet). Fine for the common one-peer-per-socket
  case; an idle-timeout reaper is a follow-up.
- The positional stream socket is still required even for datagram-only use.

## Phase 2 — one vmnet interface per VM

Enabled with `--interface-per-vm`. Instead of one shared interface,
`vmnet_start_interface` is called **once per client** (`start_conn_interface`),
each with its own random `vmnet_interface_id`.

- `vmnet.framework` then performs the L2 switching itself and delivers to each
  interface only the frames addressed to its MAC (plus broadcast/multicast). The
  per-interface packets-available callback forwards straight to that one client
  (`_on_vmnet_packets_available(..., only)`), so there is **no userspace
  fan-out and no shared connection-list lock on the hot path** — this is what
  removes the [#58][issue-58] scaling collapse at its root.
- `--isolated` + `--interface-per-vm` sets the framework's
  [`vmnet_enable_isolation_key`][isolation-key] per interface: hard,
  non-spoofable isolation enforced by the kernel.
- Composes with both transports (a stream or datagram client each gets its own
  interface).

### Caveats to validate on hardware

- **macOS 11+.** `vmnet_enable_isolation_key` exists only on macOS 11+. The
  symbol is referenced unconditionally; on 10.15 (still the project's stated
  floor) the dynamic loader may refuse the binary. Weak-linking the symbol, or
  raising the minimum to 11, is a required follow-up before merge.
- **Scaling.** N interfaces == N software bridges + N DHCP leases. `vmnet` caps
  the number of interfaces; measure the ceiling and per-interface overhead, and
  cap with a fallback to Phase 1.
- **`isolated=on` conflict.** Mixing isolated and non-isolated interfaces on one
  sharing service has been observed to fail with *"conflict, sharing service is
  in use"* ([utmapp/UTM#4520][utm-4520]). Treat isolation as a daemon-wide
  choice, not an arbitrary per-VM mix; verify empirically.
- **Teardown on signal.** Per-VM interfaces of still-active stream clients are
  reclaimed by the OS on process exit (their reader threads are blocked in
  `read`); the common path (client disconnect) stops the interface in
  `on_accept`. Graceful per-connection teardown on `SIGTERM` is a follow-up.

## How the pieces compose

| transport / mode | shared interface (default) | `--interface-per-vm` |
| --- | --- | --- |
| `unix://` stream | Phase 1 switched forwarding | Phase 2, per-client iface |
| `--socket-dgram` | Phase 0 + Phase 1 switch | Phase 0 + Phase 2 |
| `--isolated` | userspace block (spoofable) | framework isolation key (hard) |

Defaults are unchanged: a single shared interface with the legacy stream
protocol. Every new behavior is opt-in.

## Validation

Not yet run. The plan, reproducing [#58][issue-58]'s benchmark:

1. Build and code-sign per `README.md`; run as root.
2. 1→4 guests, `iperf3` from one guest to an external host; record throughput
   and the daemon's CPU. Compare: stock flooding vs Phase 1 (shared switched)
   vs Phase 2 (`--interface-per-vm`). Expect the multi-VM throughput collapse to
   flatten, and the "unrelated packet" CPU to drop toward zero.
3. Correctness matrix per mode: ARP/broadcast reaches all guests; unicast
   reaches only the addressed guest; `--isolated` blocks guest-to-guest while
   leaving gateway/NAT/external reachable.
4. Transport matrix: QEMU `-netdev socket` (stream) and `-netdev dgram`
   (datagram); a VZ `VZFileHandleNetworkDeviceAttachment` launcher on the
   datagram socket.

[issue-77]: https://github.com/lima-vm/socket_vmnet/issues/77
[issue-58]: https://github.com/lima-vm/socket_vmnet/issues/58
[issue-13]: https://github.com/lima-vm/socket_vmnet/issues/13
[isolation-key]: https://developer.apple.com/documentation/vmnet/vmnet_enable_isolation_key
[utm-4520]: https://github.com/utmapp/UTM/issues/4520
