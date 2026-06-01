# Design: per-VM isolation and a datagram fast path

This document describes the redesign that addresses
[lima-vm/socket_vmnet#77][issue-77] ("Consider one vmnet interface per VM,
datagram-based interface"), and the adjacent issues
[#58][issue-58] (performance) and [#13][issue-13]
(`VZFileHandleNetworkDeviceAttachment` support).

It is staged in three phases so that each step is independently reviewable and
shippable. **Phase 1 is implemented in this branch and builds cleanly. Phases 0
and 2 are specified here as the agreed design target and are not yet
implemented.**

## Problem

`socket_vmnet` runs a single shared `vmnet` interface and multiplexes every
connected client (QEMU / VZ guest) onto it. Two consequences fall out of that
design:

1. **Flooding / performance.** Every frame received from `vmnet`, and every
   frame sent by a guest, is copied to *all* connected clients. With N guests
   this is O(N) duplication per packet, and guests receive traffic that is not
   addressed to them. See the two `// FIXME: avoid flooding` sites in the
   pre-existing `main.c`.
2. **No isolation.** Because all guests sit on one shared L2 segment and the
   daemon floods between them, any guest can observe (and inject into) another
   guest's traffic. There is no way to run mutually untrusting guests.

The transport itself adds a third cost: the QEMU stream protocol frames each
packet with a `uint32be` length header, forcing two `read(2)`s per packet and
preventing vectorized I/O.

## Goals

- Stop flooding: deliver unicast frames only to the client that owns the
  destination MAC.
- Offer real isolation between guests as an opt-in.
- Provide a header-less datagram transport that serves both modern QEMU
  (`-netdev dgram`, 7.2+) and Apple's `VZFileHandleNetworkDeviceAttachment`
  without a wrapper, and that allows `recvmmsg(2)`/`sendmmsg(2)` batching.
- Keep full backward compatibility with the existing `unix://` stream protocol.

## Phase 0 — datagram transport (not yet implemented)

Add a datagram endpoint alongside the existing stream socket, e.g.

```
socket_vmnet --vmnet-mode=shared \
  unix:///var/run/socket_vmnet \           # legacy QEMU stream (length-prefixed)
  unixgram:///var/run/socket_vmnet.dgram   # QEMU -netdev dgram + VZ file handle
```

- One datagram == one ethernet frame, **no `uint32be` length header**. This is
  exactly what `VZFileHandleNetworkDeviceAttachment` expects (the header
  mismatch is the blocker reported in [#13][issue-13]) and what QEMU's
  `-netdev dgram` speaks.
- The hot path uses `recvmmsg`/`sendmmsg` to batch, mirroring the existing
  `vmnet_read`/`vmnet_write` batching (`MAX_PACKET_COUNT_AT_ONCE`).
- The stream protocol (`unix://`) stays the default and is untouched, so
  existing QEMU `-netdev socket` users are unaffected.

This converges with the dual-socket proposal in [#13][issue-13].

## Phase 1 — switched forwarding + isolation (implemented in this branch)

Turn the daemon's fan-out into a learning ethernet switch.

- `struct conn` gains a learned source MAC (`uint8_t mac[6]` + `mac_known`),
  filling the pre-existing `// TODO: uint8_t mac[6];`.
- On each frame a guest sends, the daemon learns `src_mac -> connection`
  (`conn_learn_mac`).
- Forwarding decisions (both `vmnet -> sockets` and `socket -> sockets`):
  - **multicast/broadcast** (`mac[0] & 0x01`) → flood;
  - **known unicast** → switch to the single owning connection;
  - **unknown unicast** → flood until the MAC is learned (standard switch
    behavior).
- `--isolated` disables direct guest-to-guest delivery entirely. Guests still
  reach the gateway/NAT and the outside world (that traffic flows through
  `vmnet_write` / the `vmnet -> sockets` path), but they cannot see each other.
  This is a userspace isolation knob and does **not** depend on macOS 11+ or on
  the `vmnet` isolation key (see Phase 2).

This removes the O(N) duplication of [#58][issue-58] and gives a first,
spoofable-but-useful isolation option, without changing the wire protocol or
the single-interface model.

### Limitations of Phase 1

- MAC learning is **spoofable**: a malicious guest can forge a source MAC to
  hijack another guest's traffic or evade `--isolated` only insofar as it can
  reach `vmnet`'s own switching. `--isolated` blocks the daemon-level
  guest-to-guest path, but hard, non-spoofable isolation belongs to the
  framework (Phase 2).
- The MAC table lookup is O(N) per frame (matching the pre-existing
  `// TODO: avoid O(N) lookup`). A hash table keyed by MAC is the obvious
  follow-up; N is small in practice (one entry per guest).
- Forwarding now holds `state->sem` across the `writev`. This is correct (it
  closes a pre-existing race where the connection list was iterated after the
  lock was released) but serializes sends; the datagram fast path (Phase 0) and
  a finer-grained lock are the performance follow-ups.

## Phase 2 — one vmnet interface per VM (not yet implemented)

The structural fix requested in [#77][issue-77]: call `vmnet_start_interface`
**once per client** instead of sharing one interface.

- `vmnet.framework` then performs the L2 switching itself, and only delivers to
  each interface the frames addressed to its MAC (plus broadcast/multicast).
  This eliminates userspace fan-out entirely.
- Hard isolation becomes available via the framework's
  [`vmnet_enable_isolation_key`][isolation-key] set per interface (macOS 11+),
  which is not spoofable.
- Combine with a small handshake that passes a dedicated datagram fd per client:

  ```
  1. client -> control socket (SOCK_SEQPACKET): REQUEST { isolated?, mac? }
  2. daemon: vmnet_start_interface(...) -> MAC, subnet, MTU, DHCP IP, gateway/DNS
  3. daemon -> client: METADATA + per-VM datagram fd (via SCM_RIGHTS)
  4. client wires the fd into QEMU `-netdev dgram,fd=` or
     VZ `VZFileHandleNetworkDeviceAttachment(fileHandle:)`
  ```

  The fast path is then a pure datagram copy between the per-VM fd and the
  per-VM `vmnet` interface, vectorizable with `recvmmsg`/`sendmmsg`.

### Caveats to validate on real hardware

- **Scaling.** N interfaces means N software bridges and N DHCP leases.
  `vmnet` has limits on the number of interfaces; measure the ceiling and the
  per-interface overhead, and cap with a fallback to the shared-interface
  Phase 1 mode.
- **`isolated=on` conflict.** Mixing isolated and non-isolated interfaces on the
  same sharing service has been observed to fail with *"conflict, sharing
  service is in use"* (see [utmapp/UTM#4520][utm-4520]). Treat isolation as a
  per-network choice for the whole daemon, not an arbitrary per-VM mix, and
  verify empirically.
- **Version / signing requirements.** The isolation key requires macOS 11+;
  `-netdev dgram` requires QEMU 7.2+; and `vmnet` itself is gated behind SIP and
  requires the binary to be code-signed with a full Apple Developer certificate.

## Compatibility & rollout

- Phase 1 keeps the wire protocol and the single-interface model; the only
  behavioral change is that unicast is no longer flooded. `--isolated` is
  opt-in.
- Phase 0 adds a new endpoint; the stream protocol stays the default.
- Phase 2 is selectable (e.g. `--interface-per-vm`) and falls back to Phase 1.

[issue-77]: https://github.com/lima-vm/socket_vmnet/issues/77
[issue-58]: https://github.com/lima-vm/socket_vmnet/issues/58
[issue-13]: https://github.com/lima-vm/socket_vmnet/issues/13
[isolation-key]: https://developer.apple.com/documentation/vmnet/vmnet_enable_isolation_key
[utm-4520]: https://github.com/utmapp/UTM/issues/4520
