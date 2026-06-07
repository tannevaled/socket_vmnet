#ifndef SOCKET_VMNET_CLI_H
#define SOCKET_VMNET_CLI_H

#include <stdbool.h>
#include <uuid/uuid.h>

#include <vmnet/vmnet.h>

struct cli_options {
  // --socket-group
  char *socket_group;
  // --vmnet-mode, corresponds to vmnet_operation_mode_key
  operating_modes_t vmnet_mode;
  // --vmnet-interface, corresponds to vmnet_shared_interface_name_key
  char *vmnet_interface;
  // --vmnet-gateway, corresponds to vmnet_start_address_key
  char *vmnet_gateway;
  // --vmnet-dhcp-end, corresponds to vmnet_end_address_key
  char *vmnet_dhcp_end;
  // --vmnet-mask, corresponds to vmnet_subnet_mask_key
  char *vmnet_mask;
  // --vmnet-interface-id, corresponds to vmnet_interface_id_key
  uuid_t vmnet_interface_id;
  // --vmnet-network-identifier, corresponds to vmnet_network_identifier_key
  uuid_t vmnet_network_identifier;
  // --vmnet-nat66-prefix, corresponds to vmnet_nat66_prefix_key
  char *vmnet_nat66_prefix;
  // -p, --pidfile; writes pidfile using permissions of socket_vmnet
  char *pidfile;
  // --isolated; drop guest-to-guest traffic (guests can still reach the
  // gateway/NAT, but they cannot see each other). In --interface-per-vm mode
  // this is enforced by vmnet's own isolation key (hard, non-spoofable).
  bool isolated;
  // --interface-per-vm (Phase 2); start a dedicated vmnet interface per client
  // so that vmnet.framework performs the L2 switching itself
  bool interface_per_vm;
  // --socket-dgram=PATH (Phase 0); additional header-less SOCK_DGRAM endpoint,
  // consumed by QEMU `-netdev dgram` and Apple's
  // VZFileHandleNetworkDeviceAttachment. The positional stream socket keeps the
  // legacy uint32be-length-prefixed protocol.
  char *socket_dgram_path;
  // --acl=PATH (Phase 3); JSON access-control list (see hcl2acl) applied to
  // guest egress and ingress for targeted L3/L4 filtering.
  char *acl_path;
  // --stateful; track TCP/UDP flows so return traffic of an allowed flow is
  // permitted without an explicit reverse rule. Requires --acl.
  bool stateful;
  // --control-socket=PATH; a local UNIX socket exposing the firewall stats +
  // control plane (JSON) for an out-of-process UI. NULL = disabled.
  char *control_path;
  // arg (the positional SOCK_STREAM socket; legacy QEMU `-netdev socket`)
  char *socket_path;
};

struct cli_options *cli_options_parse(int argc, char *argv[]);
void cli_options_destroy(struct cli_options *);

#endif /* SOCKET_VMNET_CLI_H */
