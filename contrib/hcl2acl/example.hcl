# Example socket_vmnet ACL policy.
#
#   go run . example.hcl > example.acl.json
#   socket_vmnet --acl=example.acl.json --interface-per-vm /var/run/socket_vmnet
#
# Frames not matched by any rule fall through to default_action.

default_action = "allow"

# A "web" group: two VMs identified by MAC. Group rules are expanded over every
# member (egress rules bind to the member's source MAC, ingress to the dest).
group "web" {
  member_mac = [
    "de:ad:be:ef:00:01",
    "de:ad:be:ef:00:02",
  ]

  # Allow inbound HTTPS to the web VMs.
  rule {
    action    = "allow"
    direction = "ingress"
    proto     = "tcp"
    dst_port  = 443
  }

  # Block these VMs from reaching the internal 10.0.0.0/8 range.
  rule {
    action    = "deny"
    direction = "egress"
    dst_cidr  = "10.0.0.0/8"
  }
}

# A global rule (no group binding): deny outbound SMTP from anyone.
rule {
  action    = "deny"
  direction = "egress"
  proto     = "tcp"
  dst_port  = 25
}
