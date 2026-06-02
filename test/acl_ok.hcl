# Valid ACL policy for the offline load smoke-test.
default_action = "allow"

group "web" {
  member_mac = ["de:ad:be:ef:00:01", "de:ad:be:ef:00:02"]
  rule { action = "allow" direction = "ingress" proto = "tcp" dst_port = 443 }
  rule { action = "deny"  direction = "egress"  dst_cidr = "10.0.0.0/8" }
}

rule { action = "deny" direction = "egress" proto = "tcp" dst_port = 25 }
