// Command hcl2acl compiles a human-friendly HCL security-group description into
// the compact JSON ACL consumed by `socket_vmnet --acl=PATH`.
//
//	hcl2acl policy.hcl > policy.acl.json
//	socket_vmnet --acl=policy.acl.json /var/run/socket_vmnet
//
// HCL lets you express named groups with member MAC addresses and rules; this
// tool expands each group rule over its members into the flat, MAC-matched rule
// list that the C daemon evaluates first-match-wins. Egress rules bind to the
// member's source MAC; ingress rules bind to the destination MAC.
//
// Note: the daemon's filtering is stateless (no conntrack); an allow rule does
// not implicitly permit the return traffic. See ACL.md.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/hashicorp/hcl/v2/hclsimple"
)

// --- HCL input schema ---

type Config struct {
	DefaultAction string  `hcl:"default_action,optional"`
	Groups        []Group `hcl:"group,block"`
	Rules         []Rule  `hcl:"rule,block"` // global rules (no group binding)
}

type Group struct {
	Name      string   `hcl:"name,label"`
	MemberMAC []string `hcl:"member_mac,optional"`
	Rules     []Rule   `hcl:"rule,block"`
}

type Rule struct {
	Action    string `hcl:"action"`
	Direction string `hcl:"direction,optional"` // egress | ingress | any (default any)
	SrcMAC    string `hcl:"src_mac,optional"`
	DstMAC    string `hcl:"dst_mac,optional"`
	SrcCIDR   string `hcl:"src_cidr,optional"`
	DstCIDR   string `hcl:"dst_cidr,optional"`
	Proto     string `hcl:"proto,optional"` // tcp | udp | icmp | any
	SrcPort   *int   `hcl:"src_port,optional"`
	DstPort   *int   `hcl:"dst_port,optional"`
	SrcPorts  []int  `hcl:"src_ports,optional"` // [min, max]
	DstPorts  []int  `hcl:"dst_ports,optional"` // [min, max]
}

// --- JSON output schema (matches acl.c) ---

type jRule struct {
	Action    string `json:"action"`
	Direction string `json:"direction,omitempty"`
	SrcMAC    string `json:"src_mac,omitempty"`
	DstMAC    string `json:"dst_mac,omitempty"`
	SrcCIDR   string `json:"src_cidr,omitempty"`
	DstCIDR   string `json:"dst_cidr,omitempty"`
	Proto     string `json:"proto,omitempty"`
	SrcPort   any    `json:"src_port,omitempty"` // int or [min,max]
	DstPort   any    `json:"dst_port,omitempty"`
}

type jACL struct {
	DefaultAction string  `json:"default_action,omitempty"`
	Rules         []jRule `json:"rules"`
}

func portValue(single *int, rng []int) any {
	if single != nil {
		return *single
	}
	if len(rng) == 2 {
		return rng
	}
	return nil
}

// base translates a Rule's transport/address fields (everything except the
// direction and the MAC binding, which the caller sets).
func base(r Rule) jRule {
	return jRule{
		Action:  r.Action,
		SrcCIDR: r.SrcCIDR,
		DstCIDR: r.DstCIDR,
		Proto:   r.Proto,
		SrcPort: portValue(r.SrcPort, r.SrcPorts),
		DstPort: portValue(r.DstPort, r.DstPorts),
	}
}

func compile(cfg Config) (jACL, error) {
	out := jACL{DefaultAction: cfg.DefaultAction}

	// Global rules pass through unchanged (their MACs, if any, are honored).
	for _, r := range cfg.Rules {
		jr := base(r)
		jr.Direction = r.Direction
		jr.SrcMAC = r.SrcMAC
		jr.DstMAC = r.DstMAC
		out.Rules = append(out.Rules, jr)
	}

	for _, g := range cfg.Groups {
		if len(g.MemberMAC) == 0 {
			return jACL{}, fmt.Errorf("group %q has no member_mac", g.Name)
		}
		for _, r := range g.Rules {
			for _, mac := range g.MemberMAC {
				switch r.Direction {
				case "", "any":
					// Bind egress on src and ingress on dst.
					eg := base(r)
					eg.Direction = "egress"
					eg.SrcMAC = mac
					in := base(r)
					in.Direction = "ingress"
					in.DstMAC = mac
					out.Rules = append(out.Rules, eg, in)
				case "egress":
					jr := base(r)
					jr.Direction = "egress"
					jr.SrcMAC = mac
					out.Rules = append(out.Rules, jr)
				case "ingress":
					jr := base(r)
					jr.Direction = "ingress"
					jr.DstMAC = mac
					out.Rules = append(out.Rules, jr)
				default:
					return jACL{}, fmt.Errorf("group %q: invalid direction %q", g.Name, r.Direction)
				}
			}
		}
	}
	return out, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s POLICY.hcl > policy.acl.json\n", os.Args[0])
		os.Exit(2)
	}
	var cfg Config
	if err := hclsimple.DecodeFile(os.Args[1], nil, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "hcl2acl: %v\n", err)
		os.Exit(1)
	}
	acl, err := compile(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hcl2acl: %v\n", err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(acl); err != nil {
		fmt.Fprintf(os.Stderr, "hcl2acl: %v\n", err)
		os.Exit(1)
	}
}
