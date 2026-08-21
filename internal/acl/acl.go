// Package acl evaluates immutable destination policies for admitted client flows.
package acl

import (
	"fmt"
	"net/netip"

	"git.gosuda.org/lemon-mint/proxygen/internal/config"
	"git.gosuda.org/lemon-mint/proxygen/internal/model"
)

type action uint8

const (
	actionDeny action = iota
	actionAllow
)

type protocol uint8

const (
	protocolAny protocol = iota
	protocolTCP
	protocolUDP
)

type rule struct {
	action   action
	protocol protocol
	prefix   netip.Prefix
	ports    []config.PortRange
}

// Policy is an immutable, first-match destination ACL.
type Policy struct {
	defaultAction action
	rules         []rule
}

// New validates and compiles configured. A nil configuration installs the
// built-in Internet-exit policy, which rejects special-use destinations.
func New(configured *config.DestinationACLConfig) (*Policy, error) {
	if configured == nil {
		configured = defaultInternetPolicy()
	}
	if err := configured.Validate(); err != nil {
		return nil, fmt.Errorf("invalid destination ACL: %w", err)
	}
	policy := &Policy{
		defaultAction: parseAction(configured.DefaultAction),
		rules:         make([]rule, 0, len(configured.Rules)),
	}
	for _, configuredRule := range configured.Rules {
		policy.rules = append(policy.rules, rule{
			action:   parseAction(configuredRule.Action),
			protocol: parseProtocol(configuredRule.Protocol),
			prefix:   configuredRule.Prefix,
			ports:    append([]config.PortRange(nil), configuredRule.Ports...),
		})
	}
	return policy, nil
}

// Allow reports whether key is admitted. Invalid keys are denied.
func (policy *Policy) Allow(key model.FlowKey) bool {
	if policy == nil || key.Validate() != nil {
		return false
	}
	for _, rule := range policy.rules {
		if !rule.matches(key) {
			continue
		}
		return rule.action == actionAllow
	}
	return policy.defaultAction == actionAllow
}

func (rule rule) matches(key model.FlowKey) bool {
	if !rule.prefix.Contains(key.DestinationAddr) {
		return false
	}
	switch rule.protocol {
	case protocolTCP:
		if key.Protocol != model.ProtocolTCP {
			return false
		}
	case protocolUDP:
		if key.Protocol != model.ProtocolUDP {
			return false
		}
	}
	if len(rule.ports) == 0 {
		return true
	}
	for _, portRange := range rule.ports {
		if key.DestinationPort >= portRange.From && key.DestinationPort <= portRange.To {
			return true
		}
	}
	return false
}

func parseAction(value string) action {
	if value == "allow" {
		return actionAllow
	}
	return actionDeny
}

func parseProtocol(value string) protocol {
	switch value {
	case "tcp":
		return protocolTCP
	case "udp":
		return protocolUDP
	default:
		return protocolAny
	}
}

func defaultInternetPolicy() *config.DestinationACLConfig {
	denied := []string{
		"0.0.0.0/8",
		"10.0.0.0/8",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"192.168.0.0/16",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"224.0.0.0/4",
		"240.0.0.0/4",
		"::/128",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
		"ff00::/8",
		"2001:db8::/32",
	}
	rules := make([]config.DestinationACLRule, 0, len(denied))
	for _, prefix := range denied {
		rules = append(rules, config.DestinationACLRule{
			Action:   "deny",
			Protocol: "any",
			Prefix:   netip.MustParsePrefix(prefix),
		})
	}
	return &config.DestinationACLConfig{DefaultAction: "allow", Rules: rules}
}
