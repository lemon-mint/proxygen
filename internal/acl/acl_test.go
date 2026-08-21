package acl

import (
	"net/netip"
	"testing"

	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/config"
	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/model"
)

func TestDefaultPolicyRejectsSpecialUseDestinations(t *testing.T) {
	policy, err := New(nil)
	if err != nil {
		t.Fatalf("New(nil): %v", err)
	}
	for _, destination := range []string{
		"10.0.0.1:443",
		"100.64.0.1:443",
		"127.0.0.1:443",
		"169.254.1.1:443",
		"192.168.1.1:443",
		"[::1]:443",
		"[fd00::1]:443",
		"[fe80::1]:443",
	} {
		if policy.Allow(flow(t, model.ProtocolTCP, destination)) {
			t.Errorf("default policy allowed special-use destination %s", destination)
		}
	}
	for _, destination := range []string{"8.8.8.8:443", "[2606:4700:4700::1111]:443"} {
		if !policy.Allow(flow(t, model.ProtocolTCP, destination)) {
			t.Errorf("default policy denied public destination %s", destination)
		}
	}
}

func TestConfiguredPolicyUsesOrderedProtocolAndPortRules(t *testing.T) {
	policy, err := New(&config.DestinationACLConfig{
		DefaultAction: "deny",
		Rules: []config.DestinationACLRule{
			{
				Action: "allow", Protocol: "tcp", Prefix: netip.MustParsePrefix("10.0.0.0/8"),
				Ports: []config.PortRange{{From: 443, To: 443}},
			},
			{Action: "deny", Protocol: "any", Prefix: netip.MustParsePrefix("10.0.0.0/8")},
			{Action: "allow", Protocol: "udp", Prefix: netip.MustParsePrefix("0.0.0.0/0")},
		},
	})
	if err != nil {
		t.Fatalf("New(configured): %v", err)
	}

	if !policy.Allow(flow(t, model.ProtocolTCP, "10.1.2.3:443")) {
		t.Fatal("ordered policy denied explicitly allowed TCP/443")
	}
	if policy.Allow(flow(t, model.ProtocolTCP, "10.1.2.3:80")) {
		t.Fatal("ordered policy allowed denied private TCP/80")
	}
	if policy.Allow(flow(t, model.ProtocolUDP, "10.1.2.3:443")) {
		t.Fatal("ordered policy ignored earlier private-network deny")
	}
	if !policy.Allow(flow(t, model.ProtocolUDP, "8.8.8.8:53")) {
		t.Fatal("ordered policy denied public UDP fallback rule")
	}
	if policy.Allow(flow(t, model.ProtocolTCP, "8.8.8.8:443")) {
		t.Fatal("ordered policy ignored default deny")
	}
}

func flow(t *testing.T, protocol model.TransportProtocol, destination string) model.FlowKey {
	t.Helper()
	destinationAddr := netip.MustParseAddrPort(destination)
	source := netip.MustParseAddrPort("10.77.0.2:40000")
	if destinationAddr.Addr().Is6() {
		source = netip.MustParseAddrPort("[fd00::2]:40000")
	}
	key, err := model.NewFlowKey(protocol, source, destinationAddr)
	if err != nil {
		t.Fatalf("NewFlowKey: %v", err)
	}
	return key
}
