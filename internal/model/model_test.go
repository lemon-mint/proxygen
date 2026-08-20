package model

import (
	"net/netip"
	"testing"
)

func TestFlowKeyDistinguishesEveryTupleComponent(t *testing.T) {
	base := mustFlowKey(t, ProtocolUDP, "192.0.2.10:40000", "198.51.100.20:53")
	tests := map[string]FlowKey{
		"protocol": {
			IPVersion: IPv4, Protocol: ProtocolTCP,
			SourceAddr: base.SourceAddr, SourcePort: base.SourcePort,
			DestinationAddr: base.DestinationAddr, DestinationPort: base.DestinationPort,
		},
		"source address":      mustFlowKey(t, ProtocolUDP, "192.0.2.11:40000", "198.51.100.20:53"),
		"source port":         mustFlowKey(t, ProtocolUDP, "192.0.2.10:40001", "198.51.100.20:53"),
		"destination address": mustFlowKey(t, ProtocolUDP, "192.0.2.10:40000", "198.51.100.21:53"),
		"destination port":    mustFlowKey(t, ProtocolUDP, "192.0.2.10:40000", "198.51.100.20:54"),
	}

	for name, candidate := range tests {
		t.Run(name, func(t *testing.T) {
			if candidate == base {
				t.Fatalf("changed %s did not change the comparable flow key", name)
			}
		})
	}
}

func TestFlowKeyDistinguishesDestinationsInMap(t *testing.T) {
	first := mustFlowKey(t, ProtocolUDP, "[2001:db8::10]:40000", "[2001:db8:1::20]:53")
	second := mustFlowKey(t, ProtocolUDP, "[2001:db8::10]:40000", "[2001:db8:2::20]:53")

	flows := map[FlowKey]string{first: "first", second: "second"}
	if len(flows) != 2 {
		t.Fatalf("full flow keys collapsed distinct destinations: %#v", flows)
	}
}

func TestNewFlowKeyCanonicalizesMappedIPv4(t *testing.T) {
	key, err := NewFlowKey(
		ProtocolTCP,
		netip.MustParseAddrPort("[::ffff:192.0.2.10]:1234"),
		netip.MustParseAddrPort("[::ffff:198.51.100.20]:443"),
	)
	if err != nil {
		t.Fatalf("NewFlowKey() error = %v", err)
	}
	if key.IPVersion != IPv4 || !key.SourceAddr.Is4() || !key.DestinationAddr.Is4() {
		t.Fatalf("NewFlowKey() did not canonicalize mapped IPv4 addresses: %#v", key)
	}
}

func mustFlowKey(t *testing.T, protocol TransportProtocol, source, destination string) FlowKey {
	t.Helper()
	key, err := NewFlowKey(protocol, netip.MustParseAddrPort(source), netip.MustParseAddrPort(destination))
	if err != nil {
		t.Fatalf("NewFlowKey() error = %v", err)
	}
	return key
}
