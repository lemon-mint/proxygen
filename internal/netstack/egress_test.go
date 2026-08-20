package netstack

import (
	"net"
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

func TestNewEgressEnforcesWireGuardMTUAndPublishesUp(t *testing.T) {
	if network, err := NewEgress(netip.MustParseAddr("10.10.1.2"), device.MaxContentSize+1); err == nil {
		_ = network.Close()
		t.Fatal("NewEgress() accepted an MTU larger than device.MaxContentSize")
	}

	network, err := NewEgress(netip.MustParseAddr("10.10.1.2"), 1420)
	if err != nil {
		t.Fatalf("NewEgress() error = %v", err)
	}
	defer network.Close()
	if name, err := network.Name(); err != nil || name != egressName {
		t.Fatalf("Name() = %q, %v; want %q, nil", name, err, egressName)
	}
	select {
	case event := <-network.Events():
		if event != tun.EventUp {
			t.Fatalf("initial event = %v, want EventUp", event)
		}
	default:
		t.Fatal("NewEgress() did not publish EventUp")
	}
}

func TestEgressDialUDPUsesExplicitLocalBind(t *testing.T) {
	network, err := NewEgress(netip.MustParseAddr("10.10.1.2"), 1420)
	if err != nil {
		t.Fatalf("NewEgress() error = %v", err)
	}
	defer network.Close()

	connection, err := network.DialUDP(24001, netip.MustParseAddrPort("192.0.2.1:53"))
	if err != nil {
		t.Fatalf("DialUDP() error = %v", err)
	}
	defer connection.Close()
	local, ok := connection.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("LocalAddr() type = %T, want *net.UDPAddr", connection.LocalAddr())
	}
	if local.Port != 24001 {
		t.Fatalf("LocalAddr().Port = %d, want 24001", local.Port)
	}
}
