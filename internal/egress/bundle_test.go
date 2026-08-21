package egress

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"git.gosuda.org/lemon-mint/proxygen/internal/config"
	"git.gosuda.org/lemon-mint/proxygen/internal/model"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

func TestEdgeUAPIConvertsKeysAndIncludesRoutes(t *testing.T) {
	cfg := validEdgeConfig()
	cfg.ListenPort = 42001
	cfg.PresharedKey = testKey(3)

	configuration, err := edgeUAPI(cfg)
	if err != nil {
		t.Fatalf("edgeUAPI() error = %v", err)
	}
	privateHex := hex.EncodeToString(bytesOf(1))
	publicHex := hex.EncodeToString(bytesOf(2))
	presharedHex := hex.EncodeToString(bytesOf(3))
	want := "private_key=" + privateHex + "\n" +
		"listen_port=42001\n" +
		"replace_peers=true\n" +
		"public_key=" + publicHex + "\n" +
		"preshared_key=" + presharedHex + "\n" +
		"endpoint=[2001:db8::10]:51820\n" +
		"persistent_keepalive_interval=25\n" +
		"replace_allowed_ips=true\n" +
		"allowed_ip=0.0.0.0/0\n\n"
	if configuration != want {
		t.Fatalf("edgeUAPI() = %q, want %q", configuration, want)
	}
}

func TestNewBundleUsesFreshBindPerEdge(t *testing.T) {
	var binds []conn.Bind
	dependencies := bundleDependencies{
		createNetwork: emptyNetwork,
		newBind:       conn.NewDefaultBind,
		newDevice: func(_ tun.Device, bind conn.Bind, _ *device.Logger) wireGuardDevice {
			binds = append(binds, bind)
			return &fakeWireGuardDevice{}
		},
	}

	first, err := newBundle(validEdgeConfig(), 1420, dependencies)
	if err != nil {
		t.Fatalf("first newBundle() error = %v", err)
	}
	secondCfg := validEdgeConfig()
	secondCfg.ID = model.EdgeID("edge-2")
	second, err := newBundle(secondCfg, 1420, dependencies)
	if err != nil {
		t.Fatalf("second newBundle() error = %v", err)
	}
	defer first.Close()
	defer second.Close()

	if len(binds) != 2 || binds[0] == binds[1] {
		t.Fatalf("newBundle() binds = %#v, want two distinct bind instances", binds)
	}
}

func TestNewBundleCleansUpConfigurationAndUpFailures(t *testing.T) {
	for _, test := range []struct {
		name   string
		ipcErr error
		upErr  error
	}{
		{name: "configuration", ipcErr: errors.New("rejected private_key=" + hex.EncodeToString(bytesOf(1)))},
		{name: "up", upErr: errors.New("bind failed")},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakeWireGuardDevice{ipcErr: test.ipcErr, upErr: test.upErr}
			dependencies := bundleDependencies{
				createNetwork: emptyNetwork,
				newBind:       conn.NewDefaultBind,
				newDevice: func(tun.Device, conn.Bind, *device.Logger) wireGuardDevice {
					return fake
				},
			}

			_, err := newBundle(validEdgeConfig(), 1420, dependencies)
			if err == nil {
				t.Fatal("newBundle() error = nil, want construction failure")
			}
			if fake.closeCalls != 1 {
				t.Fatalf("device Close() calls = %d, want 1", fake.closeCalls)
			}
			if strings.Contains(err.Error(), testKey(1)) || strings.Contains(err.Error(), hex.EncodeToString(bytesOf(1))) {
				t.Fatalf("newBundle() error exposed private key: %q", err)
			}
		})
	}
}

func TestBundleCloseIsIdempotent(t *testing.T) {
	fake := &fakeWireGuardDevice{}
	dependencies := bundleDependencies{
		createNetwork: emptyNetwork,
		newBind:       conn.NewDefaultBind,
		newDevice: func(tun.Device, conn.Bind, *device.Logger) wireGuardDevice {
			return fake
		},
	}
	bundle, err := newBundle(validEdgeConfig(), 1420, dependencies)
	if err != nil {
		t.Fatalf("newBundle() error = %v", err)
	}

	_ = bundle.Close()
	_ = bundle.Close()
	if fake.closeCalls != 1 {
		t.Fatalf("device Close() calls = %d, want 1", fake.closeCalls)
	}
}

type fakeWireGuardDevice struct {
	ipcErr     error
	upErr      error
	closeCalls int
}

func (fake *fakeWireGuardDevice) IpcSet(string) error { return fake.ipcErr }
func (fake *fakeWireGuardDevice) Up() error           { return fake.upErr }
func (fake *fakeWireGuardDevice) Close()              { fake.closeCalls++ }

func emptyNetwork(netip.Addr, int) (tun.Device, bundleNetwork, error) {
	return nil, nil, nil
}

func validEdgeConfig() config.EdgeConfig {
	return config.EdgeConfig{
		ID:                  model.EdgeID("edge-1"),
		PrivateKey:          testKey(1),
		OverlayAddress:      netip.MustParsePrefix("10.10.1.2/24"),
		PeerPublicKey:       testKey(2),
		Endpoint:            "[2001:db8::10]:51820",
		HealthCheckAddress:  "198.51.100.20:443",
		AllowedIPs:          []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		PersistentKeepalive: config.Duration(25_000_000_000),
		Geo: config.GeoConfig{
			CountryCode: "US",
			Region:      "Test Region",
			City:        "Test City",
			Latitude:    40,
			Longitude:   -70,
		},
	}
}

func testKey(fill byte) string {
	return base64.StdEncoding.EncodeToString(bytesOf(fill))
}

func bytesOf(fill byte) []byte {
	key := make([]byte, 32)
	for index := range key {
		key[index] = fill
	}
	return key
}

func TestBundleDialTCPPassesContextToLocalNetwork(t *testing.T) {
	network := &fakeBundleNetwork{}
	bundle := &Bundle{
		network:  network,
		udpPorts: newUDPPortAllocator(),
		device:   &fakeWireGuardDevice{},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := bundle.DialTCP(ctx, netip.MustParseAddrPort("192.0.2.1:443"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("DialTCP() error = %v, want context.Canceled", err)
	}
	if network.tcpContext != ctx {
		t.Fatal("DialTCP() did not pass the caller context to the local network")
	}
}

func TestBundleDialUDPReservesDestinationIndependentPortsAndReleasesOnce(t *testing.T) {
	network := &fakeBundleNetwork{}
	bundle := &Bundle{
		network:  network,
		udpPorts: newUDPPortAllocator(),
		device:   &fakeWireGuardDevice{},
	}

	first, err := bundle.DialUDP(context.Background(), netip.MustParseAddrPort("192.0.2.1:53"))
	if err != nil {
		t.Fatalf("first DialUDP() error = %v", err)
	}
	second, err := bundle.DialUDP(context.Background(), netip.MustParseAddrPort("198.51.100.2:53"))
	if err != nil {
		t.Fatalf("second DialUDP() error = %v", err)
	}
	firstPort := first.LocalAddr().(*net.UDPAddr).Port
	secondPort := second.LocalAddr().(*net.UDPAddr).Port
	if firstPort == secondPort {
		t.Fatalf("simultaneous destinations received the same local port %d", firstPort)
	}
	if len(bundle.udpPorts.active) != 2 {
		t.Fatalf("active UDP reservations = %d, want 2", len(bundle.udpPorts.active))
	}

	if err := first.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("second first.Close() error = %v", err)
	}
	if got := network.connections[0].closeCalls(); got != 1 {
		t.Fatalf("underlying first Close() calls = %d, want 1", got)
	}
	if len(bundle.udpPorts.active) != 1 {
		t.Fatalf("active UDP reservations after close = %d, want 1", len(bundle.udpPorts.active))
	}

	_ = bundle.Close()
	if got := network.connections[1].closeCalls(); got != 1 {
		t.Fatalf("underlying second Close() calls after bundle close = %d, want 1", got)
	}
	if len(bundle.udpPorts.active) != 0 {
		t.Fatalf("active UDP reservations after bundle close = %d, want 0", len(bundle.udpPorts.active))
	}
}

func TestBundleDialUDPReleasesPortWhenDialFails(t *testing.T) {
	network := &fakeBundleNetwork{udpErr: errors.New("bind failed")}
	bundle := &Bundle{
		network:  network,
		udpPorts: newUDPPortAllocator(),
		device:   &fakeWireGuardDevice{},
	}

	if _, err := bundle.DialUDP(context.Background(), netip.MustParseAddrPort("192.0.2.1:53")); err == nil {
		t.Fatal("DialUDP() error = nil, want failure")
	}
	if len(bundle.udpPorts.active) != 0 {
		t.Fatalf("active UDP reservations after failed dial = %d, want 0", len(bundle.udpPorts.active))
	}
}

type fakeBundleNetwork struct {
	tcpContext  context.Context
	udpErr      error
	connections []*fakeUDPConn
}

func (network *fakeBundleNetwork) DialTCP(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	network.tcpContext = ctx
	return nil, ctx.Err()
}

func (network *fakeBundleNetwork) DialUDP(localPort uint16, _ netip.AddrPort) (net.Conn, error) {
	if network.udpErr != nil {
		return nil, network.udpErr
	}
	connection := &fakeUDPConn{
		local: &net.UDPAddr{IP: net.IPv4(10, 10, 1, 2), Port: int(localPort)},
	}
	network.connections = append(network.connections, connection)
	return connection, nil
}

type fakeUDPConn struct {
	local  net.Addr
	mu     sync.Mutex
	closes int
}

func (*fakeUDPConn) Read([]byte) (int, error)          { return 0, net.ErrClosed }
func (*fakeUDPConn) Write(payload []byte) (int, error) { return len(payload), nil }
func (connection *fakeUDPConn) Close() error {
	connection.mu.Lock()
	connection.closes++
	connection.mu.Unlock()
	return nil
}
func (connection *fakeUDPConn) LocalAddr() net.Addr   { return connection.local }
func (*fakeUDPConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (*fakeUDPConn) SetDeadline(time.Time) error      { return nil }
func (*fakeUDPConn) SetReadDeadline(time.Time) error  { return nil }
func (*fakeUDPConn) SetWriteDeadline(time.Time) error { return nil }
func (connection *fakeUDPConn) closeCalls() int {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	return connection.closes
}
