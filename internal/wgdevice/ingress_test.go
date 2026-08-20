package wgdevice

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"

	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/config"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

func TestIngressUAPIConvertsKeysAndRestrictsPeerAddresses(t *testing.T) {
	cfg := validIngressConfig()

	configuration, err := ingressUAPI(cfg)
	if err != nil {
		t.Fatalf("ingressUAPI() error = %v", err)
	}
	want := "private_key=" + hex.EncodeToString(bytesOf(1)) + "\n" +
		"listen_port=51820\n" +
		"replace_peers=true\n" +
		"public_key=" + hex.EncodeToString(bytesOf(2)) + "\n" +
		"replace_allowed_ips=true\n" +
		"allowed_ip=10.0.0.2/32\n" +
		"public_key=" + hex.EncodeToString(bytesOf(3)) + "\n" +
		"replace_allowed_ips=true\n" +
		"allowed_ip=10.0.0.3/32\n\n"
	if configuration != want {
		t.Fatalf("ingressUAPI() = %q, want %q", configuration, want)
	}
}

func TestIngressUAPIRejectsAllZeroKeysWithoutEmittingConfiguration(t *testing.T) {
	zeroKey := testKey(0)
	tests := []struct {
		name   string
		change func(*config.IngressConfig)
	}{
		{
			name: "private key",
			change: func(cfg *config.IngressConfig) {
				cfg.PrivateKey = zeroKey
			},
		},
		{
			name: "peer public key",
			change: func(cfg *config.IngressConfig) {
				cfg.Peers[0].PublicKey = zeroKey
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validIngressConfig()
			test.change(&cfg)

			configuration, err := ingressUAPI(cfg)
			if err == nil {
				t.Fatal("ingressUAPI() error = nil, want all-zero key rejection")
			}
			if configuration != "" {
				t.Fatalf("ingressUAPI() configuration = %q, want no emitted configuration", configuration)
			}
			if strings.Contains(err.Error(), zeroKey) {
				t.Fatalf("ingressUAPI() error exposed rejected key: %q", err)
			}
		})
	}
}

func TestKeyToHexRejectsAllZeroKey(t *testing.T) {
	encoded := testKey(0)

	converted, err := keyToHex(encoded)
	if err == nil {
		t.Fatal("keyToHex() error = nil, want all-zero key rejection")
	}
	if converted != "" {
		t.Fatalf("keyToHex() = %q, want empty output", converted)
	}
	if strings.Contains(err.Error(), encoded) {
		t.Fatalf("keyToHex() error exposed rejected key: %q", err)
	}
}

func TestNewIngressCleansUpConfigurationAndUpFailures(t *testing.T) {
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
			dependencies := ingressDependencies{
				newBind: conn.NewDefaultBind,
				newDevice: func(tun.Device, conn.Bind, *device.Logger) wireGuardDevice {
					return fake
				},
			}

			_, err := newIngress(validIngressConfig(), testTunnel{}, dependencies)
			if err == nil {
				t.Fatal("newIngress() error = nil, want construction failure")
			}
			if fake.closeCalls != 1 {
				t.Fatalf("device Close() calls = %d, want 1", fake.closeCalls)
			}
			if strings.Contains(err.Error(), testKey(1)) || strings.Contains(err.Error(), hex.EncodeToString(bytesOf(1))) {
				t.Fatalf("newIngress() error exposed private key: %q", err)
			}
		})
	}
}

func TestIngressCloseIsIdempotent(t *testing.T) {
	fake := &fakeWireGuardDevice{}
	dependencies := ingressDependencies{
		newBind: conn.NewDefaultBind,
		newDevice: func(tun.Device, conn.Bind, *device.Logger) wireGuardDevice {
			return fake
		},
	}
	ingress, err := newIngress(validIngressConfig(), testTunnel{}, dependencies)
	if err != nil {
		t.Fatalf("newIngress() error = %v", err)
	}

	_ = ingress.Close()
	_ = ingress.Close()
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

type testTunnel struct{}

func (testTunnel) File() *os.File                             { return nil }
func (testTunnel) Read([][]byte, []int, int) (int, error)     { return 0, nil }
func (testTunnel) Write(packets [][]byte, _ int) (int, error) { return len(packets), nil }
func (testTunnel) MTU() (int, error)                          { return 1420, nil }
func (testTunnel) Name() (string, error)                      { return "test", nil }
func (testTunnel) Events() <-chan tun.Event                   { return make(chan tun.Event) }
func (testTunnel) Close() error                               { return nil }
func (testTunnel) BatchSize() int                             { return 1 }

func validIngressConfig() config.IngressConfig {
	return config.IngressConfig{
		PrivateKey:     testKey(1),
		ListenPort:     51820,
		OverlayAddress: netip.MustParsePrefix("10.0.0.1/24"),
		Peers: []config.IngressPeerConfig{
			{PublicKey: testKey(2), OverlayAddress: netip.MustParseAddr("10.0.0.2")},
			{PublicKey: testKey(3), OverlayAddress: netip.MustParseAddr("10.0.0.3")},
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
