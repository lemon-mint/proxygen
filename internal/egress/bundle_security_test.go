package egress

import (
	"net/netip"
	"strings"
	"testing"

	"git.gosuda.org/lemon-mint/proxygen/internal/config"
)

func TestEdgeUAPIRejectsAllZeroKeysWithoutEmittingConfiguration(t *testing.T) {
	zeroKey := testKey(0)
	tests := []struct {
		name   string
		change func(*config.EdgeConfig)
	}{
		{
			name: "private key",
			change: func(cfg *config.EdgeConfig) {
				cfg.PrivateKey = zeroKey
			},
		},
		{
			name: "peer public key",
			change: func(cfg *config.EdgeConfig) {
				cfg.PeerPublicKey = zeroKey
			},
		},
		{
			name: "preshared key",
			change: func(cfg *config.EdgeConfig) {
				cfg.PresharedKey = zeroKey
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validEdgeConfig()
			test.change(&cfg)

			configuration, err := edgeUAPI(cfg)
			if err == nil {
				t.Fatal("edgeUAPI() error = nil, want all-zero key rejection")
			}
			if configuration != "" {
				t.Fatalf("edgeUAPI() configuration = %q, want no emitted configuration", configuration)
			}
			if strings.Contains(err.Error(), zeroKey) {
				t.Fatalf("edgeUAPI() error exposed rejected key: %q", err)
			}
		})
	}
}

func TestEdgeUAPIRejectsNonCanonicalKeysWithoutEmittingConfiguration(t *testing.T) {
	canonical := testKey(4)
	for _, separator := range []struct {
		name  string
		value string
	}{
		{name: "carriage return", value: "\r"},
		{name: "line feed", value: "\n"},
	} {
		t.Run(separator.name, func(t *testing.T) {
			injected := canonical[:8] + separator.value + canonical[8:]
			for _, field := range []struct {
				name   string
				path   string
				change func(*config.EdgeConfig)
			}{
				{
					name: "private key",
					path: "edge.private_key",
					change: func(cfg *config.EdgeConfig) {
						cfg.PrivateKey = injected
					},
				},
				{
					name: "peer public key",
					path: "edge.peer_public_key",
					change: func(cfg *config.EdgeConfig) {
						cfg.PeerPublicKey = injected
					},
				},
				{
					name: "preshared key",
					path: "edge.preshared_key",
					change: func(cfg *config.EdgeConfig) {
						cfg.PresharedKey = injected
					},
				},
			} {
				t.Run(field.name, func(t *testing.T) {
					cfg := validEdgeConfig()
					field.change(&cfg)

					configuration, err := edgeUAPI(cfg)
					if err == nil || !strings.Contains(err.Error(), field.path) || !strings.Contains(err.Error(), "canonical base64") {
						t.Fatalf("edgeUAPI() error = %v, want canonical-key error for %s", err, field.path)
					}
					if configuration != "" {
						t.Fatalf("edgeUAPI() configuration = %q, want no emitted configuration", configuration)
					}
					if strings.Contains(err.Error(), injected) || strings.Contains(err.Error(), canonical) {
						t.Fatalf("edgeUAPI() error exposed rejected key: %q", err)
					}
				})
			}
		})
	}
}

func TestEdgeUAPIRejectsInjectedEndpointWithoutEmittingConfiguration(t *testing.T) {
	cfg := validEdgeConfig()
	injectedLine := "public_key=" + strings.Repeat("ab", 32)
	cfg.Endpoint = "[fe80::1%eth0]:1234\n" + injectedLine + "\nendpoint=[2001:db8::1]:51820"

	configuration, err := edgeUAPI(cfg)
	if err == nil {
		t.Fatal("edgeUAPI() error = nil, want injected endpoint rejection")
	}
	if configuration != "" {
		t.Fatalf("edgeUAPI() configuration = %q, want no emitted configuration", configuration)
	}
	if strings.Contains(err.Error(), injectedLine) || strings.Contains(err.Error(), "endpoint=[2001:db8::1]:51820") {
		t.Fatalf("edgeUAPI() error exposed injected lines: %q", err)
	}
}

func TestEdgeUAPIRejectsCrossFamilyAllowedIPWithoutEmittingConfiguration(t *testing.T) {
	cfg := validEdgeConfig()
	cfg.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("::/0")}

	configuration, err := edgeUAPI(cfg)
	if err == nil {
		t.Fatal("edgeUAPI() error = nil, want cross-family AllowedIP rejection")
	}
	if configuration != "" {
		t.Fatalf("edgeUAPI() configuration = %q, want no emitted configuration", configuration)
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
