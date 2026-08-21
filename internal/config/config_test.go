package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"git.gosuda.org/lemon-mint/proxygen/internal/model"
	"golang.zx2c4.com/wireguard/device"
)

func TestDecodeRejectsUnknownFields(t *testing.T) {
	encoded := marshalConfig(t, validConfig())
	encoded = append([]byte(`{"unexpected":true,`), encoded[1:]...)

	_, err := Decode(bytes.NewReader(encoded))
	if err == nil || !strings.Contains(err.Error(), `unknown field "unexpected"`) {
		t.Fatalf("Decode() error = %v, want concrete unknown-field error", err)
	}
}

func TestDecodeRejectsTrailingJSONValue(t *testing.T) {
	encoded := append(marshalConfig(t, validConfig()), []byte(` {}`)...)

	_, err := Decode(bytes.NewReader(encoded))
	if err == nil || !strings.Contains(err.Error(), "multiple JSON values") {
		t.Fatalf("Decode() error = %v, want multiple-value error", err)
	}
}

func TestDecodeAppliesDefaults(t *testing.T) {
	cfg := validConfig()
	cfg.MTU = 0
	cfg.Timeouts = TimeoutConfig{}
	cfg.Limits = LimitsConfig{}
	encoded := marshalConfig(t, cfg)

	var document map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	delete(document, "mtu")
	delete(document, "timeouts")
	delete(document, "limits")
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	decoded, err := Decode(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if decoded.MTU != DefaultMTU || decoded.Timeouts.UDPIdle.Std() != DefaultUDPIdleTimeout || decoded.Limits.MaxUDPFlows != DefaultMaxUDPFlows {
		t.Fatalf("Decode() did not apply defaults: %#v", decoded)
	}
}

func TestValidateRejectsUDPFlowLimitAboveMemoryBound(t *testing.T) {
	cfg := validConfig()
	cfg.Limits.MaxUDPFlows = model.MaxUDPFlows + 1

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("limits.max_udp_flows must be between 1 and %d", model.MaxUDPFlows)) {
		t.Fatalf("Validate() error = %v, want UDP relay memory-limit error", err)
	}
}

func TestValidateAllowsOneToFourEdges(t *testing.T) {
	cfg := validConfig()
	cfg.Edges = cfg.Edges[:1]
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() rejected one edge: %v", err)
	}

	cfg.Edges = nil
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "edges must contain between 1 and 4 entries") {
		t.Fatalf("Validate() error = %v, want empty-edge error", err)
	}
}

func TestValidateReportsDuplicateEdgeIdentityAndAddress(t *testing.T) {
	cfg := validConfig()
	cfg.Edges[1].ID = cfg.Edges[0].ID
	cfg.Edges[1].OverlayAddress = cfg.Edges[0].OverlayAddress

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() error = nil, want duplicate errors")
	}
	for _, message := range []string{
		"edges[1].id duplicates edges[0].id",
		"edges[1].overlay_address duplicates edges[0].overlay_address",
	} {
		if !strings.Contains(err.Error(), message) {
			t.Errorf("Validate() error = %q, want %q", err, message)
		}
	}
}

func TestValidateRejectsWireGuardListenPortCollisions(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*Config)
		want      string
	}{
		{
			name: "ingress and edge",
			configure: func(cfg *Config) {
				cfg.Edges[0].ListenPort = cfg.Ingress.ListenPort
			},
			want: "edges[0].listen_port duplicates ingress.listen_port",
		},
		{
			name: "two edges",
			configure: func(cfg *Config) {
				cfg.Edges[0].ListenPort = 42000
				cfg.Edges[1].ListenPort = 42000
			},
			want: "edges[1].listen_port duplicates edges[0].listen_port",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validConfig()
			test.configure(&cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidationErrorsDoNotExposePrivateKeys(t *testing.T) {
	cfg := validConfig()
	secret := "not-a-valid-private-key"
	cfg.Edges[0].PrivateKey = secret

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() error = nil, want key validation error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("Validate() error exposed private key: %q", err)
	}
	if !strings.Contains(err.Error(), "edges[0].private_key") {
		t.Fatalf("Validate() error = %q, want field path", err)
	}
}

func TestValidateAcceptsOptionalControlFields(t *testing.T) {
	cfg := validConfig()
	cfg.GeoDatabase = "/var/lib/GeoLite2-City.mmdb"
	cfg.MetricsListen = "127.0.0.1:9090"

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want valid optional control fields", err)
	}

	cfg.GeoDatabase = ""
	cfg.MetricsListen = ""
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want empty optional control fields to disable services", err)
	}
}

func TestValidateRejectsNonLoopbackMetricsListener(t *testing.T) {
	cfg := validConfig()
	cfg.MetricsListen = "0.0.0.0:9090"

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "metrics_listen must use a loopback IP address") {
		t.Fatalf("Validate() error = %v, want loopback-only metrics error", err)
	}
}

func TestValidateRejectsInvalidDestinationACL(t *testing.T) {
	cfg := validConfig()
	cfg.DestinationACL = &DestinationACLConfig{
		DefaultAction: "pass",
		Rules: []DestinationACLRule{{
			Action: "allow", Protocol: "icmp", Prefix: netip.MustParsePrefix("10.0.0.1/8"),
			Ports: []PortRange{{From: 443, To: 80}},
		}},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() accepted an invalid destination ACL")
	}
	for _, message := range []string{
		"destination_acl.default_action",
		"destination_acl.rules[0].protocol",
		"destination_acl.rules[0].prefix",
		"destination_acl.rules[0].ports[0]",
	} {
		if !strings.Contains(err.Error(), message) {
			t.Errorf("Validate() error = %q, want %q", err, message)
		}
	}
}

func TestValidateRejectsHostnameEndpoints(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		change func(*Config)
	}{
		{
			name: "edge endpoint",
			path: "edges[0].endpoint",
			change: func(cfg *Config) {
				cfg.Edges[0].Endpoint = "edge.example:51820"
			},
		},
		{
			name: "health check address",
			path: "edges[0].health_check_address",
			change: func(cfg *Config) {
				cfg.Edges[0].HealthCheckAddress = "health.example:443"
			},
		},
		{
			name: "metrics listen",
			path: "metrics_listen",
			change: func(cfg *Config) {
				cfg.MetricsListen = "localhost:9090"
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validConfig()
			test.change(&cfg)

			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), test.path) || !strings.Contains(err.Error(), "numeric IP address and port") {
				t.Fatalf("Validate() error = %v, want numeric endpoint error for %s", err, test.path)
			}
		})
	}
}

func TestValidateRequiresHealthCheckAddress(t *testing.T) {
	edge := validConfig().Edges[0]
	edge.HealthCheckAddress = ""

	err := edge.Validate()
	if err == nil || !strings.Contains(err.Error(), "edge.health_check_address is required") {
		t.Fatalf("Validate() error = %v, want required health-check address error", err)
	}
}

func TestValidateRejectsAllZeroWireGuardKeysWithoutExposingThem(t *testing.T) {
	zeroKey := testKey(0)
	tests := []struct {
		name   string
		path   string
		change func(*Config)
	}{
		{
			name: "ingress private key",
			path: "ingress.private_key",
			change: func(cfg *Config) {
				cfg.Ingress.PrivateKey = zeroKey
			},
		},
		{
			name: "ingress peer public key",
			path: "ingress.peers[0].public_key",
			change: func(cfg *Config) {
				cfg.Ingress.Peers[0].PublicKey = zeroKey
			},
		},
		{
			name: "egress private key",
			path: "edges[0].private_key",
			change: func(cfg *Config) {
				cfg.Edges[0].PrivateKey = zeroKey
			},
		},
		{
			name: "egress peer public key",
			path: "edges[0].peer_public_key",
			change: func(cfg *Config) {
				cfg.Edges[0].PeerPublicKey = zeroKey
			},
		},
		{
			name: "egress preshared key",
			path: "edges[0].preshared_key",
			change: func(cfg *Config) {
				cfg.Edges[0].PresharedKey = zeroKey
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validConfig()
			test.change(&cfg)

			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), test.path) {
				t.Fatalf("Validate() error = %v, want error for %s", err, test.path)
			}
			if strings.Contains(err.Error(), zeroKey) {
				t.Fatalf("Validate() error exposed rejected key: %q", err)
			}
		})
	}
}

func TestValidateRejectsNonCanonicalWireGuardKeysWithoutExposingThem(t *testing.T) {
	canonical := testKey(42)
	variants := []struct {
		name string
		key  string
	}{
		{name: "carriage return", key: canonical[:8] + "\r" + canonical[8:]},
		{name: "line feed", key: canonical[:8] + "\n" + canonical[8:]},
	}
	fields := []struct {
		name   string
		path   string
		change func(*Config, string)
	}{
		{
			name: "ingress private key",
			path: "ingress.private_key",
			change: func(cfg *Config, key string) {
				cfg.Ingress.PrivateKey = key
			},
		},
		{
			name: "ingress peer public key",
			path: "ingress.peers[0].public_key",
			change: func(cfg *Config, key string) {
				cfg.Ingress.Peers[0].PublicKey = key
			},
		},
		{
			name: "egress private key",
			path: "edges[0].private_key",
			change: func(cfg *Config, key string) {
				cfg.Edges[0].PrivateKey = key
			},
		},
		{
			name: "egress peer public key",
			path: "edges[0].peer_public_key",
			change: func(cfg *Config, key string) {
				cfg.Edges[0].PeerPublicKey = key
			},
		},
		{
			name: "egress preshared key",
			path: "edges[0].preshared_key",
			change: func(cfg *Config, key string) {
				cfg.Edges[0].PresharedKey = key
			},
		},
	}

	for _, field := range fields {
		t.Run(field.name, func(t *testing.T) {
			for _, variant := range variants {
				t.Run(variant.name, func(t *testing.T) {
					cfg := validConfig()
					field.change(&cfg, variant.key)

					err := cfg.Validate()
					if err == nil || !strings.Contains(err.Error(), field.path) || !strings.Contains(err.Error(), "canonical base64") {
						t.Fatalf("Validate() error = %v, want canonical-key error for %s", err, field.path)
					}
					if strings.Contains(err.Error(), variant.key) || strings.Contains(err.Error(), canonical) {
						t.Fatalf("Validate() error exposed rejected key: %q", err)
					}
				})
			}
		})
	}
}

func TestValidateRejectsNonCanonicalDuplicateIngressPublicKeys(t *testing.T) {
	for _, separator := range []struct {
		name  string
		value string
	}{
		{name: "carriage return", value: "\r"},
		{name: "line feed", value: "\n"},
	} {
		t.Run(separator.name, func(t *testing.T) {
			cfg := validConfig()
			canonical := cfg.Ingress.Peers[0].PublicKey
			duplicate := canonical[:8] + separator.value + canonical[8:]
			cfg.Ingress.Peers = append(cfg.Ingress.Peers, IngressPeerConfig{
				PublicKey:      duplicate,
				OverlayAddress: netip.MustParseAddr("10.0.0.3"),
			})

			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), "ingress.peers[1].public_key") || !strings.Contains(err.Error(), "canonical base64") {
				t.Fatalf("Validate() error = %v, want non-canonical duplicate-key rejection", err)
			}
			if strings.Contains(err.Error(), duplicate) || strings.Contains(err.Error(), canonical) {
				t.Fatalf("Validate() error exposed rejected key: %q", err)
			}
		})
	}
}

func TestValidateRejectsEveryASCIIControlByteWithoutEchoingIt(t *testing.T) {
	fields := []struct {
		name   string
		path   string
		change func(*Config, string)
	}{
		{
			name: "geo database",
			path: "geo_database",
			change: func(cfg *Config, value string) {
				cfg.GeoDatabase = value
			},
		},
		{
			name: "metrics listen",
			path: "metrics_listen",
			change: func(cfg *Config, value string) {
				cfg.MetricsListen = value
			},
		},
		{
			name: "edge endpoint",
			path: "edges[0].endpoint",
			change: func(cfg *Config, value string) {
				cfg.Edges[0].Endpoint = value
			},
		},
		{
			name: "health check address",
			path: "edges[0].health_check_address",
			change: func(cfg *Config, value string) {
				cfg.Edges[0].HealthCheckAddress = value
			},
		},
	}
	controls := make([]byte, 0, 33)
	for value := range byte(0x20) {
		controls = append(controls, value)
	}
	controls = append(controls, 0x7f)

	for _, field := range fields {
		t.Run(field.name, func(t *testing.T) {
			for _, control := range controls {
				t.Run(fmt.Sprintf("%02x", control), func(t *testing.T) {
					cfg := validConfig()
					value := fmt.Sprintf("192.0.2.1:51820%cinjected", control)
					field.change(&cfg, value)

					err := cfg.Validate()
					if err == nil || !strings.Contains(err.Error(), field.path) || !strings.Contains(err.Error(), "ASCII control bytes") {
						t.Fatalf("Validate() error = %v, want ASCII-control error for %s", err, field.path)
					}
					if strings.Contains(err.Error(), value) || strings.Contains(err.Error(), "injected") {
						t.Fatalf("Validate() error exposed injected field content: %q", err)
					}
				})
			}
		})
	}
}

func TestValidateRejectsZonedEndpoints(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		change func(*Config)
	}{
		{
			name: "edge endpoint",
			path: "edges[0].endpoint",
			change: func(cfg *Config) {
				cfg.Edges[0].Endpoint = "[fe80::1%eth0]:51820"
			},
		},
		{
			name: "health check address",
			path: "edges[0].health_check_address",
			change: func(cfg *Config) {
				cfg.Edges[0].OverlayAddress = netip.MustParsePrefix("2001:db8:1::2/64")
				cfg.Edges[0].AllowedIPs = []netip.Prefix{netip.MustParsePrefix("::/0")}
				cfg.Edges[0].HealthCheckAddress = "[fe80::1%eth0]:443"
			},
		},
		{
			name: "metrics listen",
			path: "metrics_listen",
			change: func(cfg *Config) {
				cfg.MetricsListen = "[fe80::1%eth0]:9090"
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validConfig()
			test.change(&cfg)

			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), test.path) || !strings.Contains(err.Error(), "must not use an IPv6 zone") {
				t.Fatalf("Validate() error = %v, want IPv6-zone error for %s", err, test.path)
			}
		})
	}
}

func TestValidateRejectsAllowedIPFromDifferentOverlayFamily(t *testing.T) {
	tests := []struct {
		name    string
		overlay string
		allowed string
	}{
		{name: "IPv4 overlay with IPv6 route", overlay: "10.10.1.2/24", allowed: "::/0"},
		{name: "IPv6 overlay with IPv4 route", overlay: "2001:db8:1::2/64", allowed: "0.0.0.0/0"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			edge := validConfig().Edges[0]
			edge.OverlayAddress = netip.MustParsePrefix(test.overlay)
			edge.AllowedIPs = []netip.Prefix{netip.MustParsePrefix(test.allowed)}

			err := edge.Validate()
			if err == nil || !strings.Contains(err.Error(), "address family must match edge.overlay_address") {
				t.Fatalf("Validate() error = %v, want address-family error", err)
			}
		})
	}
}

func TestValidateRejectsHealthCheckAddressFromDifferentOverlayFamily(t *testing.T) {
	tests := []struct {
		name    string
		overlay string
		allowed string
		health  string
	}{
		{name: "IPv4 overlay with IPv6 health check", overlay: "10.10.1.2/24", allowed: "0.0.0.0/0", health: "[2001:db8::1]:443"},
		{name: "IPv6 overlay with IPv4 health check", overlay: "2001:db8:1::2/64", allowed: "::/0", health: "198.51.100.1:443"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			edge := validConfig().Edges[0]
			edge.OverlayAddress = netip.MustParsePrefix(test.overlay)
			edge.AllowedIPs = []netip.Prefix{netip.MustParsePrefix(test.allowed)}
			edge.HealthCheckAddress = test.health

			err := edge.Validate()
			if err == nil || !strings.Contains(err.Error(), "edge.health_check_address address family must match edge.overlay_address") {
				t.Fatalf("Validate() error = %v, want health-check address-family error", err)
			}
		})
	}
}

func TestValidateRequiresFullTunnelAllowedIP(t *testing.T) {
	edge := validConfig().Edges[0]
	edge.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}

	err := edge.Validate()
	if err == nil || !strings.Contains(err.Error(), "edge.allowed_ips must include the address-family default route") {
		t.Fatalf("Validate() error = %v, want full-tunnel route error", err)
	}
}

func TestValidateRequiresAllowedIPToCoverHealthCheck(t *testing.T) {
	edge := validConfig().Edges[0]
	edge.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}

	err := edge.Validate()
	if err == nil || !strings.Contains(err.Error(), "edge.health_check_address must be contained by edge.allowed_ips") {
		t.Fatalf("Validate() error = %v, want health-check routing error", err)
	}
}

func TestValidateRequiresEgressFamilyToMatchIngress(t *testing.T) {
	cfg := validConfig()
	cfg.Edges[0].OverlayAddress = netip.MustParsePrefix("2001:db8:1::2/64")
	cfg.Edges[0].AllowedIPs = []netip.Prefix{netip.MustParsePrefix("::/0")}
	cfg.Edges[0].HealthCheckAddress = "[2001:db8::1]:443"

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "edges[0].overlay_address address family must match ingress.overlay_address") {
		t.Fatalf("Validate() error = %v, want ingress/egress family error", err)
	}
}

func TestValidateRejectsMTUAboveWireGuardContentLimit(t *testing.T) {
	cfg := validConfig()
	cfg.MTU = device.MaxContentSize + 1

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("mtu must be between 1280 and %d", device.MaxContentSize)) {
		t.Fatalf("Validate() error = %v, want WireGuard content-limit error", err)
	}
}

func validConfig() Config {
	cfg := Default()
	cfg.Ingress = IngressConfig{
		PrivateKey:     testKey(1),
		ListenPort:     51820,
		OverlayAddress: netip.MustParsePrefix("10.0.0.1/24"),
		Peers: []IngressPeerConfig{
			{PublicKey: testKey(2), OverlayAddress: netip.MustParseAddr("10.0.0.2")},
		},
	}
	for index := range 3 {
		octet := string(rune('1' + index))
		cfg.Edges = append(cfg.Edges, EdgeConfig{
			ID:                  model.EdgeID("edge-" + octet),
			PrivateKey:          testKey(byte(10 + index)),
			OverlayAddress:      netip.MustParsePrefix("10.10." + octet + ".2/24"),
			PeerPublicKey:       testKey(byte(20 + index)),
			Endpoint:            "192.0.2." + octet + ":51820",
			HealthCheckAddress:  "198.51.100." + octet + ":443",
			AllowedIPs:          []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
			PersistentKeepalive: Duration(25_000_000_000),
			Geo: GeoConfig{
				CountryCode: "US",
				Region:      "Test Region",
				City:        "Test City",
				Latitude:    40 + float64(index),
				Longitude:   -70 - float64(index),
			},
		})
	}
	return cfg
}

func marshalConfig(t *testing.T, cfg Config) []byte {
	t.Helper()
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return encoded
}

func testKey(fill byte) string {
	key := make([]byte, 32)
	for index := range key {
		key[index] = fill
	}
	return base64.StdEncoding.EncodeToString(key)
}
