package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/model"
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
			Endpoint:            "edge" + octet + ".example:51820",
			AllowedIPs:          []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
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
