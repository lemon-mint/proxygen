package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseWireGuardFileMapsSupportedFieldsWithoutExecutingHooks(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "edge-one.conf")
	hookPath := filepath.Join(directory, "hook-ran")
	content := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.88.1.2/24
ListenPort = 42001
PostUp = touch %s

[Peer]
PublicKey = %s
PresharedKey = %s
Endpoint = 203.0.113.10:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`, testKey(1), hookPath, testKey(2), testKey(3))
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	edge, err := parseWireGuardFile(path, "edge-one", "1.1.1.1:443")
	if err != nil {
		t.Fatalf("parseWireGuardFile: %v", err)
	}
	if edge.ID != "edge-one" || edge.PrivateKey != testKey(1) || edge.ListenPort != 42001 ||
		edge.OverlayAddress != netip.MustParsePrefix("10.88.1.2/24") || edge.PeerPublicKey != testKey(2) ||
		edge.PresharedKey != testKey(3) || edge.Endpoint != "203.0.113.10:51820" ||
		edge.PersistentKeepalive.Std() != 25*time.Second || edge.Geo.CountryCode != "ZZ" {
		t.Fatalf("parsed edge = %#v", edge)
	}
	if len(edge.AllowedIPs) != 1 || edge.AllowedIPs[0] != netip.MustParsePrefix("0.0.0.0/0") {
		t.Fatalf("AllowedIPs = %v", edge.AllowedIPs)
	}
	if err := edge.Validate(); err != nil {
		t.Fatalf("parsed EdgeConfig.Validate: %v", err)
	}
	if _, err := os.Stat(hookPath); !os.IsNotExist(err) {
		t.Fatalf("PostUp hook was executed or stat failed unexpectedly: %v", err)
	}
}

func TestLoadMergesSortedWireGuardDirectory(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "wg")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	for index, name := range []string{"c-edge.conf", "a-edge.conf", "b-edge.conf"} {
		ordinal := index + 1
		content := wireGuardTestConfig(
			testKey(byte(10+ordinal)), testKey(byte(20+ordinal)),
			fmt.Sprintf("10.88.%d.2/24", ordinal), fmt.Sprintf("203.0.113.%d:51820", ordinal),
		)
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0o600); err != nil {
			t.Fatalf("WriteFile(%s): %v", name, err)
		}
	}

	cfg := validConfig()
	cfg.Edges = nil
	cfg.WireGuardDirectory = "wg"
	cfg.WireGuardHealthCheckAddress = "1.1.1.1:443"
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	configPath := filepath.Join(root, "proxygen.json")
	if err := os.WriteFile(configPath, encoded, 0o600); err != nil {
		t.Fatalf("WriteFile(config): %v", err)
	}

	loaded, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.WireGuardDirectory != "" || loaded.WireGuardHealthCheckAddress != "" {
		t.Fatalf("WireGuard import fields were not consumed: directory=%q health=%q", loaded.WireGuardDirectory, loaded.WireGuardHealthCheckAddress)
	}
	wantIDs := []string{"a-edge", "b-edge", "c-edge"}
	if len(loaded.Edges) != len(wantIDs) {
		t.Fatalf("loaded edges = %d, want %d", len(loaded.Edges), len(wantIDs))
	}
	for index, wantID := range wantIDs {
		if string(loaded.Edges[index].ID) != wantID {
			t.Fatalf("edge[%d].ID = %q, want %q", index, loaded.Edges[index].ID, wantID)
		}
		if loaded.Edges[index].HealthCheckAddress != "1.1.1.1:443" {
			t.Fatalf("edge[%d].HealthCheckAddress = %q", index, loaded.Edges[index].HealthCheckAddress)
		}
	}
}

func TestParseWireGuardFileRejectsMultiplePeers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "multiple.conf")
	content := wireGuardTestConfig(testKey(1), testKey(2), "10.88.1.2/24", "203.0.113.1:51820") +
		"\n[Peer]\nPublicKey = " + testKey(3) + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := parseWireGuardFile(path, "multiple", "1.1.1.1:443")
	if err == nil || !strings.Contains(err.Error(), "exactly one Peer section is supported") {
		t.Fatalf("parseWireGuardFile error = %v, want multiple-peer error", err)
	}
}

func TestDecodeRejectsDirectoryWithoutFileContext(t *testing.T) {
	cfg := validConfig()
	cfg.WireGuardDirectory = "wg"
	cfg.WireGuardHealthCheckAddress = "1.1.1.1:443"
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	_, err = Decode(strings.NewReader(string(encoded)))
	if err == nil || !strings.Contains(err.Error(), "wireguard_directory requires loading from a file path") {
		t.Fatalf("Decode error = %v, want file-context error", err)
	}
}

func TestParseWireGuardFileRejectsRepeatedZeroKeepalive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keepalive.conf")
	content := strings.Replace(
		wireGuardTestConfig(testKey(1), testKey(2), "10.88.1.2/24", "203.0.113.1:51820"),
		"PersistentKeepalive = 25",
		"PersistentKeepalive = 0\nPersistentKeepalive = 0",
		1,
	)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := parseWireGuardFile(path, "keepalive", "1.1.1.1:443")
	if err == nil || !strings.Contains(err.Error(), "Peer.PersistentKeepalive is repeated") {
		t.Fatalf("parseWireGuardFile error = %v, want repeated keepalive error", err)
	}
}

func TestLoadWireGuardDirectoryRejectsSymlinkedConfig(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte(wireGuardTestConfig(testKey(1), testKey(2), "10.88.1.2/24", "203.0.113.1:51820")), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(directory, "edge.conf")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	_, err := loadWireGuardDirectory(directory, "1.1.1.1:443")
	if err == nil || !strings.Contains(err.Error(), "must be a regular WireGuard configuration file") {
		t.Fatalf("loadWireGuardDirectory error = %v, want regular-file error", err)
	}
}

func wireGuardTestConfig(privateKey, publicKey, address, endpoint string) string {
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`, privateKey, address, publicKey, endpoint)
}
