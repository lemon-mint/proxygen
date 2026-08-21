package config

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"git.gosuda.org/lemon-mint/proxygen/internal/model"
)

func loadWireGuardDirectory(directory, healthCheckAddress string) ([]EdgeConfig, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", directory, err)
	}

	edges := make([]EdgeConfig, 0, len(entries))
	for _, entry := range entries {
		if strings.ToLower(filepath.Ext(entry.Name())) != ".conf" {
			continue
		}
		if !entry.Type().IsRegular() {
			return nil, fmt.Errorf("%q must be a regular WireGuard configuration file", entry.Name())
		}
		id := model.EdgeID(strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name())))
		if err := id.Validate(); err != nil {
			return nil, fmt.Errorf("WireGuard file %q has invalid edge ID: %w", entry.Name(), err)
		}
		edge, err := parseWireGuardFile(filepath.Join(directory, entry.Name()), id, healthCheckAddress)
		if err != nil {
			return nil, fmt.Errorf("WireGuard file %q: %w", entry.Name(), err)
		}
		edges = append(edges, edge)
	}
	if len(edges) == 0 {
		return nil, fmt.Errorf("directory %q contains no regular .conf files", directory)
	}
	return edges, nil
}

type wireGuardDocument struct {
	privateKey             string
	listenPort             int
	interfaceCount         int
	addresses              []string
	peerCount              int
	peerPublicKey          string
	presharedKey           string
	endpoint               string
	allowedIPs             []string
	persistentKeepalive    Duration
	persistentKeepaliveSet bool
}

func parseWireGuardFile(path string, id model.EdgeID, healthCheckAddress string) (EdgeConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return EdgeConfig{}, fmt.Errorf("open: %w", err)
	}
	defer file.Close()

	var document wireGuardDocument
	section := ""
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := stripWireGuardComment(strings.TrimSpace(scanner.Text()))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			switch section {
			case "interface":
				if document.peerCount != 0 {
					return EdgeConfig{}, fmt.Errorf("line %d: Interface section must precede Peer", lineNumber)
				}
				document.interfaceCount++
				if document.interfaceCount > 1 {
					return EdgeConfig{}, fmt.Errorf("line %d: exactly one Interface section is supported", lineNumber)
				}
			case "peer":
				document.peerCount++
				if document.peerCount > 1 {
					return EdgeConfig{}, fmt.Errorf("line %d: exactly one Peer section is supported", lineNumber)
				}
			default:
				return EdgeConfig{}, fmt.Errorf("line %d: unsupported section", lineNumber)
			}
			continue
		}

		key, value, found := strings.Cut(line, "=")
		if !found || strings.TrimSpace(value) == "" {
			return EdgeConfig{}, fmt.Errorf("line %d: expected key = value", lineNumber)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		var parseErr error
		switch section {
		case "interface":
			parseErr = document.parseInterface(key, value)
		case "peer":
			parseErr = document.parsePeer(key, value)
		default:
			return EdgeConfig{}, fmt.Errorf("line %d: key appears outside a supported section", lineNumber)
		}
		if parseErr != nil {
			return EdgeConfig{}, fmt.Errorf("line %d: %w", lineNumber, parseErr)
		}
	}
	if err := scanner.Err(); err != nil {
		return EdgeConfig{}, fmt.Errorf("read: %w", err)
	}
	return document.edge(id, healthCheckAddress)
}

func (document *wireGuardDocument) parseInterface(key, value string) error {
	switch key {
	case "privatekey":
		return setOnce("Interface.PrivateKey", &document.privateKey, value)
	case "listenport":
		if document.listenPort != 0 {
			return errors.New("Interface.ListenPort is repeated")
		}
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil || port == 0 {
			return errors.New("Interface.ListenPort must be between 1 and 65535")
		}
		document.listenPort = int(port)
		return nil
	case "address":
		document.addresses = append(document.addresses, splitWireGuardList(value)...)
		return nil
	case "dns", "mtu", "table", "fwmark", "preup", "postup", "predown", "postdown", "saveconfig":
		// Host routing, DNS, and hooks are intentionally not applied by the
		// userspace data plane. In particular, shell hooks are never executed.
		return nil
	default:
		return fmt.Errorf("unsupported Interface key %q", key)
	}
}

func (document *wireGuardDocument) parsePeer(key, value string) error {
	switch key {
	case "publickey":
		return setOnce("Peer.PublicKey", &document.peerPublicKey, value)
	case "presharedkey":
		return setOnce("Peer.PresharedKey", &document.presharedKey, value)
	case "endpoint":
		return setOnce("Peer.Endpoint", &document.endpoint, value)
	case "allowedips":
		document.allowedIPs = append(document.allowedIPs, splitWireGuardList(value)...)
		return nil
	case "persistentkeepalive":
		if document.persistentKeepaliveSet {
			return errors.New("Peer.PersistentKeepalive is repeated")
		}
		seconds, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return errors.New("Peer.PersistentKeepalive must be whole seconds between 0 and 65535")
		}
		document.persistentKeepalive = Duration(time.Duration(seconds) * time.Second)
		document.persistentKeepaliveSet = true
		return nil
	default:
		return fmt.Errorf("unsupported Peer key %q", key)
	}
}

func (document wireGuardDocument) edge(id model.EdgeID, healthCheckAddress string) (EdgeConfig, error) {
	if document.interfaceCount != 1 {
		return EdgeConfig{}, fmt.Errorf("exactly one Interface section is required; got %d", document.interfaceCount)
	}
	if document.privateKey == "" {
		return EdgeConfig{}, errors.New("Interface.PrivateKey is required")
	}
	if len(document.addresses) != 1 {
		return EdgeConfig{}, fmt.Errorf("Interface.Address must contain exactly one prefix; got %d", len(document.addresses))
	}
	address, err := netip.ParsePrefix(document.addresses[0])
	if err != nil {
		return EdgeConfig{}, errors.New("Interface.Address must be an IP prefix")
	}
	if document.peerCount != 1 {
		return EdgeConfig{}, fmt.Errorf("exactly one Peer section is required; got %d", document.peerCount)
	}
	if document.peerPublicKey == "" {
		return EdgeConfig{}, errors.New("Peer.PublicKey is required")
	}
	if document.endpoint == "" {
		return EdgeConfig{}, errors.New("Peer.Endpoint is required")
	}
	if len(document.allowedIPs) == 0 {
		return EdgeConfig{}, errors.New("Peer.AllowedIPs is required")
	}
	allowedIPs := make([]netip.Prefix, 0, len(document.allowedIPs))
	for _, value := range document.allowedIPs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return EdgeConfig{}, errors.New("Peer.AllowedIPs must contain IP prefixes")
		}
		allowedIPs = append(allowedIPs, prefix)
	}
	return EdgeConfig{
		ID:                  id,
		PrivateKey:          document.privateKey,
		ListenPort:          document.listenPort,
		OverlayAddress:      address,
		PeerPublicKey:       document.peerPublicKey,
		PresharedKey:        document.presharedKey,
		Endpoint:            document.endpoint,
		HealthCheckAddress:  healthCheckAddress,
		AllowedIPs:          allowedIPs,
		PersistentKeepalive: document.persistentKeepalive,
		Geo:                 GeoConfig{CountryCode: "ZZ"},
	}, nil
}

func setOnce(name string, destination *string, value string) error {
	if *destination != "" {
		return fmt.Errorf("%s is repeated", name)
	}
	*destination = value
	return nil
}

func splitWireGuardList(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func stripWireGuardComment(line string) string {
	for index, character := range line {
		if character == '#' || character == ';' {
			return strings.TrimSpace(line[:index])
		}
	}
	return line
}
