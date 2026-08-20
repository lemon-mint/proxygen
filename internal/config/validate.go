package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

// Validate checks every required field and all cross-field invariants. Errors
// identify configuration paths but never include private key material.
func (cfg Config) Validate() error {
	var problems []error
	add := func(err error) {
		if err != nil {
			problems = append(problems, err)
		}
	}

	if cfg.MTU < 1280 || cfg.MTU > device.MaxContentSize {
		add(fmt.Errorf("mtu must be between 1280 and %d", device.MaxContentSize))
	}
	add(validateControlBytes("geo_database", cfg.GeoDatabase))
	add(validateMetricsListen("metrics_listen", cfg.MetricsListen))
	add(cfg.Ingress.validate())
	if len(cfg.Edges) < 3 || len(cfg.Edges) > 4 {
		add(fmt.Errorf("edges must contain 3 or 4 entries; got %d", len(cfg.Edges)))
	}

	edgeIDs := make(map[string]int, len(cfg.Edges))
	edgeAddresses := make(map[netip.Addr]int, len(cfg.Edges))
	for index, edge := range cfg.Edges {
		path := fmt.Sprintf("edges[%d]", index)
		add(edge.validate(path))
		if cfg.Ingress.OverlayAddress.IsValid() && edge.OverlayAddress.IsValid() &&
			cfg.Ingress.OverlayAddress.Addr().Unmap().Is4() != edge.OverlayAddress.Addr().Unmap().Is4() {
			add(fmt.Errorf("%s.overlay_address address family must match ingress.overlay_address", path))
		}

		idKey := string(edge.ID)
		if previous, exists := edgeIDs[idKey]; exists {
			add(fmt.Errorf("%s.id duplicates edges[%d].id", path, previous))
		} else {
			edgeIDs[idKey] = index
		}
		if edge.OverlayAddress.IsValid() {
			address := edge.OverlayAddress.Addr().Unmap()
			if previous, exists := edgeAddresses[address]; exists {
				add(fmt.Errorf("%s.overlay_address duplicates edges[%d].overlay_address", path, previous))
			} else {
				edgeAddresses[address] = index
			}
		}
	}

	add(validatePositiveDuration("timeouts.tcp_connect", cfg.Timeouts.TCPConnect))
	add(validatePositiveDuration("timeouts.tcp_idle", cfg.Timeouts.TCPIdle))
	add(validatePositiveDuration("timeouts.udp_idle", cfg.Timeouts.UDPIdle))
	add(validatePositiveDuration("timeouts.health_check_interval", cfg.Timeouts.HealthCheckInterval))
	add(validatePositiveDuration("timeouts.shutdown", cfg.Timeouts.Shutdown))

	if cfg.Limits.TCPRaceWorkers < 1 || cfg.Limits.TCPRaceWorkers > 65535 {
		add(fmt.Errorf("limits.tcp_race_workers must be between 1 and 65535"))
	}
	if cfg.Limits.TCPRaceQueueDepth < 1 || cfg.Limits.TCPRaceQueueDepth > 1_000_000 {
		add(fmt.Errorf("limits.tcp_race_queue_depth must be between 1 and 1000000"))
	}
	if cfg.Limits.MaxUDPFlows < 1 || cfg.Limits.MaxUDPFlows > 10_000_000 {
		add(fmt.Errorf("limits.max_udp_flows must be between 1 and 10000000"))
	}
	if cfg.Limits.RelayBufferBytes < 1024 || cfg.Limits.RelayBufferBytes > 1<<20 {
		add(fmt.Errorf("limits.relay_buffer_bytes must be between 1024 and 1048576"))
	}

	return errors.Join(problems...)
}

// Validate checks the ingress WireGuard configuration independently of a full
// proxy configuration.
func (ingress IngressConfig) Validate() error {
	return ingress.validate()
}

func (ingress IngressConfig) validate() error {
	var problems []error
	add := func(err error) {
		if err != nil {
			problems = append(problems, err)
		}
	}

	add(validateKey("ingress.private_key", ingress.PrivateKey))
	if ingress.ListenPort < 1 || ingress.ListenPort > 65535 {
		add(fmt.Errorf("ingress.listen_port must be between 1 and 65535"))
	}
	add(validateOverlayPrefix("ingress.overlay_address", ingress.OverlayAddress))
	if len(ingress.Peers) == 0 {
		add(fmt.Errorf("ingress.peers must contain at least one entry"))
	}

	addresses := make(map[netip.Addr]int, len(ingress.Peers))
	publicKeys := make(map[string]int, len(ingress.Peers))
	for index, peer := range ingress.Peers {
		path := fmt.Sprintf("ingress.peers[%d]", index)
		add(validateKey(path+".public_key", peer.PublicKey))
		address := peer.OverlayAddress.Unmap()
		if !address.IsValid() {
			add(fmt.Errorf("%s.overlay_address is required", path))
		} else {
			if !isUsableAddress(address) {
				add(fmt.Errorf("%s.overlay_address must be a unicast address", path))
			}
			if ingress.OverlayAddress.IsValid() {
				localAddress := ingress.OverlayAddress.Addr().Unmap()
				if !ingress.OverlayAddress.Contains(address) {
					add(fmt.Errorf("%s.overlay_address must be within ingress.overlay_address", path))
				}
				if address == localAddress {
					add(fmt.Errorf("%s.overlay_address must differ from ingress.overlay_address", path))
				}
			}
			if previous, exists := addresses[address]; exists {
				add(fmt.Errorf("%s.overlay_address duplicates ingress.peers[%d].overlay_address", path, previous))
			} else {
				addresses[address] = index
			}
		}
		if peer.PublicKey != "" {
			if previous, exists := publicKeys[peer.PublicKey]; exists {
				add(fmt.Errorf("%s.public_key duplicates ingress.peers[%d].public_key", path, previous))
			} else {
				publicKeys[peer.PublicKey] = index
			}
		}
	}
	return errors.Join(problems...)
}

// Validate checks an egress edge independently of a full proxy
// configuration.
func (edge EdgeConfig) Validate() error {
	return edge.validate("edge")
}

func (edge EdgeConfig) validate(path string) error {
	var problems []error
	add := func(err error) {
		if err != nil {
			problems = append(problems, err)
		}
	}

	if err := edge.ID.Validate(); err != nil {
		add(fmt.Errorf("%s.id: %w", path, err))
	}
	add(validateKey(path+".private_key", edge.PrivateKey))
	add(validateOverlayPrefix(path+".overlay_address", edge.OverlayAddress))
	add(validateKey(path+".peer_public_key", edge.PeerPublicKey))
	add(validateEndpoint(path+".endpoint", edge.Endpoint))
	add(validateHealthCheckAddress(path+".health_check_address", edge.HealthCheckAddress, path+".overlay_address", edge.OverlayAddress))
	healthCheck, healthCheckErr := netip.ParseAddrPort(edge.HealthCheckAddress)
	if healthCheckErr == nil {
		healthCheck = netip.AddrPortFrom(healthCheck.Addr().Unmap(), healthCheck.Port())
	}
	if len(edge.AllowedIPs) == 0 {
		add(fmt.Errorf("%s.allowed_ips must contain at least one prefix", path))
	}
	seenPrefixes := make(map[netip.Prefix]int, len(edge.AllowedIPs))
	hasDefaultRoute := false
	routesHealthCheck := false
	for index, prefix := range edge.AllowedIPs {
		prefixPath := fmt.Sprintf("%s.allowed_ips[%d]", path, index)
		if !prefix.IsValid() {
			add(fmt.Errorf("%s is invalid", prefixPath))
			continue
		}
		if prefix != prefix.Masked() {
			add(fmt.Errorf("%s must be a canonical network prefix", prefixPath))
		}
		familyMatches := !edge.OverlayAddress.IsValid() ||
			prefix.Addr().Is4() == edge.OverlayAddress.Addr().Unmap().Is4()
		if !familyMatches {
			add(fmt.Errorf("%s address family must match %s.overlay_address", prefixPath, path))
		}
		if prefix == prefix.Masked() && familyMatches {
			if prefix.Bits() == 0 {
				hasDefaultRoute = true
			}
			if healthCheckErr == nil && prefix.Contains(healthCheck.Addr()) {
				routesHealthCheck = true
			}
		}
		if previous, exists := seenPrefixes[prefix]; exists {
			add(fmt.Errorf("%s duplicates %s.allowed_ips[%d]", prefixPath, path, previous))
		} else {
			seenPrefixes[prefix] = index
		}
	}
	if edge.OverlayAddress.IsValid() && !hasDefaultRoute {
		add(fmt.Errorf("%s.allowed_ips must include the address-family default route", path))
	}
	if healthCheckErr == nil && !routesHealthCheck {
		add(fmt.Errorf("%s.health_check_address must be contained by %s.allowed_ips", path, path))
	}
	keepalive := edge.PersistentKeepalive.Std()
	if keepalive < 0 || keepalive > 65535*time.Second || keepalive%time.Second != 0 {
		add(fmt.Errorf("%s.persistent_keepalive must be zero or a whole number of seconds no greater than 65535s", path))
	}
	add(edge.Geo.validate(path + ".geo"))
	return errors.Join(problems...)
}

func (geo GeoConfig) validate(path string) error {
	var problems []error
	if len(geo.CountryCode) != 2 || geo.CountryCode[0] < 'A' || geo.CountryCode[0] > 'Z' || geo.CountryCode[1] < 'A' || geo.CountryCode[1] > 'Z' {
		problems = append(problems, fmt.Errorf("%s.country_code must contain exactly two uppercase ASCII letters", path))
	}
	if err := validateOptionalLabel(path+".region", geo.Region); err != nil {
		problems = append(problems, err)
	}
	if err := validateOptionalLabel(path+".city", geo.City); err != nil {
		problems = append(problems, err)
	}
	if math.IsNaN(geo.Latitude) || math.IsInf(geo.Latitude, 0) || geo.Latitude < -90 || geo.Latitude > 90 {
		problems = append(problems, fmt.Errorf("%s.latitude must be between -90 and 90", path))
	}
	if math.IsNaN(geo.Longitude) || math.IsInf(geo.Longitude, 0) || geo.Longitude < -180 || geo.Longitude > 180 {
		problems = append(problems, fmt.Errorf("%s.longitude must be between -180 and 180", path))
	}
	return errors.Join(problems...)
}

func validateKey(path, key string) error {
	if key == "" {
		return fmt.Errorf("%s is required", path)
	}
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(decoded) != 32 {
		return fmt.Errorf("%s must be a base64-encoded 32-byte key", path)
	}
	if base64.StdEncoding.EncodeToString(decoded) != key {
		return fmt.Errorf("%s must be a canonical base64-encoded 32-byte key", path)
	}
	var combined byte
	for _, value := range decoded {
		combined |= value
	}
	if combined == 0 {
		return fmt.Errorf("%s must not be an all-zero key", path)
	}
	return nil
}

func validateOverlayPrefix(path string, prefix netip.Prefix) error {
	if !prefix.IsValid() {
		return fmt.Errorf("%s is required", path)
	}
	if !isUsableAddress(prefix.Addr().Unmap()) {
		return fmt.Errorf("%s must use a unicast address", path)
	}
	return nil
}

func isUsableAddress(address netip.Addr) bool {
	return address.IsValid() && !address.IsUnspecified() && !address.IsMulticast()
}

func validateEndpoint(path, endpoint string) error {
	address, err := parseEndpoint(path, endpoint)
	if err != nil {
		return err
	}
	if !isUsableAddress(address.Addr().Unmap()) {
		return fmt.Errorf("%s must use a unicast IP address", path)
	}
	return nil
}

func validateHealthCheckAddress(path, endpoint, overlayPath string, overlay netip.Prefix) error {
	if endpoint == "" {
		return fmt.Errorf("%s is required", path)
	}
	address, err := parseEndpoint(path, endpoint)
	if err != nil {
		return err
	}
	if !isUsableAddress(address.Addr().Unmap()) {
		return fmt.Errorf("%s must use a unicast IP address", path)
	}
	if overlay.IsValid() && address.Addr().Unmap().Is4() != overlay.Addr().Unmap().Is4() {
		return fmt.Errorf("%s address family must match %s", path, overlayPath)
	}
	return nil
}

func validateMetricsListen(path, endpoint string) error {
	if endpoint == "" {
		return nil
	}
	_, err := parseEndpoint(path, endpoint)
	return err
}

func parseEndpoint(path, endpoint string) (netip.AddrPort, error) {
	if err := validateControlBytes(path, endpoint); err != nil {
		return netip.AddrPort{}, err
	}
	address, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%s must be a numeric IP address and port", path)
	}
	if address.Addr().Zone() != "" {
		return netip.AddrPort{}, fmt.Errorf("%s must not use an IPv6 zone", path)
	}
	if address.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("%s port must be between 1 and 65535", path)
	}
	return address, nil
}

func validateControlBytes(path, value string) error {
	for index := range value {
		if value[index] < 0x20 || value[index] == 0x7f {
			return fmt.Errorf("%s must not contain ASCII control bytes", path)
		}
	}
	return nil
}

func validatePositiveDuration(path string, duration Duration) error {
	if duration.Std() <= 0 {
		return fmt.Errorf("%s must be greater than zero", path)
	}
	return nil
}

func validateOptionalLabel(path, value string) error {
	if value == "" {
		return nil
	}
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s must not contain only whitespace", path)
	}
	if len(value) > 128 {
		return fmt.Errorf("%s must be at most 128 bytes", path)
	}
	return nil
}
