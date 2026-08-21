// Package config loads and validates proxygen's JSON configuration using only
// the Go standard library.
package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/model"
)

const (
	DefaultMTU                 = 1420
	DefaultTCPConnectTimeout   = 10 * time.Second
	DefaultTCPIdleTimeout      = 5 * time.Minute
	DefaultUDPIdleTimeout      = 2 * time.Minute
	DefaultHealthCheckInterval = 10 * time.Second
	DefaultShutdownTimeout     = 10 * time.Second
	DefaultTCPRaceWorkers      = 256
	DefaultTCPRaceQueueDepth   = 1024
	DefaultMaxUDPFlows         = 1024
	DefaultRelayBufferBytes    = 32 * 1024
)

// Duration is a JSON duration encoded using time.ParseDuration syntax.
type Duration time.Duration

func (duration Duration) String() string {
	return time.Duration(duration).String()
}

// Std returns duration as a time.Duration.
func (duration Duration) Std() time.Duration {
	return time.Duration(duration)
}

func (duration Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(duration.String())
}

func (duration *Duration) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("duration must be a string: %w", err)
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf("invalid duration: %w", err)
	}
	*duration = Duration(parsed)
	return nil
}

// Config is the complete proxygen configuration.
type Config struct {
	MTU                         int                   `json:"mtu"`
	GeoDatabase                 string                `json:"geo_database"`
	MetricsListen               string                `json:"metrics_listen"`
	WireGuardDirectory          string                `json:"wireguard_directory"`
	WireGuardHealthCheckAddress string                `json:"wireguard_health_check_address"`
	DestinationACL              *DestinationACLConfig `json:"destination_acl"`
	Ingress                     IngressConfig         `json:"ingress"`
	Edges                       []EdgeConfig          `json:"edges"`
	Timeouts                    TimeoutConfig         `json:"timeouts"`
	Limits                      LimitsConfig          `json:"limits"`
}

// IngressConfig configures the userspace WireGuard device accepting clients.
type IngressConfig struct {
	PrivateKey     string              `json:"private_key"`
	ListenPort     int                 `json:"listen_port"`
	OverlayAddress netip.Prefix        `json:"overlay_address"`
	Peers          []IngressPeerConfig `json:"peers"`
}

// IngressPeerConfig authorizes one client overlay address.
type IngressPeerConfig struct {
	PublicKey      string     `json:"public_key"`
	OverlayAddress netip.Addr `json:"overlay_address"`
}

// EdgeConfig configures one independent userspace WireGuard egress edge.
type EdgeConfig struct {
	ID                  model.EdgeID   `json:"id"`
	PrivateKey          string         `json:"private_key"`
	ListenPort          int            `json:"listen_port"`
	OverlayAddress      netip.Prefix   `json:"overlay_address"`
	PeerPublicKey       string         `json:"peer_public_key"`
	PresharedKey        string         `json:"preshared_key"`
	Endpoint            string         `json:"endpoint"`
	HealthCheckAddress  string         `json:"health_check_address"`
	AllowedIPs          []netip.Prefix `json:"allowed_ips"`
	PersistentKeepalive Duration       `json:"persistent_keepalive"`
	Geo                 GeoConfig      `json:"geo"`
}

// GeoConfig is operator-provided edge location metadata.
type GeoConfig struct {
	CountryCode string  `json:"country_code"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
}

// DestinationACLConfig is an ordered first-match destination policy. A nil
// policy uses proxygen's built-in Internet-exit policy.
type DestinationACLConfig struct {
	DefaultAction string               `json:"default_action"`
	Rules         []DestinationACLRule `json:"rules"`
}

// DestinationACLRule matches one protocol, network prefix, and optional list
// of destination-port ranges.
type DestinationACLRule struct {
	Action   string       `json:"action"`
	Protocol string       `json:"protocol"`
	Prefix   netip.Prefix `json:"prefix"`
	Ports    []PortRange  `json:"ports"`
}

// PortRange is an inclusive destination-port interval.
type PortRange struct {
	From uint16 `json:"from"`
	To   uint16 `json:"to"`
}

// TimeoutConfig controls connection, flow, health, and shutdown lifetimes.
type TimeoutConfig struct {
	TCPConnect          Duration `json:"tcp_connect"`
	TCPIdle             Duration `json:"tcp_idle"`
	UDPIdle             Duration `json:"udp_idle"`
	HealthCheckInterval Duration `json:"health_check_interval"`
	Shutdown            Duration `json:"shutdown"`
}

// LimitsConfig bounds race work, queued admissions, UDP state, and relay memory.
type LimitsConfig struct {
	TCPRaceWorkers    int `json:"tcp_race_workers"`
	TCPRaceQueueDepth int `json:"tcp_race_queue_depth"`
	MaxUDPFlows       int `json:"max_udp_flows"`
	RelayBufferBytes  int `json:"relay_buffer_bytes"`
}

// Default returns a Config populated with defaults for optional scalar fields.
// Required ingress, peer, and edge values remain unset.
func Default() Config {
	return Config{
		MTU: DefaultMTU,
		Timeouts: TimeoutConfig{
			TCPConnect:          Duration(DefaultTCPConnectTimeout),
			TCPIdle:             Duration(DefaultTCPIdleTimeout),
			UDPIdle:             Duration(DefaultUDPIdleTimeout),
			HealthCheckInterval: Duration(DefaultHealthCheckInterval),
			Shutdown:            Duration(DefaultShutdownTimeout),
		},
		Limits: LimitsConfig{
			TCPRaceWorkers:    DefaultTCPRaceWorkers,
			TCPRaceQueueDepth: DefaultTCPRaceQueueDepth,
			MaxUDPFlows:       DefaultMaxUDPFlows,
			RelayBufferBytes:  DefaultRelayBufferBytes,
		},
	}
}
