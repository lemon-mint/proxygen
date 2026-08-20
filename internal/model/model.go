// Package model contains the small, dependency-free domain types shared by
// proxygen's control and data planes.
package model

import (
	"fmt"
	"net/netip"
)

// EdgeID is the stable, operator-assigned identity of an egress edge.
type EdgeID string

// NewEdgeID validates value and returns it as an EdgeID.
func NewEdgeID(value string) (EdgeID, error) {
	id := EdgeID(value)
	if err := id.Validate(); err != nil {
		return "", err
	}
	return id, nil
}

// Validate reports whether id is suitable for use in configuration and logs.
func (id EdgeID) Validate() error {
	value := string(id)
	if len(value) == 0 {
		return fmt.Errorf("edge ID is required")
	}
	if len(value) > 63 {
		return fmt.Errorf("edge ID must be at most 63 bytes")
	}
	for i := range len(value) {
		char := value[i]
		if isASCIIAlphaNumeric(char) {
			continue
		}
		if i > 0 && i < len(value)-1 && (char == '-' || char == '_' || char == '.') {
			continue
		}
		return fmt.Errorf("edge ID must start and end with an ASCII letter or digit and contain only letters, digits, '.', '-', or '_'")
	}
	return nil
}

func isASCIIAlphaNumeric(char byte) bool {
	return char >= 'a' && char <= 'z' ||
		char >= 'A' && char <= 'Z' ||
		char >= '0' && char <= '9'
}

// EdgeState is the current lifecycle and health state of an egress edge.
type EdgeState uint8

const (
	EdgeStateUnknown EdgeState = iota
	EdgeStateStarting
	EdgeStateHealthy
	EdgeStateUnhealthy
	EdgeStateStopped
)

// Valid reports whether state is a defined EdgeState.
func (state EdgeState) Valid() bool {
	return state >= EdgeStateStarting && state <= EdgeStateStopped
}

func (state EdgeState) String() string {
	switch state {
	case EdgeStateStarting:
		return "starting"
	case EdgeStateHealthy:
		return "healthy"
	case EdgeStateUnhealthy:
		return "unhealthy"
	case EdgeStateStopped:
		return "stopped"
	default:
		return "unknown"
	}
}

// IPVersion identifies the address family carried by a flow.
type IPVersion uint8

const (
	IPv4 IPVersion = 4
	IPv6 IPVersion = 6
)

// Valid reports whether version is IPv4 or IPv6.
func (version IPVersion) Valid() bool {
	return version == IPv4 || version == IPv6
}

// TransportProtocol is the transport protocol in a FlowKey.
type TransportProtocol uint8

const (
	ProtocolTCP TransportProtocol = 6
	ProtocolUDP TransportProtocol = 17
)

// Valid reports whether protocol is supported by proxygen.
func (protocol TransportProtocol) Valid() bool {
	return protocol == ProtocolTCP || protocol == ProtocolUDP
}

// FlowKey is an IP-version-aware transport 5-tuple. netip.Addr and all other
// fields are comparable, so FlowKey can be used directly as a map key.
type FlowKey struct {
	IPVersion       IPVersion
	Protocol        TransportProtocol
	SourceAddr      netip.Addr
	SourcePort      uint16
	DestinationAddr netip.Addr
	DestinationPort uint16
}

// NewFlowKey constructs a canonical, validated full flow key. IPv4-mapped IPv6
// addresses are unmapped so the same IPv4 flow has only one representation.
func NewFlowKey(protocol TransportProtocol, source, destination netip.AddrPort) (FlowKey, error) {
	sourceAddr := source.Addr().Unmap()
	destinationAddr := destination.Addr().Unmap()

	key := FlowKey{
		Protocol:        protocol,
		SourceAddr:      sourceAddr,
		SourcePort:      source.Port(),
		DestinationAddr: destinationAddr,
		DestinationPort: destination.Port(),
	}
	if sourceAddr.Is4() {
		key.IPVersion = IPv4
	} else if sourceAddr.Is6() {
		key.IPVersion = IPv6
	}
	if err := key.Validate(); err != nil {
		return FlowKey{}, err
	}
	return key, nil
}

// Validate reports whether key is a canonical TCP or UDP 5-tuple.
func (key FlowKey) Validate() error {
	if !key.IPVersion.Valid() {
		return fmt.Errorf("flow IP version must be 4 or 6")
	}
	if !key.Protocol.Valid() {
		return fmt.Errorf("flow protocol must be TCP or UDP")
	}
	if err := validateFlowAddr("source", key.SourceAddr, key.IPVersion); err != nil {
		return err
	}
	if err := validateFlowAddr("destination", key.DestinationAddr, key.IPVersion); err != nil {
		return err
	}
	if key.SourcePort == 0 {
		return fmt.Errorf("flow source port must be non-zero")
	}
	if key.DestinationPort == 0 {
		return fmt.Errorf("flow destination port must be non-zero")
	}
	return nil
}

func validateFlowAddr(name string, addr netip.Addr, version IPVersion) error {
	if !addr.IsValid() {
		return fmt.Errorf("flow %s address is invalid", name)
	}
	if addr.Zone() != "" {
		return fmt.Errorf("flow %s address must not contain a zone", name)
	}
	if addr.Is4In6() {
		return fmt.Errorf("flow %s address must use canonical IPv4 form", name)
	}
	if version == IPv4 && !addr.Is4() || version == IPv6 && !addr.Is6() {
		return fmt.Errorf("flow %s address does not match IP version %d", name, version)
	}
	return nil
}
