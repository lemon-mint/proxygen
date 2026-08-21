// Package egress owns independent WireGuard egress edges and the interfaces
// used to select them.
package egress

import (
	"context"
	"net"
	"net/netip"
	"time"

	"git.gosuda.org/lemon-mint/proxygen/internal/model"
)

// Edge is one independently owned egress path.
type Edge interface {
	ID() model.EdgeID
	DialTCP(context.Context, netip.AddrPort) (net.Conn, error)
	DialUDP(context.Context, netip.AddrPort) (net.Conn, error)
	Close() error
}

// TCPAttemptObserver optionally receives every edge selected for a TCP race.
type TCPAttemptObserver interface {
	ObserveTCPAttempt(edgeID model.EdgeID)
}

// TCPObserver optionally receives the winning edge and monotonic dial latency
// for a committed TCP race.
type TCPObserver interface {
	ObserveTCP(destination netip.AddrPort, edgeID model.EdgeID, latency time.Duration)
}

// Source supplies healthy edges to TCP races and pins new UDP flows.
type Source interface {
	Healthy() []Edge
	SelectUDP(model.FlowKey) (Edge, error)
}
