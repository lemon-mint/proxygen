// Package egress owns independent WireGuard egress edges and the interfaces
// used to select them.
package egress

import (
	"context"
	"net"
	"net/netip"

	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/model"
)

// Edge is one independently owned egress path.
type Edge interface {
	ID() model.EdgeID
	DialTCP(context.Context, netip.AddrPort) (net.Conn, error)
	DialUDP(context.Context, netip.AddrPort) (net.Conn, error)
	Close() error
}

// Source supplies healthy edges to TCP races and pins new UDP flows.
type Source interface {
	Healthy() []Edge
	SelectUDP(model.FlowKey) (Edge, error)
}
