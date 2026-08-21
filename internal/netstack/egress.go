package netstack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// Egress is a userspace-only WireGuard TUN device and its private gVisor
// network stack. Its public dial API deliberately keeps gVisor types private.
type Egress struct {
	*Ingress
	local netip.Addr
}

// NewEgress builds an independently owned stack with one local overlay address.
func NewEgress(local netip.Addr, mtu int) (*Egress, error) {
	if err := validateMTU(mtu); err != nil {
		return nil, err
	}
	local = local.Unmap()
	if !local.IsValid() || local.Zone() != "" || (!local.Is4() && !local.Is6()) {
		return nil, errors.New("local overlay address must be an unzoned IPv4 or IPv6 address")
	}

	s, ep, err := buildEgressStack(local, mtu)
	if err != nil {
		return nil, err
	}
	return &Egress{
		Ingress: newChannelIngress(egressName, mtu, s, ep, nil, nil),
		local:   local,
	}, nil
}

func buildEgressStack(local netip.Addr, mtu int) (*stack.Stack, *channel.Endpoint, error) {
	ep := channel.New(outboundQueueSize, uint32(mtu), "")
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
		HandleLocal: true,
	})
	cleanup := func() {
		s.Destroy()
		ep.Close()
	}
	if err := configureTCPBuffers(s); err != nil {
		cleanup()
		return nil, nil, err
	}

	sackEnabled := tcpip.TCPSACKEnabled(true)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabled); err != nil {
		cleanup()
		return nil, nil, tcpipError("enable egress TCP SACK", err)
	}
	if err := s.CreateNIC(ingressNICID, ep); err != nil {
		cleanup()
		return nil, nil, tcpipError("create egress NIC", err)
	}

	protocol, defaultRoute := networkProtocol(local)
	protocolAddress := tcpip.ProtocolAddress{
		Protocol:          protocol,
		AddressWithPrefix: tcpip.AddrFromSlice(local.AsSlice()).WithPrefix(),
	}
	if err := s.AddProtocolAddress(ingressNICID, protocolAddress, stack.AddressProperties{}); err != nil {
		cleanup()
		return nil, nil, tcpipError("add egress overlay address", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: defaultRoute, NIC: ingressNICID}})
	return s, ep, nil
}

func networkProtocol(address netip.Addr) (tcpip.NetworkProtocolNumber, tcpip.Subnet) {
	if address.Is4() {
		return ipv4.ProtocolNumber, header.IPv4EmptySubnet
	}
	return ipv6.ProtocolNumber, header.IPv6EmptySubnet
}

func fullAddress(address netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	protocol, _ := networkProtocol(address.Addr())
	return tcpip.FullAddress{
		NIC:  ingressNICID,
		Addr: tcpip.AddrFromSlice(address.Addr().AsSlice()),
		Port: address.Port(),
	}, protocol
}

func (e *Egress) validateRemote(remote netip.AddrPort) (netip.AddrPort, error) {
	if !remote.IsValid() || remote.Port() == 0 || remote.Addr().Zone() != "" {
		return netip.AddrPort{}, errors.New("remote address and port are invalid")
	}
	remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	if remote.Addr().Is4() != e.local.Is4() {
		return netip.AddrPort{}, errors.New("remote address family differs from the local overlay address")
	}
	return remote, nil
}

// DialTCP opens a connected TCP socket and makes handshake cancellation follow
// ctx. No payload is exchanged before this method returns.
func (e *Egress) DialTCP(ctx context.Context, remote netip.AddrPort) (net.Conn, error) {
	if ctx == nil {
		return nil, errors.New("TCP dial context is required")
	}
	remote, err := e.validateRemote(remote)
	if err != nil {
		return nil, err
	}
	remoteAddress, protocol := fullAddress(remote)
	connection, err := gonet.DialContextTCP(ctx, e.stack, remoteAddress, protocol)
	if err != nil {
		return nil, err
	}
	return connection, nil
}

// DialUDP opens a connected UDP socket explicitly bound to localPort on this
// edge's overlay address. The caller owns the returned connection.
func (e *Egress) DialUDP(localPort uint16, remote netip.AddrPort) (net.Conn, error) {
	if localPort == 0 {
		return nil, errors.New("UDP local port is required")
	}
	remote, err := e.validateRemote(remote)
	if err != nil {
		return nil, err
	}
	localAddress, localProtocol := fullAddress(netip.AddrPortFrom(e.local, localPort))
	remoteAddress, remoteProtocol := fullAddress(remote)
	if localProtocol != remoteProtocol {
		return nil, fmt.Errorf("UDP local and remote address families differ")
	}
	connection, err := gonet.DialUDP(e.stack, &localAddress, &remoteAddress, remoteProtocol)
	if err != nil {
		return nil, err
	}
	return connection, nil
}
