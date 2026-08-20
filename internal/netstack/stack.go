package netstack

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	ingressNICID      tcpip.NICID = 1
	outboundQueueSize             = 1024
)

// Handlers receive connection and session requests accepted by the ingress
// stack. TCP handlers run in the goroutine started by gVisor's TCP forwarder;
// UDP handlers run synchronously on packet delivery.
type Handlers struct {
	TCP func(*tcp.ForwarderRequest)
	UDP udp.ForwarderHandler
}

func buildStack(mtu, maxTCPInFlight int, handlers Handlers) (*stack.Stack, *channel.Endpoint, *tcp.Forwarder, *udp.Forwarder, error) {
	ep := channel.New(outboundQueueSize, uint32(mtu), "")
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
		},
		HandleLocal: true,
	})
	cleanup := func() {
		s.Destroy()
		ep.Close()
	}

	if err := s.CreateNIC(ingressNICID, ep); err != nil {
		cleanup()
		return nil, nil, nil, nil, tcpipError("create ingress NIC", err)
	}
	if err := s.SetPromiscuousMode(ingressNICID, true); err != nil {
		cleanup()
		return nil, nil, nil, nil, tcpipError("enable ingress promiscuous mode", err)
	}
	if err := s.SetSpoofing(ingressNICID, true); err != nil {
		cleanup()
		return nil, nil, nil, nil, tcpipError("enable ingress spoofing", err)
	}

	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: ingressNICID},
		{Destination: header.IPv6EmptySubnet, NIC: ingressNICID},
	})

	tcpForwarder := tcp.NewForwarder(s, 0, maxTCPInFlight, handlers.TCP)
	udpForwarder := udp.NewForwarder(s, handlers.UDP)
	// Transport handlers are initialization-only in gVisor. Install both before
	// NewIngress makes the device observable or emits EventUp.
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	return s, ep, tcpForwarder, udpForwarder, nil
}

func tcpipError(operation string, err tcpip.Error) error {
	return fmt.Errorf("%s: %s", operation, err.String())
}
