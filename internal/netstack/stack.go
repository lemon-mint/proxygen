package netstack

import (
	"fmt"
	"git.gosuda.org/lemon-mint/proxygen/internal/model"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
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
type udpTransportHandler func(stack.TransportEndpointID, *stack.PacketBuffer) bool

func buildStack(mtu, maxTCPInFlight int, handlers Handlers) (*stack.Stack, *channel.Endpoint, *tcp.Forwarder, udpTransportHandler, error) {
	ep := channel.New(outboundQueueSize, uint32(mtu), "")
	// HandleLocal must remain false on this promiscuous ingress NIC. With it
	// enabled, gVisor treats every unassigned packet source as a temporary local
	// address and rejects the packet before transport delivery.
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
		HandleLocal: false,
	})
	cleanup := func() {
		s.Destroy()
		ep.Close()
	}
	if err := configureTCPBuffers(s); err != nil {
		cleanup()
		return nil, nil, nil, nil, err
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

	tcpForwarder := tcp.NewForwarder(s, model.TCPIngressReceiveWindowBytes, maxTCPInFlight, handlers.TCP)
	udpHandler := makeUDPTransportHandler(s, handlers.UDP)
	// Transport handlers are initialization-only in gVisor. Install both before
	// NewIngress makes the device observable or emits EventUp.
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpHandler)
	// Consume unsupported ICMP explicitly. Without default handlers, gVisor's
	// IPv6 endpoint synthesizes echo replies for temporary promiscuous
	// destinations, making arbitrary remote pings appear successful locally.
	dropICMP := func(stack.TransportEndpointID, *stack.PacketBuffer) bool { return true }
	s.SetTransportProtocolHandler(icmp.ProtocolNumber4, dropICMP)
	s.SetTransportProtocolHandler(icmp.ProtocolNumber6, dropICMP)

	return s, ep, tcpForwarder, udpHandler, nil
}

// makeUDPTransportHandler deliberately bypasses udp.NewForwarder. That helper
// clones every first packet without releasing the clone in the selected gVisor
// revision. Our UDP handler creates its endpoint synchronously before returning,
// so a stack-owned packet can be borrowed safely for the duration of this call.
func makeUDPTransportHandler(s *stack.Stack, handler udp.ForwarderHandler) udpTransportHandler {
	return func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		return handler(udp.NewForwarderRequest(s, id, pkt))
	}
}

func configureTCPBuffers(s *stack.Stack) error {
	send := tcpip.TCPSendBufferSizeRangeOption{
		Min:     4096,
		Default: model.TCPStackBufferBytes,
		Max:     model.TCPStackBufferBytes,
	}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &send); err != nil {
		return tcpipError("configure TCP send buffers", err)
	}
	receive := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     4096,
		Default: model.TCPStackBufferBytes,
		Max:     model.TCPStackBufferBytes,
	}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &receive); err != nil {
		return tcpipError("configure TCP receive buffers", err)
	}
	moderateReceive := tcpip.TCPModerateReceiveBufferOption(false)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &moderateReceive); err != nil {
		return tcpipError("disable TCP receive autotuning", err)
	}
	return nil
}

func tcpipError(operation string, err tcpip.Error) error {
	return fmt.Errorf("%s: %s", operation, err.String())
}
