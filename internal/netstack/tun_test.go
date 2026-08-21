package netstack

import (
	"errors"
	"git.gosuda.org/lemon-mint/proxygen/internal/model"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

func testHandlers() Handlers {
	return Handlers{
		TCP: func(req *tcp.ForwarderRequest) {
			req.Complete(true)
		},
		UDP: func(*udp.ForwarderRequest) bool {
			return false
		},
	}
}

func newTestIngress(t *testing.T) *Ingress {
	t.Helper()
	dev, err := NewIngress(1420, 8, testHandlers())
	if err != nil {
		t.Fatalf("NewIngress: %v", err)
	}
	t.Cleanup(func() {
		if err := dev.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return dev
}

func assertTCPBufferBounds(t *testing.T, networkStack *stack.Stack) {
	t.Helper()
	var send tcpip.TCPSendBufferSizeRangeOption
	if err := networkStack.TransportProtocolOption(tcp.ProtocolNumber, &send); err != nil {
		t.Fatalf("read TCP send buffer option: %s", err)
	}
	if send.Default != model.TCPStackBufferBytes || send.Max != model.TCPStackBufferBytes {
		t.Fatalf("TCP send buffers = %+v, want default/max %d", send, model.TCPStackBufferBytes)
	}
	var receive tcpip.TCPReceiveBufferSizeRangeOption
	if err := networkStack.TransportProtocolOption(tcp.ProtocolNumber, &receive); err != nil {
		t.Fatalf("read TCP receive buffer option: %s", err)
	}
	if receive.Default != model.TCPStackBufferBytes || receive.Max != model.TCPStackBufferBytes {
		t.Fatalf("TCP receive buffers = %+v, want default/max %d", receive, model.TCPStackBufferBytes)
	}
	var moderate tcpip.TCPModerateReceiveBufferOption
	if err := networkStack.TransportProtocolOption(tcp.ProtocolNumber, &moderate); err != nil {
		t.Fatalf("read TCP autotuning option: %s", err)
	}
	if bool(moderate) {
		t.Fatal("TCP receive autotuning is enabled")
	}
}

func TestNewIngressConfiguresUserspaceStackBeforeEventUp(t *testing.T) {
	dev := newTestIngress(t)

	if dev.File() != nil {
		t.Fatal("File returned a host file descriptor")
	}
	if got, err := dev.Name(); err != nil || got != ingressName {
		t.Fatalf("Name = %q, %v; want %q, nil", got, err, ingressName)
	}
	if got, err := dev.MTU(); err != nil || got != 1420 {
		t.Fatalf("MTU = %d, %v; want 1420, nil", got, err)
	}
	if got := dev.BatchSize(); got != conn.IdealBatchSize {
		t.Fatalf("BatchSize = %d; want %d", got, conn.IdealBatchSize)
	}
	if dev.tcpForwarder == nil || dev.udpHandler == nil {
		t.Fatal("transport handlers were not installed")
	}
	assertTCPBufferBounds(t, dev.stack)

	info, ok := dev.stack.SingleNICInfo(ingressNICID)
	if !ok {
		t.Fatal("ingress NIC is missing")
	}
	if !info.Flags.Promiscuous {
		t.Fatal("ingress NIC is not promiscuous")
	}
	arbitrary := tcpip.AddrFrom4([4]byte{203, 0, 113, 9})
	if got := dev.stack.CheckLocalAddress(ingressNICID, ipv4.ProtocolNumber, arbitrary); got != ingressNICID {
		t.Fatalf("CheckLocalAddress returned NIC %d; spoofing is not enabled", got)
	}

	routes := dev.stack.GetRouteTable()
	var hasV4Default, hasV6Default bool
	for _, route := range routes {
		if route.NIC != ingressNICID {
			continue
		}
		hasV4Default = hasV4Default || route.Destination.Equal(header.IPv4EmptySubnet)
		hasV6Default = hasV6Default || route.Destination.Equal(header.IPv6EmptySubnet)
	}
	if !hasV4Default || !hasV6Default {
		t.Fatalf("route table lacks defaults: IPv4=%t IPv6=%t", hasV4Default, hasV6Default)
	}

	select {
	case event, ok := <-dev.Events():
		if !ok || event != tun.EventUp {
			t.Fatalf("first event = %v, %t; want EventUp", event, ok)
		}
	default:
		t.Fatal("EventUp was not published by the constructor")
	}
}
func TestIngressConsumesUnsupportedICMPEchoWithoutSyntheticReply(t *testing.T) {
	tests := []struct {
		name     string
		packet   []byte
		protocol tcpip.TransportProtocolNumber
	}{
		{name: "IPv4", packet: icmpv4EchoRequest(), protocol: header.ICMPv4ProtocolNumber},
		{name: "IPv6", packet: icmpv6EchoRequest(), protocol: header.ICMPv6ProtocolNumber},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dev := newTestIngress(t)
			if dev.stack.TransportProtocolInstance(test.protocol) == nil {
				t.Fatalf("ICMP transport protocol %d is not registered", test.protocol)
			}
			if written, err := dev.Write([][]byte{test.packet}, 0); err != nil || written != 1 {
				t.Fatalf("Write() = %d, %v; want 1, nil", written, err)
			}
			if queued := dev.ep.NumQueued(); queued != 0 {
				t.Fatalf("unsupported %s echo produced %d synthetic outbound packet(s)", test.name, queued)
			}
		})
	}
}

func icmpv4EchoRequest() []byte {
	packet := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize)
	source := tcpip.AddrFrom4([4]byte{10, 77, 0, 2})
	destination := tcpip.AddrFrom4([4]byte{8, 8, 8, 8})
	ip := header.IPv4(packet)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     source,
		DstAddr:     destination,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	icmp := header.ICMPv4(packet[header.IPv4MinimumSize:])
	icmp.SetType(header.ICMPv4Echo)
	icmp.SetCode(0)
	icmp.SetIdent(7)
	icmp.SetSequence(11)
	icmp.SetChecksum(^checksum.Checksum(icmp, 0))
	return packet
}

func icmpv6EchoRequest() []byte {
	packet := make([]byte, header.IPv6MinimumSize+header.ICMPv6EchoMinimumSize)
	source := tcpip.AddrFrom16([16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	destination := tcpip.AddrFrom16([16]byte{0x26, 0x06, 0x47, 0, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11})
	ip := header.IPv6(packet)
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     header.ICMPv6EchoMinimumSize,
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          64,
		SrcAddr:           source,
		DstAddr:           destination,
	})
	icmp := header.ICMPv6(packet[header.IPv6MinimumSize:])
	icmp.SetType(header.ICMPv6EchoRequest)
	icmp.SetCode(0)
	icmp.SetIdent(7)
	icmp.SetSequence(11)
	icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:     icmp,
		Src:        source,
		Dst:        destination,
		PayloadLen: 0,
	}))
	return packet
}

func TestNewIngressRejectsInvalidArguments(t *testing.T) {
	tests := []struct {
		name     string
		mtu      int
		maxTCP   int
		handlers Handlers
	}{
		{name: "zero MTU", mtu: 0, maxTCP: 1, handlers: testHandlers()},
		{name: "MTU exceeds WireGuard content size", mtu: device.MaxContentSize + 1, maxTCP: 1, handlers: testHandlers()},
		{name: "negative TCP limit", mtu: 1420, maxTCP: -1, handlers: testHandlers()},
		{name: "missing TCP handler", mtu: 1420, maxTCP: 1, handlers: Handlers{UDP: testHandlers().UDP}},
		{name: "missing UDP handler", mtu: 1420, maxTCP: 1, handlers: Handlers{TCP: testHandlers().TCP}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dev, err := NewIngress(test.mtu, test.maxTCP, test.handlers)
			if err == nil {
				dev.Close()
				t.Fatal("NewIngress succeeded; want an error")
			}
		})
	}
}

func TestReadReturnsQueuedPacketsAsBatchWithOffset(t *testing.T) {
	dev := newTestIngress(t)
	payloads := [][]byte{
		{0x45, 1, 2, 3},
		{0x60, 4, 5, 6, 7},
		{0x45, 8, 9},
	}

	var packets stack.PacketBufferList
	for _, payload := range payloads {
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(payload),
		})
		packets.PushBack(pkt)
	}
	written, tcpipErr := dev.ep.WritePackets(packets)
	packets.DecRef()
	if tcpipErr != nil {
		t.Fatalf("WritePackets: %s", tcpipErr.String())
	}
	if written != len(payloads) {
		t.Fatalf("WritePackets wrote %d packets; want %d", written, len(payloads))
	}

	bufs := make([][]byte, len(payloads))
	for index := range bufs {
		bufs[index] = make([]byte, 32)
		bufs[index][0] = 0xa5
		bufs[index][1] = 0x5a
	}
	sizes := make([]int, len(bufs))
	n, err := dev.Read(bufs, sizes, 2)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n != len(payloads) {
		t.Fatalf("Read returned %d packets; want %d", n, len(payloads))
	}
	for index, want := range payloads {
		if sizes[index] != len(want) {
			t.Errorf("sizes[%d] = %d; want %d", index, sizes[index], len(want))
		}
		if bufs[index][0] != 0xa5 || bufs[index][1] != 0x5a {
			t.Errorf("Read overwrote offset prefix for packet %d", index)
		}
		if got := bufs[index][2 : 2+sizes[index]]; string(got) != string(want) {
			t.Errorf("packet %d = %v; want %v", index, got, want)
		}
	}
}

func TestWriteProcessesBatchAndReportsUnsupportedPacket(t *testing.T) {
	dev := newTestIngress(t)
	ipv4Packet := make([]byte, 20)
	ipv4Packet[0] = 0x45
	ipv4Packet[2] = 0
	ipv4Packet[3] = 20
	ipv4Packet[8] = 64
	ipv4Packet[9] = 255
	ipv4Packet[12] = 192
	ipv4Packet[13] = 0
	ipv4Packet[14] = 2
	ipv4Packet[15] = 1
	ipv4Packet[16] = 198
	ipv4Packet[17] = 51
	ipv4Packet[18] = 100
	ipv4Packet[19] = 1

	first := append([]byte{0xaa, 0xbb}, ipv4Packet...)
	second := []byte{0xaa, 0xbb, 0x70}
	n, err := dev.Write([][]byte{first, second}, 2)
	if n != 1 {
		t.Fatalf("Write returned %d packets; want 1", n)
	}
	if !errors.Is(err, syscall.EAFNOSUPPORT) {
		t.Fatalf("Write error = %v; want EAFNOSUPPORT", err)
	}
}

func TestWriteNotifyNeverBlocks(t *testing.T) {
	dev := newTestIngress(t)
	done := make(chan struct{})
	go func() {
		dev.WriteNotify()
		dev.WriteNotify()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		// Unblock a broken second send so the test does not leak its goroutine.
		<-dev.ready
		<-done
		t.Fatal("WriteNotify blocked with a pending notification")
	}
	if got := len(dev.ready); got != 1 {
		t.Fatalf("pending notifications = %d; want one coalesced notification", got)
	}
}

func TestCloseIsConcurrentSafeAndUnblocksRead(t *testing.T) {
	dev := newTestIngress(t)
	if event := <-dev.Events(); event != tun.EventUp {
		t.Fatalf("first event = %v; want EventUp", event)
	}

	readResult := make(chan error, 1)
	go func() {
		_, err := dev.Read([][]byte{make([]byte, 64)}, make([]int, 1), 0)
		readResult <- err
	}()

	const closers = 8
	var wg sync.WaitGroup
	wg.Add(closers)
	for range closers {
		go func() {
			defer wg.Done()
			if err := dev.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		}()
	}
	wg.Wait()

	select {
	case err := <-readResult:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("blocked Read returned %v; want os.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock Read")
	}

	if _, ok := <-dev.Events(); ok {
		t.Fatal("Close did not close Events")
	}
	if n, err := dev.Write([][]byte{{0x45}}, 0); n != 0 || !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Write after Close = %d, %v; want 0, os.ErrClosed", n, err)
	}
	if err := dev.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
