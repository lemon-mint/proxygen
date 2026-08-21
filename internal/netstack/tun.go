package netstack

import (
	"fmt"
	"os"
	"sync"
	"syscall"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

const (
	ingressName = "proxygen-ingress"
	egressName  = "proxygen-egress"
)

// Ingress is a userspace-only WireGuard TUN device backed by a gVisor channel
// endpoint. It owns both the endpoint and its gVisor stack.
type Ingress struct {
	name string
	mtu  int

	stack        *stack.Stack
	ep           *channel.Endpoint
	tcpForwarder *tcp.Forwarder
	udpHandler   udpTransportHandler
	notifyHandle *channel.NotificationHandle

	events chan tun.Event
	ready  chan struct{}
	closed chan struct{}

	stateMu   sync.RWMutex
	isClosed  bool
	closeOnce sync.Once
}

var (
	_ tun.Device           = (*Ingress)(nil)
	_ channel.Notification = (*Ingress)(nil)
)

// NewIngress constructs an ingress stack and installs its transport handlers
// before publishing EventUp. It does not create or open a host TUN device.
func NewIngress(mtu, maxTCPInFlight int, handlers Handlers) (*Ingress, error) {
	if err := validateMTU(mtu); err != nil {
		return nil, err
	}
	if maxTCPInFlight < 0 {
		return nil, fmt.Errorf("maximum TCP in-flight requests must not be negative")
	}
	if handlers.TCP == nil {
		return nil, fmt.Errorf("TCP handler is required")
	}
	if handlers.UDP == nil {
		return nil, fmt.Errorf("UDP handler is required")
	}

	s, ep, tcpForwarder, udpHandler, err := buildStack(mtu, maxTCPInFlight, handlers)
	if err != nil {
		return nil, err
	}

	return newChannelIngress(ingressName, mtu, s, ep, tcpForwarder, udpHandler), nil
}

func newChannelIngress(
	name string,
	mtu int,
	s *stack.Stack,
	ep *channel.Endpoint,
	tcpForwarder *tcp.Forwarder,
	udpHandler udpTransportHandler,
) *Ingress {
	ingress := &Ingress{
		name:         name,
		mtu:          mtu,
		stack:        s,
		ep:           ep,
		tcpForwarder: tcpForwarder,
		udpHandler:   udpHandler,
		events:       make(chan tun.Event, 1),
		ready:        make(chan struct{}, 1),
		closed:       make(chan struct{}),
	}
	ingress.notifyHandle = ep.AddNotify(ingress)
	ingress.events <- tun.EventUp
	return ingress
}

func validateMTU(mtu int) error {
	if mtu <= 0 || mtu > device.MaxContentSize {
		return fmt.Errorf("MTU must be between 1 and %d", device.MaxContentSize)
	}
	return nil
}

// File returns nil because Ingress has no host file descriptor.
func (*Ingress) File() *os.File {
	return nil
}

// Name returns the stable synthetic device name.
func (i *Ingress) Name() (string, error) {
	return i.name, nil
}

// MTU returns the configured layer-three MTU.
func (i *Ingress) MTU() (int, error) {
	return i.mtu, nil
}

// Events returns device lifecycle notifications.
func (i *Ingress) Events() <-chan tun.Event {
	return i.events
}

// BatchSize returns the fixed maximum packet batch accepted by Read and Write.
func (*Ingress) BatchSize() int {
	return conn.IdealBatchSize
}

// WriteNotify implements channel.Notification. Notifications may occur on a
// gVisor packet-output path, so they are deliberately coalesced and never block.
func (i *Ingress) WriteNotify() {
	select {
	case i.ready <- struct{}{}:
	default:
	}
}

// Read copies one or more complete outbound L3 packets into bufs. It blocks for
// the first packet, then drains all packets immediately available for the batch.
func (i *Ingress) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if err := validateReadBatch(bufs, sizes, offset); err != nil {
		return 0, err
	}

	pkt, err := i.waitPacket()
	if err != nil {
		return 0, err
	}

	n := 0
	for {
		sizes[n] = copyPacket(bufs[n][offset:], pkt)
		pkt.DecRef()
		n++
		if n == len(bufs) {
			return n, nil
		}

		pkt = i.ep.Read()
		if pkt == nil {
			return n, nil
		}
	}
}

func (i *Ingress) waitPacket() (*stack.PacketBuffer, error) {
	for {
		select {
		case <-i.closed:
			return nil, os.ErrClosed
		default:
		}

		if pkt := i.ep.Read(); pkt != nil {
			return pkt, nil
		}

		select {
		case <-i.closed:
			return nil, os.ErrClosed
		case <-i.ready:
		}
	}
}

func copyPacket(dst []byte, pkt *stack.PacketBuffer) int {
	views, skip := pkt.AsViewList()
	n := 0
	for view := views.Front(); view != nil; view = view.Next() {
		src := view.AsSlice()
		if skip >= len(src) {
			skip -= len(src)
			continue
		}
		src = src[skip:]
		skip = 0
		n += copy(dst[n:], src)
		if n == len(dst) {
			break
		}
	}
	return n
}

// Write copies and synchronously injects each inbound L3 packet into gVisor.
// Holding the read side of stateMu makes the close gate and injection atomic:
// once Close marks the device closed, no later injection is possible.
func (i *Ingress) Write(bufs [][]byte, offset int) (int, error) {
	if err := validateWriteBatch(bufs, offset); err != nil {
		return 0, err
	}

	i.stateMu.RLock()
	defer i.stateMu.RUnlock()
	if i.isClosed {
		return 0, os.ErrClosed
	}

	for index, buf := range bufs {
		packet := buf[offset:]
		var protocolNumber = header.IPv4ProtocolNumber
		switch packet[0] >> 4 {
		case 4:
		case 6:
			protocolNumber = header.IPv6ProtocolNumber
		default:
			return index, syscall.EAFNOSUPPORT
		}

		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(packet),
		})
		i.ep.InjectInbound(protocolNumber, pkt)
		pkt.DecRef()
	}
	return len(bufs), nil
}

func validateReadBatch(bufs [][]byte, sizes []int, offset int) error {
	if len(bufs) == 0 {
		return syscall.EINVAL
	}
	if len(bufs) > conn.IdealBatchSize || len(sizes) < len(bufs) {
		return syscall.EINVAL
	}
	return validateBuffers(bufs, offset, true)
}

func validateWriteBatch(bufs [][]byte, offset int) error {
	if len(bufs) == 0 || len(bufs) > conn.IdealBatchSize {
		return syscall.EINVAL
	}
	return validateBuffers(bufs, offset, false)
}

func validateBuffers(bufs [][]byte, offset int, allowEmptyPayload bool) error {
	if offset < 0 {
		return syscall.EINVAL
	}
	for _, buf := range bufs {
		if offset > len(buf) || (!allowEmptyPayload && offset == len(buf)) {
			return syscall.EINVAL
		}
	}
	return nil
}

// Close gates new writes, wakes readers, removes the synchronous notification,
// and destroys all gVisor-owned resources exactly once.
func (i *Ingress) Close() error {
	i.closeOnce.Do(func() {
		i.stateMu.Lock()
		i.isClosed = true
		close(i.closed)
		i.stateMu.Unlock()

		i.ep.RemoveNotify(i.notifyHandle)
		i.ep.Close()
		i.stack.Destroy()
		close(i.events)
	})
	return nil
}
