// Package relay connects ingress gVisor endpoints to selected egress edges.
package relay

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/egress"
	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/model"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	gvisorudp "gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const maxUDPDatagramSize = 65535

var udpBufferPool = sync.Pool{
	New: func() any {
		buffer := make([]byte, maxUDPDatagramSize)
		return &buffer
	},
}

// UDPSnapshot is an atomic point-in-time view of UDP mapping activity.
type UDPSnapshot struct {
	// Mappings is the number of currently active full-tuple mappings.
	Mappings int64 `json:"mappings"`
	// Expired counts mappings closed by the idle timer.
	Expired uint64 `json:"expired"`
	// Dropped counts rejected admissions and mapping setup failures.
	Dropped uint64 `json:"dropped"`
}

type udpStats struct {
	mappings atomic.Int64
	expired  atomic.Uint64
	dropped  atomic.Uint64
}

// UDP owns the literal full-5-tuple UDP mappings for one ingress stack.
type UDP struct {
	source      egress.Source
	idleTimeout time.Duration
	maxFlows    int

	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	closed bool
	flows  map[model.FlowKey]*udpFlow
	wg     sync.WaitGroup
	stats  udpStats

	closeOnce sync.Once
}

// NewUDP constructs a bounded UDP mapping relay. It does not start background
// work until Handler accepts a flow.
func NewUDP(source egress.Source, idleTimeout time.Duration, maxFlows int) (*UDP, error) {
	if source == nil {
		return nil, errors.New("UDP relay requires an egress source")
	}
	if idleTimeout <= 0 {
		return nil, errors.New("UDP idle timeout must be greater than zero")
	}
	if maxFlows <= 0 {
		return nil, errors.New("maximum UDP flows must be greater than zero")
	}
	if maxFlows > model.MaxUDPFlows {
		return nil, errors.New("maximum UDP flows exceeds the relay memory limit")
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &UDP{
		source:      source,
		idleTimeout: idleTimeout,
		maxFlows:    maxFlows,
		ctx:         ctx,
		cancel:      cancel,
		flows:       make(map[model.FlowKey]*udpFlow),
	}, nil
}

// Handler is a synchronous gVisor UDP forwarder handler. It only validates and
// registers the local endpoint; edge selection, dialing, and packet relay run
// asynchronously so packet delivery is never held up by network operations.
func (relay *UDP) Handler(request *gvisorudp.ForwarderRequest) bool {
	if request == nil {
		relay.stats.dropped.Add(1)
		return false
	}
	key, ok := udpKeyFromEndpointID(request.ID())
	if !ok {
		relay.stats.dropped.Add(1)
		return false
	}

	return relay.admit(key, func() (net.Conn, bool) {
		var queue waiter.Queue
		endpoint, endpointErr := request.CreateEndpoint(&queue)
		if endpointErr != nil {
			return nil, false
		}
		return gonet.NewUDPConn(&queue, endpoint), true
	})
}

// admit performs the capacity check and ingress endpoint creation atomically.
// Keeping the endpoint factory here also lets focused tests exercise mapping
// behavior without constructing a gVisor packet path.
func (relay *UDP) admit(key model.FlowKey, openIngress func() (net.Conn, bool)) bool {
	if key.Protocol != model.ProtocolUDP || key.Validate() != nil || openIngress == nil {
		relay.stats.dropped.Add(1)
		return false
	}

	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.closed || len(relay.flows) >= relay.maxFlows {
		relay.stats.dropped.Add(1)
		return false
	}
	if _, exists := relay.flows[key]; exists {
		relay.stats.dropped.Add(1)
		return false
	}

	ingress, ok := openIngress()
	if !ok || ingress == nil {
		if ingress != nil {
			_ = ingress.Close()
		}
		relay.stats.dropped.Add(1)
		return false
	}

	flowCtx, cancel := context.WithCancel(relay.ctx)
	flow := &udpFlow{
		key:          key,
		ingress:      ingress,
		ctx:          flowCtx,
		cancel:       cancel,
		lastActivity: time.Now(),
	}
	relay.flows[key] = flow
	relay.stats.mappings.Add(1)
	relay.wg.Add(1)
	go relay.run(flow)
	return true
}

func (relay *UDP) run(flow *udpFlow) {
	defer relay.wg.Done()
	defer func() {
		flow.close()
		relay.mu.Lock()
		if relay.flows[flow.key] == flow {
			delete(relay.flows, flow.key)
			relay.stats.mappings.Add(-1)
		}
		relay.mu.Unlock()
	}()

	expiryDone := make(chan struct{})
	go func() {
		if flow.expire(relay.idleTimeout) {
			relay.stats.expired.Add(1)
		}
		close(expiryDone)
	}()
	defer func() {
		flow.close()
		<-expiryDone
	}()

	edge, err := relay.source.SelectUDP(flow.key)
	if err != nil || edge == nil || flow.ctx.Err() != nil {
		if flow.ctx.Err() == nil {
			relay.stats.dropped.Add(1)
		}
		return
	}
	destination := netip.AddrPortFrom(flow.key.DestinationAddr, flow.key.DestinationPort)
	egressConn, err := edge.DialUDP(flow.ctx, destination)
	if err != nil || egressConn == nil {
		if egressConn != nil {
			_ = egressConn.Close()
		}
		if flow.ctx.Err() == nil {
			relay.stats.dropped.Add(1)
		}
		return
	}
	if !flow.attachEgress(egressConn) {
		return
	}

	pumpDone := make(chan struct{}, 2)
	go relayUDPDatagrams(flow, flow.ingress, egressConn, pumpDone)
	go relayUDPDatagrams(flow, egressConn, flow.ingress, pumpDone)
	<-pumpDone
	flow.close()
	<-pumpDone
}

func relayUDPDatagrams(flow *udpFlow, source, destination net.Conn, done chan<- struct{}) {
	defer func() { done <- struct{}{} }()
	bufferPointer := udpBufferPool.Get().(*[]byte)
	buffer := *bufferPointer
	defer udpBufferPool.Put(bufferPointer)

	for {
		count, err := source.Read(buffer)
		if err != nil {
			return
		}
		if flow.ctx.Err() != nil {
			return
		}
		written, err := destination.Write(buffer[:count])
		if err != nil || written != count {
			return
		}
		flow.touch()
	}
}

// Snapshot returns mapping counters and gauges without blocking the data path.
func (relay *UDP) Snapshot() UDPSnapshot {
	if relay == nil {
		return UDPSnapshot{}
	}
	return UDPSnapshot{
		Mappings: relay.stats.mappings.Load(),
		Expired:  relay.stats.expired.Load(),
		Dropped:  relay.stats.dropped.Load(),
	}
}

// Close stops admission, closes both sockets of every mapping exactly once,
// and waits for all mapping and relay workers to leave.
func (relay *UDP) Close() error {
	relay.closeOnce.Do(func() {
		relay.mu.Lock()
		relay.closed = true
		relay.cancel()
		flows := make([]*udpFlow, 0, len(relay.flows))
		for _, flow := range relay.flows {
			flows = append(flows, flow)
		}
		relay.mu.Unlock()

		for _, flow := range flows {
			flow.close()
		}
		relay.wg.Wait()
	})
	return nil
}

type udpFlow struct {
	key     model.FlowKey
	ingress net.Conn
	ctx     context.Context
	cancel  context.CancelFunc

	mu           sync.Mutex
	egress       net.Conn
	closed       bool
	lastActivity time.Time
	closeOnce    sync.Once
}

func (flow *udpFlow) attachEgress(conn net.Conn) bool {
	if conn == nil {
		return false
	}
	flow.mu.Lock()
	if flow.closed {
		flow.mu.Unlock()
		_ = conn.Close()
		return false
	}
	flow.egress = conn
	flow.mu.Unlock()
	return true
}

func (flow *udpFlow) touch() {
	flow.mu.Lock()
	if !flow.closed {
		flow.lastActivity = time.Now()
	}
	flow.mu.Unlock()
}

func (flow *udpFlow) expire(idleTimeout time.Duration) bool {
	timer := time.NewTimer(idleTimeout)
	defer timer.Stop()
	for {
		select {
		case <-flow.ctx.Done():
			return false
		case <-timer.C:
			flow.mu.Lock()
			remaining := time.Until(flow.lastActivity.Add(idleTimeout))
			flow.mu.Unlock()
			if remaining <= 0 {
				flow.close()
				return true
			}
			timer.Reset(remaining)
		}
	}
}

func (flow *udpFlow) close() {
	flow.closeOnce.Do(func() {
		flow.cancel()
		flow.mu.Lock()
		flow.closed = true
		ingress := flow.ingress
		egressConn := flow.egress
		flow.mu.Unlock()
		_ = ingress.Close()
		if egressConn != nil {
			_ = egressConn.Close()
		}
	})
}

func udpKeyFromEndpointID(id stack.TransportEndpointID) (model.FlowKey, bool) {
	if id.RemoteAddress.Len() != id.LocalAddress.Len() {
		return model.FlowKey{}, false
	}

	var sourceAddress netip.Addr
	var destinationAddress netip.Addr
	var version model.IPVersion
	switch id.RemoteAddress.Len() {
	case 4:
		sourceAddress = netip.AddrFrom4(id.RemoteAddress.As4())
		destinationAddress = netip.AddrFrom4(id.LocalAddress.As4())
		version = model.IPv4
	case 16:
		sourceAddress = netip.AddrFrom16(id.RemoteAddress.As16())
		destinationAddress = netip.AddrFrom16(id.LocalAddress.As16())
		version = model.IPv6
	default:
		return model.FlowKey{}, false
	}

	key := model.FlowKey{
		IPVersion:       version,
		Protocol:        model.ProtocolUDP,
		SourceAddr:      sourceAddress,
		SourcePort:      id.RemotePort,
		DestinationAddr: destinationAddress,
		DestinationPort: id.LocalPort,
	}
	if key.Validate() != nil {
		return model.FlowKey{}, false
	}
	return key, true
}
