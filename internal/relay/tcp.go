// Package relay connects ingress transport endpoints to healthy egress edges.
package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"git.gosuda.org/lemon-mint/proxygen/internal/egress"
	"git.gosuda.org/lemon-mint/proxygen/internal/model"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// TCPConfig bounds TCP admission, racing, and relay memory.
type TCPConfig struct {
	Workers          int
	QueueDepth       int
	ConnectTimeout   time.Duration
	IdleTimeout      time.Duration
	RelayBufferBytes int
	AllowDestination DestinationPolicy

	// AbortPending synchronously aborts in-progress endpoint handshakes on Close.
	AbortPending func()
}

// TCPSnapshot is an atomic point-in-time view of TCP relay activity.
type TCPSnapshot struct {
	// Admissions is the cumulative number of requests handed to workers.
	Admissions uint64 `json:"admissions"`
	// Active is the number of admitted requests currently dialing or relaying.
	Active int64 `json:"active"`
	// Wins and Failures count completed edge races by outcome. Denied counts
	// requests rejected by the destination ACL before endpoint creation.
	Wins     uint64 `json:"wins"`
	Failures uint64 `json:"failures"`
	Denied   uint64 `json:"denied"`
}

type tcpStats struct {
	admissions atomic.Uint64
	active     atomic.Int64
	wins       atomic.Uint64
	failures   atomic.Uint64
	denied     atomic.Uint64
}

// TCP owns the bounded workers that race and relay ingress TCP connections.
type TCP struct {
	source           egress.Source
	observer         egress.TCPObserver
	connectTimeout   time.Duration
	idleTimeout      time.Duration
	allowDestination DestinationPolicy
	abortPending     func()
	now              func() time.Time
	buffers          sync.Pool

	ctx    context.Context
	cancel context.CancelFunc

	admissions chan struct{}
	jobs       chan tcpJob

	gateMu    sync.Mutex
	closing   bool
	requests  sync.WaitGroup
	workers   sync.WaitGroup
	closeOnce sync.Once
	stats     tcpStats
}

type tcpJob struct {
	ingress     net.Conn
	destination netip.AddrPort
}

type request interface {
	ID() stack.TransportEndpointID
	CreateConn() (net.Conn, bool)
	Complete(bool)
}

type gvisorRequest struct {
	request *tcp.ForwarderRequest
}

func (r gvisorRequest) ID() stack.TransportEndpointID {
	return r.request.ID()
}

func (r gvisorRequest) CreateConn() (net.Conn, bool) {
	var queue waiter.Queue
	endpoint, err := r.request.CreateEndpoint(&queue)
	if err != nil {
		return nil, false
	}
	return gonet.NewTCPConn(&queue, endpoint), true
}

func (r gvisorRequest) Complete(sendReset bool) {
	r.request.Complete(sendReset)
}

// NewTCP starts a bounded TCP race/relay worker pool.
func NewTCP(source egress.Source, cfg TCPConfig) (*TCP, error) {
	if source == nil {
		return nil, fmt.Errorf("TCP relay source is required")
	}
	if cfg.Workers < 1 {
		return nil, fmt.Errorf("TCP relay workers must be positive")
	}
	if cfg.QueueDepth < 0 {
		return nil, fmt.Errorf("TCP relay queue depth must not be negative")
	}
	if cfg.ConnectTimeout <= 0 {
		return nil, fmt.Errorf("TCP relay connect timeout must be positive")
	}
	if cfg.IdleTimeout <= 0 {
		return nil, fmt.Errorf("TCP relay idle timeout must be positive")
	}
	if cfg.RelayBufferBytes < 1 {
		return nil, fmt.Errorf("TCP relay buffer size must be positive")
	}
	if cfg.AllowDestination == nil {
		return nil, fmt.Errorf("TCP relay destination policy is required")
	}
	if cfg.AbortPending == nil {
		return nil, fmt.Errorf("TCP relay pending-request abort callback is required")
	}
	observer, _ := source.(egress.TCPObserver)

	ctx, cancel := context.WithCancel(context.Background())
	capacity := cfg.Workers + cfg.QueueDepth
	relay := &TCP{
		source:           source,
		connectTimeout:   cfg.ConnectTimeout,
		idleTimeout:      cfg.IdleTimeout,
		allowDestination: cfg.AllowDestination,
		observer:         observer,
		abortPending:     cfg.AbortPending,
		now:              time.Now,
		ctx:              ctx,
		cancel:           cancel,
		admissions:       make(chan struct{}, capacity),
		jobs:             make(chan tcpJob, capacity),
	}
	relay.buffers.New = func() any {
		return make([]byte, cfg.RelayBufferBytes)
	}
	relay.workers.Add(cfg.Workers)
	for range cfg.Workers {
		go relay.runWorker()
	}
	return relay, nil
}

// Handle accepts one gVisor TCP forwarder request. It never waits for worker
// capacity: an over-capacity or shutting-down request is reset immediately.
func (r *TCP) Handle(req *tcp.ForwarderRequest) {
	if req == nil {
		return
	}
	r.handle(gvisorRequest{request: req})
}

func (r *TCP) handle(req request) {
	if !r.beginRequest() {
		req.Complete(true)
		return
	}
	defer r.requests.Done()

	select {
	case r.admissions <- struct{}{}:
	default:
		req.Complete(true)
		return
	}
	admitted := true
	defer func() {
		if admitted {
			<-r.admissions
		}
	}()

	key, err := flowKeyFromID(req.ID())
	if err != nil {
		req.Complete(true)
		return
	}
	if !r.allowDestination(key) {
		r.stats.denied.Add(1)
		req.Complete(true)
		return
	}

	ingress, ok := req.CreateConn()
	if !ok {
		req.Complete(true)
		return
	}
	req.Complete(false)
	r.stats.admissions.Add(1)

	job := tcpJob{
		ingress: ingress,
		destination: netip.AddrPortFrom(
			key.DestinationAddr,
			key.DestinationPort,
		),
	}
	r.jobs <- job
	admitted = false
}

func (r *TCP) beginRequest() bool {
	r.gateMu.Lock()
	defer r.gateMu.Unlock()
	if r.closing {
		return false
	}
	r.requests.Add(1)
	return true
}

func (r *TCP) runWorker() {
	defer r.workers.Done()
	for job := range r.jobs {
		r.process(job)
		<-r.admissions
	}
}

func (r *TCP) process(job tcpJob) {
	defer job.ingress.Close()
	if r.ctx.Err() != nil {
		return
	}

	r.stats.active.Add(1)
	defer r.stats.active.Add(-1)

	egressConn := r.race(job.destination)
	if egressConn == nil {
		return
	}
	defer egressConn.Close()

	r.relay(job.ingress, egressConn)
}

type raceWinner struct {
	conn net.Conn
}

func (r *TCP) race(destination netip.AddrPort) net.Conn {
	if r.ctx.Err() != nil {
		return nil
	}

	edges := r.source.Healthy()
	if len(edges) == 0 {
		r.stats.failures.Add(1)
		return nil
	}

	ctx, cancel := context.WithTimeout(r.ctx, r.connectTimeout)
	defer cancel()

	var winner atomic.Pointer[raceWinner]
	var attempts sync.WaitGroup
	attempts.Add(len(edges))
	for _, edge := range edges {
		go func(edge egress.Edge) {
			defer attempts.Done()
			started := time.Now()
			conn, err := edge.DialTCP(ctx, destination)
			latency := time.Since(started)
			if err != nil || conn == nil {
				if conn != nil {
					conn.Close()
				}
				return
			}
			candidate := &raceWinner{conn: conn}
			if ctx.Err() != nil || !winner.CompareAndSwap(nil, candidate) {
				conn.Close()
				return
			}
			r.stats.wins.Add(1)
			cancel()
			if r.observer != nil {
				r.observer.ObserveTCP(destination, edge.ID(), latency)
			}
		}(edge)
	}
	attempts.Wait()

	selected := winner.Load()
	if selected == nil {
		if r.ctx.Err() == nil {
			r.stats.failures.Add(1)
		}
		return nil
	}
	if r.ctx.Err() != nil {
		selected.conn.Close()
		return nil
	}
	return selected.conn
}

type closeWriter interface {
	CloseWrite() error
}

type closeReader interface {
	CloseRead() error
}

type activityDeadline struct {
	mu          sync.Mutex
	idleTimeout time.Duration
	left        net.Conn
	right       net.Conn
	now         func() time.Time
}

func (d *activityDeadline) refresh() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	deadline := d.now().Add(d.idleTimeout)
	leftErr := d.left.SetDeadline(deadline)
	rightErr := d.right.SetDeadline(deadline)
	return errors.Join(leftErr, rightErr)
}

type activityConn struct {
	net.Conn
	deadline *activityDeadline
}

func (c activityConn) Read(buffer []byte) (int, error) {
	count, err := c.Conn.Read(buffer)
	if count > 0 {
		if deadlineErr := c.deadline.refresh(); deadlineErr != nil {
			err = errors.Join(err, deadlineErr)
		}
	}
	return count, err
}

func (c activityConn) Write(buffer []byte) (int, error) {
	count, err := c.Conn.Write(buffer)
	if count > 0 {
		if deadlineErr := c.deadline.refresh(); deadlineErr != nil {
			err = errors.Join(err, deadlineErr)
		}
	}
	return count, err
}

func (c activityConn) CloseWrite() error {
	if closer, ok := c.Conn.(closeWriter); ok {
		return closer.CloseWrite()
	}
	return nil
}

func (c activityConn) CloseRead() error {
	if closer, ok := c.Conn.(closeReader); ok {
		return closer.CloseRead()
	}
	return nil
}

func (r *TCP) relay(left, right net.Conn) {
	deadline := &activityDeadline{
		idleTimeout: r.idleTimeout,
		left:        left,
		right:       right,
		now:         r.now,
	}
	if err := deadline.refresh(); err != nil {
		left.Close()
		right.Close()
		return
	}

	activeLeft := activityConn{Conn: left, deadline: deadline}
	activeRight := activityConn{Conn: right, deadline: deadline}
	results := make(chan error, 2)
	go r.copyDirection(results, activeRight, activeLeft)
	go r.copyDirection(results, activeLeft, activeRight)

	for completed := 0; completed < 2; completed++ {
		select {
		case err := <-results:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				left.Close()
				right.Close()
			}
		case <-r.ctx.Done():
			left.Close()
			right.Close()
			for ; completed < 2; completed++ {
				<-results
			}
			return
		}
	}
}

func (r *TCP) copyDirection(results chan<- error, destination, source net.Conn) {
	buffer := r.buffers.Get().([]byte)
	defer r.buffers.Put(buffer)
	_, err := io.CopyBuffer(destination, source, buffer)
	if closer, ok := destination.(closeWriter); ok {
		closer.CloseWrite()
	}
	if closer, ok := source.(closeReader); ok {
		closer.CloseRead()
	}
	results <- err
}

// Snapshot returns relay counters and gauges without blocking the data path.
func (r *TCP) Snapshot() TCPSnapshot {
	if r == nil {
		return TCPSnapshot{}
	}
	return TCPSnapshot{
		Admissions: r.stats.admissions.Load(),
		Active:     r.stats.active.Load(),
		Wins:       r.stats.wins.Load(),
		Failures:   r.stats.failures.Load(),
		Denied:     r.stats.denied.Load(),
	}
}

// Close rejects new requests, cancels every race and relay, aborts pending
// endpoint handshakes, closes queued ingress connections, and waits until all
// accepted work has finished.
func (r *TCP) Close() {
	r.closeOnce.Do(func() {
		r.gateMu.Lock()
		r.closing = true
		r.gateMu.Unlock()

		r.cancel()
		r.abortPending()
		r.requests.Wait()
		close(r.jobs)
		r.workers.Wait()
	})
}

func flowKeyFromID(id stack.TransportEndpointID) (model.FlowKey, error) {
	source, version, err := addressFromTCPIP(id.RemoteAddress)
	if err != nil {
		return model.FlowKey{}, fmt.Errorf("TCP source address: %w", err)
	}
	destination, destinationVersion, err := addressFromTCPIP(id.LocalAddress)
	if err != nil {
		return model.FlowKey{}, fmt.Errorf("TCP destination address: %w", err)
	}
	if destinationVersion != version {
		return model.FlowKey{}, fmt.Errorf("TCP source and destination address families differ")
	}

	key := model.FlowKey{
		IPVersion:       version,
		Protocol:        model.ProtocolTCP,
		SourceAddr:      source,
		SourcePort:      id.RemotePort,
		DestinationAddr: destination,
		DestinationPort: id.LocalPort,
	}
	if err := key.Validate(); err != nil {
		return model.FlowKey{}, err
	}
	return key, nil
}

func addressFromTCPIP(address tcpip.Address) (netip.Addr, model.IPVersion, error) {
	switch address.Len() {
	case 4:
		return netip.AddrFrom4(address.As4()), model.IPv4, nil
	case 16:
		return netip.AddrFrom16(address.As16()), model.IPv6, nil
	default:
		return netip.Addr{}, 0, fmt.Errorf("address length is %d, want 4 or 16", address.Len())
	}
}
