package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"git.gosuda.org/lemon-mint/proxygen/internal/egress"
	"git.gosuda.org/lemon-mint/proxygen/internal/model"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestTCPRequestFailurePathsCompleteOnce(t *testing.T) {
	t.Run("invalid flow", func(t *testing.T) {
		relay := newTestTCP(t, fakeSource{})
		defer relay.Close()

		req := &fakeRequest{id: stack.TransportEndpointID{}}
		relay.handle(req)
		req.assertCompletion(t, true)
		if req.creates != 0 {
			t.Fatalf("CreateConn calls = %d, want 0", req.creates)
		}
	})

	t.Run("endpoint creation", func(t *testing.T) {
		relay := newTestTCP(t, fakeSource{})
		defer relay.Close()

		req := &fakeRequest{id: validTCPID(), createOK: false}
		relay.handle(req)
		req.assertCompletion(t, true)
		if req.creates != 1 {
			t.Fatalf("CreateConn calls = %d, want 1", req.creates)
		}
	})

	t.Run("shutdown", func(t *testing.T) {
		relay := newTestTCP(t, fakeSource{})
		relay.Close()

		req := &fakeRequest{id: validTCPID(), createOK: true}
		relay.handle(req)
		req.assertCompletion(t, true)
		if req.creates != 0 {
			t.Fatalf("post-shutdown CreateConn calls = %d, want 0", req.creates)
		}
	})
}

func TestTCPDestinationPolicyRejectsBeforeEndpointCreation(t *testing.T) {
	relay, err := NewTCP(fakeSource{}, TCPConfig{
		Workers:          1,
		ConnectTimeout:   time.Second,
		IdleTimeout:      time.Second,
		RelayBufferBytes: 1024,
		AllowDestination: func(model.FlowKey) bool { return false },
		AbortPending:     func() {},
	})
	if err != nil {
		t.Fatalf("NewTCP: %v", err)
	}
	defer relay.Close()

	req := &fakeRequest{id: validTCPID(), createOK: true}
	relay.handle(req)
	req.assertCompletion(t, true)
	if req.creates != 0 {
		t.Fatalf("CreateConn calls = %d, want 0 for ACL denial", req.creates)
	}
	if snapshot := relay.Snapshot(); snapshot.Denied != 1 || snapshot.Admissions != 0 {
		t.Fatalf("snapshot = %+v, want one denial and no admission", snapshot)
	}
}

func TestTCPRejectsResourceLimits(t *testing.T) {
	base := TCPConfig{
		Workers:          1,
		ConnectTimeout:   time.Second,
		IdleTimeout:      time.Second,
		RelayBufferBytes: 1024,
		AllowDestination: allowAllTestDestinations,
		AbortPending:     func() {},
	}
	tests := []struct {
		name      string
		configure func(*TCPConfig)
	}{
		{name: "workers", configure: func(cfg *TCPConfig) { cfg.Workers = model.MaxTCPRaceWorkers + 1 }},
		{name: "queue", configure: func(cfg *TCPConfig) { cfg.QueueDepth = model.MaxTCPRaceQueueDepth + 1 }},
		{name: "buffer", configure: func(cfg *TCPConfig) { cfg.RelayBufferBytes = model.MaxTCPRelayBufferBytes + 1 }},
		{name: "copy memory", configure: func(cfg *TCPConfig) {
			cfg.Workers = model.MaxTCPRaceWorkers
			cfg.RelayBufferBytes = model.MaxTCPRelayBufferBytes
		}},
		{name: "aggregate memory", configure: func(cfg *TCPConfig) {
			cfg.Workers = 1024
			cfg.QueueDepth = model.MaxTCPRaceQueueDepth
			cfg.RelayBufferBytes = model.MaxTCPRelayBufferBytes
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := base
			test.configure(&cfg)
			relay, err := NewTCP(fakeSource{}, cfg)
			if err == nil {
				relay.Close()
				t.Fatal("NewTCP accepted an unsafe resource limit")
			}
		})
	}
}

func TestTCPRequiresDestinationPolicy(t *testing.T) {
	relay, err := NewTCP(fakeSource{}, TCPConfig{
		Workers:          1,
		ConnectTimeout:   time.Second,
		IdleTimeout:      time.Second,
		RelayBufferBytes: 1024,
		AbortPending:     func() {},
	})
	if err == nil {
		relay.Close()
		t.Fatal("NewTCP accepted a nil destination policy")
	}
}

func TestTCPRequiresPositiveIdleTimeout(t *testing.T) {
	relay, err := NewTCP(fakeSource{}, TCPConfig{
		Workers:          1,
		ConnectTimeout:   time.Second,
		RelayBufferBytes: 1024,
		AllowDestination: allowAllTestDestinations,
		AbortPending:     func() {},
	})
	if err == nil {
		relay.Close()
		t.Fatal("NewTCP accepted a non-positive idle timeout")
	}
}

func TestTCPRequiresAbortPending(t *testing.T) {
	relay, err := NewTCP(fakeSource{}, TCPConfig{
		Workers:          1,
		ConnectTimeout:   time.Second,
		IdleTimeout:      time.Second,
		RelayBufferBytes: 1024,
		AllowDestination: allowAllTestDestinations,
	})
	if err == nil {
		relay.abortPending = func() {}
		relay.Close()
		t.Fatal("NewTCP accepted a nil AbortPending callback")
	}
}

func TestTCPCloseAbortsPendingCreateConn(t *testing.T) {
	started := make(chan struct{})
	aborted := make(chan struct{})
	var abortCalls atomic.Int32

	relay, err := NewTCP(fakeSource{}, TCPConfig{
		Workers:          1,
		ConnectTimeout:   time.Second,
		IdleTimeout:      time.Second,
		RelayBufferBytes: 1024,
		AllowDestination: allowAllTestDestinations,
		AbortPending: func() {
			abortCalls.Add(1)
			close(aborted)
		},
	})
	if err != nil {
		t.Fatalf("NewTCP: %v", err)
	}

	req := &fakeRequest{
		id: validTCPID(),
		createConn: func() (net.Conn, bool) {
			close(started)
			<-aborted
			return nil, false
		},
	}
	handleDone := make(chan struct{})
	go func() {
		relay.handle(req)
		close(handleDone)
	}()
	waitSignal(t, started, "endpoint creation")

	closeDone := make(chan struct{})
	go func() {
		relay.Close()
		close(closeDone)
	}()
	waitSignal(t, closeDone, "TCP close")
	waitSignal(t, handleDone, "request handler")

	relay.Close()
	req.assertCompletion(t, true)
	if req.creates != 1 {
		t.Fatalf("CreateConn calls = %d, want 1", req.creates)
	}
	if calls := abortCalls.Load(); calls != 1 {
		t.Fatalf("AbortPending calls = %d, want 1", calls)
	}
}

func TestTCPBoundedAdmissionAndCancellationCleanup(t *testing.T) {
	started := make(chan struct{})
	edge := &fakeEdge{
		id: "blocked",
		dialTCP: func(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	relay := newTestTCP(t, fakeSource{edges: []egress.Edge{edge}})

	firstRelay, firstPeer := net.Pipe()
	defer firstPeer.Close()
	firstObserved := observeClose(firstRelay)
	first := &fakeRequest{id: validTCPID(), createOK: true, conn: firstObserved}
	relay.handle(first)
	first.assertCompletion(t, false)
	waitSignal(t, started, "first dial")

	second := &fakeRequest{id: validTCPID(), createOK: true}
	relay.handle(second)
	second.assertCompletion(t, true)
	if second.creates != 0 {
		t.Fatalf("over-capacity CreateConn calls = %d, want 0", second.creates)
	}
	snapshot := relay.Snapshot()
	if snapshot.Admissions != 1 || snapshot.Active != 1 || snapshot.Wins != 0 || snapshot.Failures != 0 {
		t.Fatalf("active snapshot = %+v, want one admitted active race", snapshot)
	}

	relay.Close()
	waitSignal(t, firstObserved.closed, "ingress close")
	snapshot = relay.Snapshot()
	if snapshot.Admissions != 1 || snapshot.Active != 0 {
		t.Fatalf("closed snapshot = %+v, want one admission and no active work", snapshot)
	}
	if edge.dials.Load() != 1 {
		t.Fatalf("DialTCP calls = %d, want 1", edge.dials.Load())
	}
}

func TestTCPRaceSelectsOneWinnerAndClosesEveryLoser(t *testing.T) {
	started := make(chan struct{}, 3)
	release := make(chan struct{})
	connections := make([]*observedConn, 3)
	peers := make([]net.Conn, 3)
	edges := make([]egress.Edge, 3)
	for i := range edges {
		relaySide, peer := net.Pipe()
		connections[i] = observeClose(relaySide)
		peers[i] = peer
		conn := connections[i]
		edges[i] = &fakeEdge{
			id: model.EdgeID("edge" + string(rune('0'+i))),
			dialTCP: func(context.Context, netip.AddrPort) (net.Conn, error) {
				started <- struct{}{}
				<-release
				return conn, nil
			},
		}
	}
	defer func() {
		for _, peer := range peers {
			peer.Close()
		}
	}()

	relay := newTestTCP(t, fakeSource{edges: edges})
	defer relay.Close()

	result := make(chan net.Conn, 1)
	go func() {
		result <- relay.race(netip.MustParseAddrPort("192.0.2.20:443"))
	}()
	for range edges {
		waitSignal(t, started, "race attempt")
	}
	close(release)

	var winner net.Conn
	select {
	case winner = <-result:
	case <-time.After(time.Second):
		t.Fatal("race did not finish")
	}
	if winner == nil {
		t.Fatal("race returned no winner")
	}

	open := 0
	for _, conn := range connections {
		if !conn.isClosed() {
			open++
		}
		if conn.reads.Load() != 0 || conn.writes.Load() != 0 {
			t.Fatalf("connection carried payload during race: reads=%d writes=%d", conn.reads.Load(), conn.writes.Load())
		}
	}
	if open != 1 {
		t.Fatalf("open raced connections = %d, want exactly 1", open)
	}
	winner.Close()
}

func TestTCPWinnerObservationIsCommittedOnce(t *testing.T) {
	destination := netip.MustParseAddrPort("192.0.2.40:443")
	winnerConn, winnerPeer := net.Pipe()
	defer winnerPeer.Close()
	source := &observingTCPSource{
		fakeSource: fakeSource{edges: []egress.Edge{
			&fakeEdge{
				id: "winner",
				dialTCP: func(context.Context, netip.AddrPort) (net.Conn, error) {
					time.Sleep(time.Millisecond)
					return winnerConn, nil
				},
			},
			&fakeEdge{
				id: "loser",
				dialTCP: func(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
					<-ctx.Done()
					return nil, ctx.Err()
				},
			},
		}},
		observations: make(chan tcpObservation, 2),
	}
	relay := newTestTCP(t, source)
	defer relay.Close()

	conn := relay.race(destination)
	if conn == nil {
		t.Fatal("race returned no winner")
	}
	defer conn.Close()

	select {
	case observation := <-source.observations:
		if observation.destination != destination || observation.edgeID != "winner" {
			t.Fatalf("observation = %+v, want destination %v on winner", observation, destination)
		}
		if observation.latency <= 0 {
			t.Fatalf("winner latency = %v, want positive duration", observation.latency)
		}
	case <-time.After(time.Second):
		t.Fatal("winner was not observed")
	}
	select {
	case observation := <-source.observations:
		t.Fatalf("unexpected second winner observation: %+v", observation)
	default:
	}

	snapshot := relay.Snapshot()
	if snapshot.Wins != 1 || snapshot.Failures != 0 {
		t.Fatalf("winner snapshot = %+v, want one win and no failures", snapshot)
	}
}

func TestTCPAllFailureClosesIngress(t *testing.T) {
	edges := []egress.Edge{
		&fakeEdge{id: "a", dialTCP: failDial},
		&fakeEdge{id: "b", dialTCP: failDial},
	}
	relay := newTestTCP(t, fakeSource{edges: edges})
	defer relay.Close()

	ingressRelay, ingressPeer := net.Pipe()
	defer ingressPeer.Close()
	observed := observeClose(ingressRelay)
	req := &fakeRequest{id: validTCPID(), createOK: true, conn: observed}
	relay.handle(req)
	req.assertCompletion(t, false)
	waitSignal(t, observed.closed, "all-failure ingress close")
	snapshot := relay.Snapshot()
	if snapshot.Admissions != 1 || snapshot.Active != 0 || snapshot.Wins != 0 || snapshot.Failures != 1 {
		t.Fatalf("failure snapshot = %+v, want one admitted failed race", snapshot)
	}
}

func TestTCPRelaysBothDirections(t *testing.T) {
	ingressRelay, ingressClient := net.Pipe()
	egressRelay, egressServer := net.Pipe()
	edge := &fakeEdge{
		id: "edge",
		dialTCP: func(context.Context, netip.AddrPort) (net.Conn, error) {
			return egressRelay, nil
		},
	}
	relay := newTestTCP(t, fakeSource{edges: []egress.Edge{edge}})

	req := &fakeRequest{id: validTCPID(), createOK: true, conn: ingressRelay}
	relay.handle(req)
	req.assertCompletion(t, false)

	clientPayload := []byte("from client")
	serverPayload := []byte("from server")
	writes := make(chan error, 2)
	go func() {
		_, err := ingressClient.Write(clientPayload)
		writes <- err
	}()
	go func() {
		_, err := egressServer.Write(serverPayload)
		writes <- err
	}()

	gotAtServer := make([]byte, len(clientPayload))
	if _, err := io.ReadFull(egressServer, gotAtServer); err != nil {
		t.Fatalf("read at egress: %v", err)
	}
	gotAtClient := make([]byte, len(serverPayload))
	if _, err := io.ReadFull(ingressClient, gotAtClient); err != nil {
		t.Fatalf("read at ingress: %v", err)
	}
	if string(gotAtServer) != string(clientPayload) {
		t.Fatalf("egress payload = %q, want %q", gotAtServer, clientPayload)
	}
	if string(gotAtClient) != string(serverPayload) {
		t.Fatalf("ingress payload = %q, want %q", gotAtClient, serverPayload)
	}
	for range 2 {
		if err := <-writes; err != nil {
			t.Fatalf("relay peer write: %v", err)
		}
	}

	ingressClient.Close()
	egressServer.Close()
	relay.Close()
}

func TestTCPInitialIdleDeadlineClosesFlowAndReleasesWorker(t *testing.T) {
	const idleTimeout = time.Minute
	base := time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC)
	firstIngress := newDeadlineTestConn()
	firstEgress := newDeadlineTestConn()
	secondIngress := newDeadlineTestConn()
	secondEgress := newDeadlineTestConn()
	secondDialed := make(chan struct{})
	var dials atomic.Int32
	edge := &fakeEdge{
		id: "edge",
		dialTCP: func(context.Context, netip.AddrPort) (net.Conn, error) {
			switch dials.Add(1) {
			case 1:
				return firstEgress, nil
			case 2:
				close(secondDialed)
				return secondEgress, nil
			default:
				return nil, errors.New("unexpected extra dial")
			}
		},
	}
	relay, err := NewTCP(fakeSource{edges: []egress.Edge{edge}}, TCPConfig{
		Workers:          1,
		QueueDepth:       1,
		ConnectTimeout:   time.Second,
		IdleTimeout:      idleTimeout,
		RelayBufferBytes: 1024,
		AllowDestination: allowAllTestDestinations,
		AbortPending:     func() {},
	})
	if err != nil {
		t.Fatalf("NewTCP: %v", err)
	}
	defer relay.Close()

	now := make(chan time.Time, 2)
	now <- base
	now <- base.Add(time.Hour)
	relay.now = func() time.Time { return <-now }

	firstRequest := &fakeRequest{id: validTCPID(), createOK: true, conn: firstIngress}
	relay.handle(firstRequest)
	firstRequest.assertCompletion(t, false)
	firstDeadline := base.Add(idleTimeout)
	assertDeadlinePair(t, firstIngress, firstEgress, firstDeadline)

	secondRequest := &fakeRequest{id: validTCPID(), createOK: true, conn: secondIngress}
	relay.handle(secondRequest)
	secondRequest.assertCompletion(t, false)

	firstEgress.advance <- firstDeadline
	waitSignal(t, firstIngress.closed, "idle ingress close")
	waitSignal(t, firstEgress.closed, "idle egress close")
	waitSignal(t, secondDialed, "worker to process queued flow after idle expiry")
	if admitted := len(relay.admissions); admitted != 1 {
		t.Fatalf("admission slots in use after worker advanced = %d, want 1", admitted)
	}

	secondDeadline := base.Add(time.Hour + idleTimeout)
	assertDeadlinePair(t, secondIngress, secondEgress, secondDeadline)
	secondEgress.advance <- secondDeadline
	waitSignal(t, secondIngress.closed, "queued ingress idle close")
	waitSignal(t, secondEgress.closed, "queued egress idle close")
}

func TestTCPActivityExtendsSharedBidirectionalDeadline(t *testing.T) {
	relay := newTestTCP(t, fakeSource{})
	defer relay.Close()

	base := time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC)
	now := make(chan time.Time, 3)
	now <- base
	now <- base.Add(100 * time.Millisecond)
	now <- base.Add(200 * time.Millisecond)
	relay.now = func() time.Time { return <-now }

	ingress := newDeadlineTestConn()
	egress := newDeadlineTestConn()
	ingress.reads <- deadlineTestRead{payload: []byte("activity")}
	done := make(chan struct{})
	go func() {
		relay.relay(ingress, egress)
		close(done)
	}()

	initialDeadline := base.Add(time.Second)
	readDeadline := base.Add(1100 * time.Millisecond)
	writeDeadline := base.Add(1200 * time.Millisecond)
	for _, deadline := range []time.Time{initialDeadline, readDeadline, writeDeadline} {
		assertDeadlinePair(t, ingress, egress, deadline)
	}
	if payload := string(waitWrite(t, egress)); payload != "activity" {
		t.Fatalf("egress payload = %q, want activity", payload)
	}

	egress.advance <- initialDeadline
	waitDeadlineCheck(t, egress, initialDeadline)
	if ingress.isClosed() || egress.isClosed() {
		t.Fatal("flow closed at the original deadline despite one-direction activity")
	}

	egress.advance <- writeDeadline
	waitSignal(t, done, "extended idle deadline expiry")
	waitSignal(t, ingress.closed, "extended-deadline ingress close")
	waitSignal(t, egress.closed, "extended-deadline egress close")
}

func TestFlowKeyFromTCPIDPreservesFullTuple(t *testing.T) {
	id := stack.TransportEndpointID{
		LocalPort:     8443,
		LocalAddress:  tcpip.AddrFromSlice(netip.MustParseAddr("2001:db8::1").AsSlice()),
		RemotePort:    40123,
		RemoteAddress: tcpip.AddrFromSlice(netip.MustParseAddr("2001:db8::2").AsSlice()),
	}
	key, err := flowKeyFromID(id)
	if err != nil {
		t.Fatalf("flowKeyFromID: %v", err)
	}
	if key.IPVersion != model.IPv6 ||
		key.Protocol != model.ProtocolTCP ||
		key.SourceAddr != netip.MustParseAddr("2001:db8::2") ||
		key.SourcePort != 40123 ||
		key.DestinationAddr != netip.MustParseAddr("2001:db8::1") ||
		key.DestinationPort != 8443 {
		t.Fatalf("flow key = %#v, want literal IPv6 TCP tuple", key)
	}
}

func newTestTCP(t *testing.T, source egress.Source) *TCP {
	t.Helper()
	relay, err := NewTCP(source, TCPConfig{
		Workers:          1,
		QueueDepth:       0,
		ConnectTimeout:   time.Second,
		IdleTimeout:      time.Second,
		RelayBufferBytes: 1024,
		AllowDestination: allowAllTestDestinations,
		AbortPending:     func() {},
	})
	if err != nil {
		t.Fatalf("NewTCP: %v", err)
	}
	return relay
}

var allowAllTestDestinations DestinationPolicy = func(model.FlowKey) bool { return true }

func validTCPID() stack.TransportEndpointID {
	return stack.TransportEndpointID{
		LocalPort:     443,
		LocalAddress:  tcpip.AddrFrom4([4]byte{192, 0, 2, 20}),
		RemotePort:    40000,
		RemoteAddress: tcpip.AddrFrom4([4]byte{198, 51, 100, 10}),
	}
}

type fakeRequest struct {
	id         stack.TransportEndpointID
	conn       net.Conn
	createOK   bool
	createConn func() (net.Conn, bool)
	creates    int

	mu          sync.Mutex
	completions []bool
}

func (r *fakeRequest) ID() stack.TransportEndpointID {
	return r.id
}

func (r *fakeRequest) CreateConn() (net.Conn, bool) {
	r.creates++
	if r.createConn != nil {
		return r.createConn()
	}
	return r.conn, r.createOK
}

func (r *fakeRequest) Complete(reset bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.completions = append(r.completions, reset)
	if len(r.completions) > 1 {
		panic("request completed more than once")
	}
}

func (r *fakeRequest) assertCompletion(t *testing.T, reset bool) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.completions) != 1 || r.completions[0] != reset {
		t.Fatalf("completions = %v, want [%v]", r.completions, reset)
	}
}

type fakeSource struct {
	edges []egress.Edge
}

func (s fakeSource) Healthy() []egress.Edge {
	return s.edges
}

func (fakeSource) SelectUDP(model.FlowKey) (egress.Edge, error) {
	return nil, errors.New("not used")
}

type tcpObservation struct {
	destination netip.AddrPort
	edgeID      model.EdgeID
	latency     time.Duration
}

type observingTCPSource struct {
	fakeSource
	observations chan tcpObservation
}

func (source *observingTCPSource) ObserveTCP(
	destination netip.AddrPort,
	edgeID model.EdgeID,
	latency time.Duration,
) {
	source.observations <- tcpObservation{
		destination: destination,
		edgeID:      edgeID,
		latency:     latency,
	}
}

type fakeEdge struct {
	id      model.EdgeID
	dialTCP func(context.Context, netip.AddrPort) (net.Conn, error)
	dials   atomic.Int32
}

func (e *fakeEdge) ID() model.EdgeID {
	return e.id
}

func (e *fakeEdge) DialTCP(ctx context.Context, destination netip.AddrPort) (net.Conn, error) {
	e.dials.Add(1)
	return e.dialTCP(ctx, destination)
}

func (*fakeEdge) DialUDP(context.Context, netip.AddrPort) (net.Conn, error) {
	return nil, errors.New("not used")
}

func (*fakeEdge) Close() error {
	return nil
}

func failDial(context.Context, netip.AddrPort) (net.Conn, error) {
	return nil, errors.New("dial failed")
}

type deadlineTestRead struct {
	payload []byte
	err     error
}

type deadlineTestConn struct {
	reads          chan deadlineTestRead
	writes         chan []byte
	advance        chan time.Time
	deadlineChecks chan time.Time
	deadlines      chan time.Time
	closed         chan struct{}
	closeOnce      sync.Once

	mu       sync.Mutex
	deadline time.Time
}

func newDeadlineTestConn() *deadlineTestConn {
	return &deadlineTestConn{
		reads:          make(chan deadlineTestRead, 1),
		writes:         make(chan []byte, 1),
		advance:        make(chan time.Time, 1),
		deadlineChecks: make(chan time.Time, 1),
		deadlines:      make(chan time.Time, 8),
		closed:         make(chan struct{}),
	}
}

func (c *deadlineTestConn) Read(buffer []byte) (int, error) {
	for {
		select {
		case result := <-c.reads:
			return copy(buffer, result.payload), result.err
		case now := <-c.advance:
			c.mu.Lock()
			deadline := c.deadline
			c.mu.Unlock()
			if !deadline.IsZero() && !now.Before(deadline) {
				return 0, os.ErrDeadlineExceeded
			}
			c.deadlineChecks <- now
		case <-c.closed:
			return 0, net.ErrClosed
		}
	}
}

func (c *deadlineTestConn) Write(buffer []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	payload := append([]byte(nil), buffer...)
	c.writes <- payload
	return len(buffer), nil
}

func (c *deadlineTestConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
	})
	return nil
}

func (*deadlineTestConn) LocalAddr() net.Addr {
	return deadlineTestAddr("local")
}

func (*deadlineTestConn) RemoteAddr() net.Addr {
	return deadlineTestAddr("remote")
}

func (c *deadlineTestConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadline = deadline
	c.mu.Unlock()
	c.deadlines <- deadline
	return nil
}

func (*deadlineTestConn) SetReadDeadline(time.Time) error {
	return nil
}

func (*deadlineTestConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (c *deadlineTestConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

type deadlineTestAddr string

func (deadlineTestAddr) Network() string {
	return "test"
}

func (a deadlineTestAddr) String() string {
	return string(a)
}

func assertDeadlinePair(
	t *testing.T,
	left *deadlineTestConn,
	right *deadlineTestConn,
	want time.Time,
) {
	t.Helper()
	leftDeadline := waitDeadline(t, left)
	rightDeadline := waitDeadline(t, right)
	if !leftDeadline.Equal(want) || !rightDeadline.Equal(want) {
		t.Fatalf(
			"shared deadlines = (%v, %v), want (%v, %v)",
			leftDeadline,
			rightDeadline,
			want,
			want,
		)
	}
}

func waitDeadline(t *testing.T, conn *deadlineTestConn) time.Time {
	t.Helper()
	select {
	case deadline := <-conn.deadlines:
		return deadline
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for connection deadline")
		return time.Time{}
	}
}

func waitDeadlineCheck(t *testing.T, conn *deadlineTestConn, want time.Time) {
	t.Helper()
	select {
	case checked := <-conn.deadlineChecks:
		if !checked.Equal(want) {
			t.Fatalf("checked time = %v, want %v", checked, want)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for pre-deadline check")
	}
}

func waitWrite(t *testing.T, conn *deadlineTestConn) []byte {
	t.Helper()
	select {
	case payload := <-conn.writes:
		return payload
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for relayed write")
		return nil
	}
}

type observedConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
	reads  atomic.Int32
	writes atomic.Int32
}

func observeClose(conn net.Conn) *observedConn {
	return &observedConn{Conn: conn, closed: make(chan struct{})}
}

func (c *observedConn) Read(buffer []byte) (int, error) {
	c.reads.Add(1)
	return c.Conn.Read(buffer)
}

func (c *observedConn) Write(buffer []byte) (int, error) {
	c.writes.Add(1)
	return c.Conn.Write(buffer)
}

func (c *observedConn) Close() error {
	c.once.Do(func() {
		close(c.closed)
	})
	return c.Conn.Close()
}

func (c *observedConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func waitSignal(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}
