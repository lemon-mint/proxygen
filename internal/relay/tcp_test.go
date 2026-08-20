package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/egress"
	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/model"
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

func TestTCPRequiresAbortPending(t *testing.T) {
	relay, err := NewTCP(fakeSource{}, TCPConfig{
		Workers:          1,
		ConnectTimeout:   time.Second,
		RelayBufferBytes: 1024,
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
		RelayBufferBytes: 1024,
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

	relay.Close()
	waitSignal(t, firstObserved.closed, "ingress close")
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
		RelayBufferBytes: 1024,
		AbortPending:     func() {},
	})
	if err != nil {
		t.Fatalf("NewTCP: %v", err)
	}
	return relay
}

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
