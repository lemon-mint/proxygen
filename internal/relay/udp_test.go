package relay

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/egress"
	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/model"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestUDPRejectsFlowLimitAboveMemoryBound(t *testing.T) {
	relay, err := NewUDP(newFakeUDPSource(newFakeUDPEdge()), time.Minute, model.MaxUDPFlows+1)
	if err == nil {
		_ = relay.Close()
		t.Fatal("NewUDP() accepted a flow limit above the relay memory bound")
	}
}

func TestUDPLiteralDestinationsCreateDistinctMappings(t *testing.T) {
	edge := newFakeUDPEdge()
	source := newFakeUDPSource(edge)
	relay, err := NewUDP(source, time.Minute, 4)
	if err != nil {
		t.Fatalf("NewUDP: %v", err)
	}
	defer relay.Close()

	firstKey := testUDPKey("10.0.0.8:31000", "192.0.2.10:53")
	secondKey := testUDPKey("10.0.0.8:31000", "198.51.100.20:53")
	firstIngress := newFakeDatagramConn()
	secondIngress := newFakeDatagramConn()
	if !relay.admit(firstKey, staticIngress(firstIngress)) {
		t.Fatal("first mapping was not admitted")
	}
	if !relay.admit(secondKey, staticIngress(secondIngress)) {
		t.Fatal("second mapping with a different literal destination was not admitted")
	}

	firstDial := awaitDial(t, edge.dials)
	secondDial := awaitDial(t, edge.dials)
	dials := map[netip.AddrPort]*fakeDatagramConn{
		firstDial.destination:  firstDial.conn,
		secondDial.destination: secondDial.conn,
	}
	firstEgress := dials[netip.MustParseAddrPort("192.0.2.10:53")]
	secondEgress := dials[netip.MustParseAddrPort("198.51.100.20:53")]
	if firstEgress == nil || secondEgress == nil || firstEgress == secondEgress {
		t.Fatalf("dials did not create one socket per literal destination: %#v", dials)
	}

	firstIngress.deliver([]byte("first"))
	secondIngress.deliver([]byte("second"))
	if got := awaitDatagram(t, firstEgress.writes); string(got) != "first" {
		t.Fatalf("first destination got %q, want first", got)
	}
	if got := awaitDatagram(t, secondEgress.writes); string(got) != "second" {
		t.Fatalf("second destination got %q, want second", got)
	}
	assertNoDatagram(t, firstEgress.writes)
	assertNoDatagram(t, secondEgress.writes)

	firstIngress.deliver([]byte("again"))
	if got := awaitDatagram(t, firstEgress.writes); string(got) != "again" {
		t.Fatalf("existing mapping got %q, want again", got)
	}
	if got := source.selectionCount(firstKey); got != 1 {
		t.Fatalf("first mapping selected an edge %d times, want 1", got)
	}
	if got := source.selectionCount(secondKey); got != 1 {
		t.Fatalf("second mapping selected an edge %d times, want 1", got)
	}
}

func TestUDPIdleExpiryReleasesBothSockets(t *testing.T) {
	edge := newFakeUDPEdge()
	source := newFakeUDPSource(edge)
	relay, err := NewUDP(source, 25*time.Millisecond, 1)
	if err != nil {
		t.Fatalf("NewUDP: %v", err)
	}
	defer relay.Close()

	key := testUDPKey("10.0.0.9:32000", "203.0.113.7:123")
	ingress := newFakeDatagramConn()
	if !relay.admit(key, staticIngress(ingress)) {
		t.Fatal("mapping was not admitted")
	}
	dial := awaitDial(t, edge.dials)

	awaitClosed(t, ingress.closed)
	awaitClosed(t, dial.conn.closed)
	awaitFlowCount(t, relay, 0)
	snapshot := relay.Snapshot()
	if snapshot.Mappings != 0 || snapshot.Expired != 1 || snapshot.Dropped != 0 {
		t.Fatalf("expiry snapshot = %+v, want one expiry and no active mappings or drops", snapshot)
	}
	if got := ingress.closeCount(); got != 1 {
		t.Fatalf("ingress socket closed %d times, want exactly 1", got)
	}
	if got := dial.conn.closeCount(); got != 1 {
		t.Fatalf("egress socket closed %d times, want exactly 1", got)
	}
}

func TestUDPMaxFlowAdmissionAndShutdown(t *testing.T) {
	edge := newFakeUDPEdge()
	source := newFakeUDPSource(edge)
	relay, err := NewUDP(source, time.Minute, 1)
	if err != nil {
		t.Fatalf("NewUDP: %v", err)
	}

	firstKey := testUDPKey("10.0.0.10:33000", "192.0.2.30:443")
	secondKey := testUDPKey("10.0.0.10:33000", "192.0.2.31:443")
	firstIngress := newFakeDatagramConn()
	if !relay.admit(firstKey, staticIngress(firstIngress)) {
		t.Fatal("first mapping was not admitted")
	}
	dial := awaitDial(t, edge.dials)

	factoryCalled := false
	if relay.admit(secondKey, func() (net.Conn, bool) {
		factoryCalled = true
		return newFakeDatagramConn(), true
	}) {
		t.Fatal("mapping above the capacity limit was admitted")
	}
	if factoryCalled {
		t.Fatal("rejected mapping created an ingress endpoint")
	}
	snapshot := relay.Snapshot()
	if snapshot.Mappings != 1 || snapshot.Expired != 0 || snapshot.Dropped != 1 {
		t.Fatalf("capacity snapshot = %+v, want one active mapping and one drop", snapshot)
	}

	if err := relay.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := relay.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	awaitClosed(t, firstIngress.closed)
	awaitClosed(t, dial.conn.closed)
	if got := firstIngress.closeCount(); got != 1 {
		t.Fatalf("ingress socket closed %d times, want exactly 1", got)
	}
	if got := dial.conn.closeCount(); got != 1 {
		t.Fatalf("egress socket closed %d times, want exactly 1", got)
	}
	snapshot = relay.Snapshot()
	if snapshot.Mappings != 0 || snapshot.Dropped != 1 {
		t.Fatalf("closed snapshot = %+v, want no active mappings and one drop", snapshot)
	}
	if relay.admit(secondKey, staticIngress(newFakeDatagramConn())) {
		t.Fatal("mapping was admitted after shutdown")
	}
	snapshot = relay.Snapshot()
	if snapshot.Dropped != 2 {
		t.Fatalf("post-close snapshot = %+v, want two dropped admissions", snapshot)
	}
}

func TestUDPSetupFailureDropsMapping(t *testing.T) {
	source := newFakeUDPSource(nil)
	relay, err := NewUDP(source, time.Minute, 1)
	if err != nil {
		t.Fatalf("NewUDP: %v", err)
	}
	defer relay.Close()

	key := testUDPKey("10.0.0.11:34000", "192.0.2.32:53")
	ingress := newFakeDatagramConn()
	if !relay.admit(key, staticIngress(ingress)) {
		t.Fatal("mapping was not admitted")
	}
	awaitClosed(t, ingress.closed)
	awaitFlowCount(t, relay, 0)

	snapshot := relay.Snapshot()
	if snapshot.Mappings != 0 || snapshot.Expired != 0 || snapshot.Dropped != 1 {
		t.Fatalf("setup-failure snapshot = %+v, want one dropped mapping", snapshot)
	}
}

func TestUDPKeyUsesIngressSourceAndLiteralDestination(t *testing.T) {
	id := stack.TransportEndpointID{
		LocalPort:     53,
		LocalAddress:  tcpip.AddrFrom4([4]byte{203, 0, 113, 9}),
		RemotePort:    31000,
		RemoteAddress: tcpip.AddrFrom4([4]byte{10, 0, 0, 8}),
	}
	key, ok := udpKeyFromEndpointID(id)
	if !ok {
		t.Fatal("valid endpoint ID was rejected")
	}
	want := testUDPKey("10.0.0.8:31000", "203.0.113.9:53")
	if key != want {
		t.Fatalf("key = %#v, want %#v", key, want)
	}
}

func testUDPKey(source, destination string) model.FlowKey {
	key, err := model.NewFlowKey(
		model.ProtocolUDP,
		netip.MustParseAddrPort(source),
		netip.MustParseAddrPort(destination),
	)
	if err != nil {
		panic(err)
	}
	return key
}

func staticIngress(conn net.Conn) func() (net.Conn, bool) {
	return func() (net.Conn, bool) { return conn, true }
}

type fakeUDPSource struct {
	edge egress.Edge

	mu         sync.Mutex
	selections map[model.FlowKey]int
}

func newFakeUDPSource(edge egress.Edge) *fakeUDPSource {
	return &fakeUDPSource{edge: edge, selections: make(map[model.FlowKey]int)}
}

func (source *fakeUDPSource) Healthy() []egress.Edge {
	return []egress.Edge{source.edge}
}

func (source *fakeUDPSource) SelectUDP(key model.FlowKey) (egress.Edge, error) {
	source.mu.Lock()
	source.selections[key]++
	source.mu.Unlock()
	return source.edge, nil
}

func (source *fakeUDPSource) selectionCount(key model.FlowKey) int {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.selections[key]
}

type fakeUDPEdge struct {
	dials chan fakeUDPDial
}

type fakeUDPDial struct {
	destination netip.AddrPort
	conn        *fakeDatagramConn
}

func newFakeUDPEdge() *fakeUDPEdge {
	return &fakeUDPEdge{dials: make(chan fakeUDPDial, 16)}
}

func (edge *fakeUDPEdge) ID() model.EdgeID {
	return model.EdgeID("fake")
}

func (edge *fakeUDPEdge) DialTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	return nil, errors.New("unexpected TCP dial")
}

func (edge *fakeUDPEdge) DialUDP(ctx context.Context, destination netip.AddrPort) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn := newFakeDatagramConn()
	select {
	case edge.dials <- fakeUDPDial{destination: destination, conn: conn}:
		return conn, nil
	case <-ctx.Done():
		_ = conn.Close()
		return nil, ctx.Err()
	}
}

func (edge *fakeUDPEdge) Close() error {
	return nil
}

type fakeDatagramConn struct {
	reads  chan []byte
	writes chan []byte
	closed chan struct{}

	closeOnce sync.Once
	mu        sync.Mutex
	closes    int
}

func newFakeDatagramConn() *fakeDatagramConn {
	return &fakeDatagramConn{
		reads:  make(chan []byte, 16),
		writes: make(chan []byte, 16),
		closed: make(chan struct{}),
	}
}

func (conn *fakeDatagramConn) deliver(datagram []byte) {
	copyOfDatagram := append([]byte(nil), datagram...)
	select {
	case conn.reads <- copyOfDatagram:
	case <-conn.closed:
	}
}

func (conn *fakeDatagramConn) Read(buffer []byte) (int, error) {
	select {
	case datagram := <-conn.reads:
		return copy(buffer, datagram), nil
	case <-conn.closed:
		return 0, net.ErrClosed
	}
}

func (conn *fakeDatagramConn) Write(datagram []byte) (int, error) {
	copyOfDatagram := append([]byte(nil), datagram...)
	select {
	case conn.writes <- copyOfDatagram:
		return len(datagram), nil
	case <-conn.closed:
		return 0, net.ErrClosed
	}
}

func (conn *fakeDatagramConn) Close() error {
	conn.closeOnce.Do(func() {
		conn.mu.Lock()
		conn.closes++
		conn.mu.Unlock()
		close(conn.closed)
	})
	return nil
}

func (conn *fakeDatagramConn) closeCount() int {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.closes
}

func (conn *fakeDatagramConn) LocalAddr() net.Addr              { return fakeAddr("local") }
func (conn *fakeDatagramConn) RemoteAddr() net.Addr             { return fakeAddr("remote") }
func (conn *fakeDatagramConn) SetDeadline(time.Time) error      { return nil }
func (conn *fakeDatagramConn) SetReadDeadline(time.Time) error  { return nil }
func (conn *fakeDatagramConn) SetWriteDeadline(time.Time) error { return nil }

type fakeAddr string

func (address fakeAddr) Network() string { return "fake-datagram" }
func (address fakeAddr) String() string  { return string(address) }

func awaitDial(t *testing.T, dials <-chan fakeUDPDial) fakeUDPDial {
	t.Helper()
	select {
	case dial := <-dials:
		return dial
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for UDP dial")
		return fakeUDPDial{}
	}
}

func awaitDatagram(t *testing.T, datagrams <-chan []byte) []byte {
	t.Helper()
	select {
	case datagram := <-datagrams:
		return datagram
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for relayed datagram")
		return nil
	}
}

func assertNoDatagram(t *testing.T, datagrams <-chan []byte) {
	t.Helper()
	select {
	case datagram := <-datagrams:
		t.Fatalf("unexpected duplicate datagram %q", datagram)
	case <-time.After(20 * time.Millisecond):
	}
}

func awaitClosed(t *testing.T, closed <-chan struct{}) {
	t.Helper()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for socket close")
	}
}

func awaitFlowCount(t *testing.T, relay *UDP, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		relay.mu.Lock()
		got := len(relay.flows)
		relay.mu.Unlock()
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("flow count is %d, want %d", got, want)
		}
		time.Sleep(time.Millisecond)
	}
}
