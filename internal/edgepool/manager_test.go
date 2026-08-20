package edgepool

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/config"
	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/egress"
	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/model"
)

type fakeEdge struct {
	id model.EdgeID

	mu             sync.Mutex
	dialTCP        func(context.Context, netip.AddrPort) (net.Conn, error)
	lastTCPAddress netip.AddrPort
	closeCount     int
}

func (edge *fakeEdge) ID() model.EdgeID {
	return edge.id
}

func (edge *fakeEdge) DialTCP(ctx context.Context, address netip.AddrPort) (net.Conn, error) {
	edge.mu.Lock()
	edge.lastTCPAddress = address
	dial := edge.dialTCP
	edge.mu.Unlock()
	if dial == nil {
		return nil, errors.New("fake TCP failure")
	}
	return dial(ctx, address)
}

func (edge *fakeEdge) DialUDP(context.Context, netip.AddrPort) (net.Conn, error) {
	return nil, errors.New("not used")
}

func (edge *fakeEdge) Close() error {
	edge.mu.Lock()
	edge.closeCount++
	edge.mu.Unlock()
	return nil
}

func TestManagerStateTransitionsAndClose(t *testing.T) {
	manager, edges := newFakeManager(t, nil)
	if snapshot := manager.Snapshot(); snapshot.Healthy != 0 || snapshot.Edges[0].State != model.EdgeStateStarting {
		t.Fatalf("initial snapshot = %+v, want all edges starting", snapshot)
	}

	entry := manager.edges[0]
	manager.recordProbe(entry, 0, false)
	manager.recordProbe(entry, 0, false)
	if state := manager.Snapshot().Edges[0].State; state != model.EdgeStateStarting {
		t.Fatalf("state after two initial failures = %s, want starting", state)
	}
	manager.recordProbe(entry, 0, false)
	if state := manager.Snapshot().Edges[0].State; state != model.EdgeStateUnhealthy {
		t.Fatalf("state after failure threshold = %s, want unhealthy", state)
	}
	manager.recordProbe(entry, 7*time.Millisecond, true)
	if snapshot := manager.Snapshot().Edges[0]; snapshot.State != model.EdgeStateHealthy || snapshot.ProbeRTT != 7*time.Millisecond || snapshot.ConsecutiveFailures != 0 {
		t.Fatalf("snapshot after success = %+v, want healthy with reset failures", snapshot)
	}
	manager.recordProbe(entry, 0, false)
	manager.recordProbe(entry, 0, false)
	if state := manager.Snapshot().Edges[0].State; state != model.EdgeStateHealthy {
		t.Fatalf("state before consecutive failure threshold = %s, want healthy", state)
	}
	manager.recordProbe(entry, 0, false)
	if state := manager.Snapshot().Edges[0].State; state != model.EdgeStateUnhealthy {
		t.Fatalf("state after consecutive failure threshold = %s, want unhealthy", state)
	}

	if err := manager.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	for index, snapshot := range manager.Snapshot().Edges {
		if snapshot.State != model.EdgeStateStopped {
			t.Errorf("edge %d state after Close = %s, want stopped", index, snapshot.State)
		}
	}
	for _, edge := range edges {
		edge.mu.Lock()
		closeCount := edge.closeCount
		edge.mu.Unlock()
		if closeCount != 1 {
			t.Errorf("edge %q close count = %d, want 1", edge.id, closeCount)
		}
	}
}

func TestManagerStartProbesImmediately(t *testing.T) {
	attempted := make(chan netip.AddrPort, 1)
	manager, _ := newFakeManager(t, func(edge *fakeEdge, index int) {
		if index != 0 {
			return
		}
		edge.dialTCP = func(ctx context.Context, address netip.AddrPort) (net.Conn, error) {
			attempted <- address
			left, right := net.Pipe()
			_ = right.Close()
			return left, nil
		}
	})
	t.Cleanup(func() { _ = manager.Close() })

	manager.Start(context.Background())
	select {
	case address := <-attempted:
		if want := netip.MustParseAddrPort("192.0.2.10:443"); address != want {
			t.Fatalf("probe address = %s, want %s", address, want)
		}
	case <-time.After(time.Second):
		t.Fatal("immediate health probe did not start")
	}
	waitForEdgeState(t, manager, 0, model.EdgeStateHealthy)
}

func TestSelectUDPPrioritizesExactRecentTCPWinner(t *testing.T) {
	manager, edges := newFakeManager(t, nil)
	t.Cleanup(func() { _ = manager.Close() })
	setHealthy(manager, 2*time.Millisecond, 8*time.Millisecond, 12*time.Millisecond)

	key := udpKey("10.0.0.2:2000", "203.0.113.8:443")
	manager.ObserveTCP(netip.MustParseAddrPort("203.0.113.8:443"), edges[2].id, 20*time.Millisecond)
	selected, err := manager.SelectUDP(key)
	if err != nil {
		t.Fatalf("SelectUDP exact observation: %v", err)
	}
	if selected.ID() != edges[2].id {
		t.Fatalf("exact observation selected %q, want %q", selected.ID(), edges[2].id)
	}

	otherPort := udpKey("10.0.0.2:2000", "203.0.113.8:53")
	selected, err = manager.SelectUDP(otherPort)
	if err != nil {
		t.Fatalf("SelectUDP different destination port: %v", err)
	}
	if selected.ID() != edges[0].id {
		t.Fatalf("different destination port selected %q, want RTT fallback %q", selected.ID(), edges[0].id)
	}

	for range unhealthyFailureThreshold {
		manager.recordProbe(manager.edges[2], 0, false)
	}
	selected, err = manager.SelectUDP(key)
	if err != nil {
		t.Fatalf("SelectUDP unhealthy observed winner: %v", err)
	}
	if selected.ID() != edges[0].id {
		t.Fatalf("unhealthy observed winner selected %q, want healthy fallback %q", selected.ID(), edges[0].id)
	}
}

func TestSelectUDPGeoFallbackThenRTTFallback(t *testing.T) {
	locationAvailable := true
	manager, edges := newFakeManager(t, nil)
	manager.locate = func(address netip.Addr) (model.GeoPoint, bool) {
		if address != netip.MustParseAddr("198.51.100.4") || !locationAvailable {
			return model.GeoPoint{}, false
		}
		return model.GeoPoint{Latitude: 48.8566, Longitude: 2.3522}, true
	}
	t.Cleanup(func() { _ = manager.Close() })
	setHealthy(manager, time.Millisecond, 15*time.Millisecond, 20*time.Millisecond)

	key := udpKey("10.0.0.2:3000", "198.51.100.4:53")
	selected, err := manager.SelectUDP(key)
	if err != nil {
		t.Fatalf("SelectUDP with Geo: %v", err)
	}
	if selected.ID() != edges[1].id {
		t.Fatalf("Geo selection = %q, want nearby edge %q", selected.ID(), edges[1].id)
	}

	locationAvailable = false
	selected, err = manager.SelectUDP(key)
	if err != nil {
		t.Fatalf("SelectUDP without Geo: %v", err)
	}
	if selected.ID() != edges[0].id {
		t.Fatalf("RTT fallback = %q, want %q", selected.ID(), edges[0].id)
	}
}

func TestSelectUDPDeterministicFullKeyRendezvous(t *testing.T) {
	first, _ := newFakeManager(t, nil)
	second, _ := newFakeManager(t, nil)
	t.Cleanup(func() { _ = first.Close() })
	t.Cleanup(func() { _ = second.Close() })
	setHealthy(first, 5*time.Millisecond, 5*time.Millisecond, 5*time.Millisecond)
	setHealthy(second, 5*time.Millisecond, 5*time.Millisecond, 5*time.Millisecond)

	base := udpKey("10.0.0.2:1000", "203.0.113.9:443")
	baseEdge, err := first.SelectUDP(base)
	if err != nil {
		t.Fatalf("SelectUDP base: %v", err)
	}
	for range 10 {
		selected, selectErr := first.SelectUDP(base)
		if selectErr != nil || selected.ID() != baseEdge.ID() {
			t.Fatalf("repeated selection = %v, %v; want %q", selected, selectErr, baseEdge.ID())
		}
	}
	selected, err := second.SelectUDP(base)
	if err != nil || selected.ID() != baseEdge.ID() {
		t.Fatalf("selection in equivalent manager = %v, %v; want %q", selected, err, baseEdge.ID())
	}

	foundDifferent := false
	for port := uint16(1001); port != 0; port++ {
		candidate := base
		candidate.SourcePort = port
		selected, selectErr := first.SelectUDP(candidate)
		if selectErr != nil {
			t.Fatalf("SelectUDP source port %d: %v", port, selectErr)
		}
		if selected.ID() != baseEdge.ID() {
			foundDifferent = true
			break
		}
	}
	if !foundDifferent {
		t.Fatal("changing the source port never changed rendezvous selection")
	}

	mutations := []model.FlowKey{base, base, base, base}
	mutations[0].SourceAddr = netip.MustParseAddr("10.0.0.3")
	mutations[1].SourcePort++
	mutations[2].DestinationAddr = netip.MustParseAddr("203.0.113.10")
	mutations[3].DestinationPort++
	for index, mutation := range mutations {
		if rendezvousHash(base, baseEdge.ID()) == rendezvousHash(mutation, baseEdge.ID()) {
			t.Errorf("full-key mutation %d did not alter rendezvous score", index)
		}
	}
}

func TestSelectUDPExcludesEveryUnhealthyEdge(t *testing.T) {
	manager, edges := newFakeManager(t, nil)
	t.Cleanup(func() { _ = manager.Close() })
	setHealthy(manager, time.Millisecond, 2*time.Millisecond, 3*time.Millisecond)
	for range unhealthyFailureThreshold {
		manager.recordProbe(manager.edges[0], 0, false)
	}

	key := udpKey("10.0.0.2:4000", "203.0.113.11:443")
	manager.ObserveTCP(netip.MustParseAddrPort("203.0.113.11:443"), edges[0].id, time.Millisecond)
	selected, err := manager.SelectUDP(key)
	if err != nil {
		t.Fatalf("SelectUDP: %v", err)
	}
	if selected.ID() == edges[0].id {
		t.Fatalf("selected unhealthy edge %q", selected.ID())
	}
	for _, healthy := range manager.Healthy() {
		if healthy.ID() == edges[0].id {
			t.Fatalf("Healthy returned unhealthy edge %q", healthy.ID())
		}
	}

	for index := 1; index < len(manager.edges); index++ {
		for range unhealthyFailureThreshold {
			manager.recordProbe(manager.edges[index], 0, false)
		}
	}
	if _, err := manager.SelectUDP(key); !errors.Is(err, ErrNoHealthyEdges) {
		t.Fatalf("SelectUDP with no healthy edges error = %v, want ErrNoHealthyEdges", err)
	}
}

func newFakeManager(t *testing.T, configure func(*fakeEdge, int)) (*Manager, []*fakeEdge) {
	t.Helper()
	cfg := validManagerConfig()
	edges := make([]*fakeEdge, 0, len(cfg.Edges))
	manager, err := New(cfg, nil, func(edgeConfig config.EdgeConfig, mtu int) (egress.Edge, error) {
		if mtu != cfg.MTU {
			t.Fatalf("factory MTU = %d, want %d", mtu, cfg.MTU)
		}
		edge := &fakeEdge{id: edgeConfig.ID}
		if configure != nil {
			configure(edge, len(edges))
		}
		edges = append(edges, edge)
		return edge, nil
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(edges) != len(cfg.Edges) {
		t.Fatalf("factory calls = %d, want %d", len(edges), len(cfg.Edges))
	}
	return manager, edges
}

func setHealthy(manager *Manager, latencies ...time.Duration) {
	for index, latency := range latencies {
		manager.recordProbe(manager.edges[index], latency, true)
	}
}

func waitForEdgeState(t *testing.T, manager *Manager, index int, want model.EdgeState) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if manager.Snapshot().Edges[index].State == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("edge %d state = %s, want %s", index, manager.Snapshot().Edges[index].State, want)
}

func udpKey(source, destination string) model.FlowKey {
	return model.FlowKey{
		IPVersion:       model.IPv4,
		Protocol:        model.ProtocolUDP,
		SourceAddr:      netip.MustParseAddrPort(source).Addr(),
		SourcePort:      netip.MustParseAddrPort(source).Port(),
		DestinationAddr: netip.MustParseAddrPort(destination).Addr(),
		DestinationPort: netip.MustParseAddrPort(destination).Port(),
	}
}

func validManagerConfig() config.Config {
	cfg := config.Default()
	cfg.Ingress = config.IngressConfig{
		PrivateKey:     testKey(1),
		ListenPort:     51820,
		OverlayAddress: netip.MustParsePrefix("10.0.0.1/24"),
		Peers: []config.IngressPeerConfig{{
			PublicKey:      testKey(2),
			OverlayAddress: netip.MustParseAddr("10.0.0.2"),
		}},
	}
	locations := []model.GeoPoint{
		{Latitude: 37.7749, Longitude: -122.4194},
		{Latitude: 48.8566, Longitude: 2.3522},
		{Latitude: 35.6762, Longitude: 139.6503},
	}
	for index := range 3 {
		cfg.Edges = append(cfg.Edges, config.EdgeConfig{
			ID:                 model.EdgeID("edge-" + string(rune('a'+index))),
			PrivateKey:         testKey(byte(10 + index)),
			OverlayAddress:     netip.MustParsePrefix("10.10." + string(rune('1'+index)) + ".1/24"),
			PeerPublicKey:      testKey(byte(20 + index)),
			Endpoint:           netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(index + 1)}), 51820).String(),
			HealthCheckAddress: netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(index + 10)}), 443).String(),
			AllowedIPs:         []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
			Geo: config.GeoConfig{
				CountryCode: "US",
				Latitude:    locations[index].Latitude,
				Longitude:   locations[index].Longitude,
			},
		})
	}
	cfg.Timeouts.HealthCheckInterval = config.Duration(time.Hour)
	return cfg
}

func testKey(value byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
}
