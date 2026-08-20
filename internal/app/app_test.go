package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/config"
	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/edgepool"
	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/egress"
	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/model"
	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/netstack"
	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/relay"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	gvisorudp "gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

func TestRunStartsHealthAndClosesRuntimeInOrder(t *testing.T) {
	cfg := validAppConfig()
	cfg.GeoDatabase = "locations.mmdb"
	events := &eventLog{}
	geoDB := &fakeGeo{events: events}
	edges := &fakeEdges{events: events}
	tcpRelay := &fakeTCP{events: events}
	udpRelay := &fakeUDP{events: events}
	ingress := &fakeIngress{events: events}
	wireGuard := &fakeCloser{name: "wireguard", events: events}

	deps := fakeDependencies()
	deps.openGeo = func(string) (geoDatabase, error) { return geoDB, nil }
	deps.newEdgePool = func(config.Config, edgepool.LocateFunc) (edgeRuntime, error) { return edges, nil }
	deps.newTCP = func(_ egress.Source, relayConfig relay.TCPConfig) (tcpRuntime, error) {
		tcpRelay.abortPending = relayConfig.AbortPending
		return tcpRelay, nil
	}
	deps.newUDP = func(egress.Source, time.Duration, int) (udpRuntime, error) { return udpRelay, nil }
	deps.newNetstack = func(int, int, netstack.Handlers) (ingressRuntime, error) { return ingress, nil }
	deps.newWireGuard = func(config.IngressConfig, ingressRuntime) (io.Closer, error) { return wireGuard, nil }

	application, err := newApp(cfg, deps)
	if err != nil {
		t.Fatalf("newApp() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := application.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	want := []string{"health-start", "wireguard", "ingress", "tcp", "udp", "edges", "geo"}
	if got := events.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("lifecycle events = %v, want %v", got, want)
	}
}

func TestMetricsListenFailureUnwindsReverseConstructionOrder(t *testing.T) {
	cfg := validAppConfig()
	cfg.GeoDatabase = "locations.mmdb"
	cfg.MetricsListen = "127.0.0.1:9090"
	events := &eventLog{}
	tcpRelay := &fakeTCP{events: events}
	ingress := &fakeIngress{events: events}
	deps := fakeDependencies()
	deps.openGeo = func(string) (geoDatabase, error) { return &fakeGeo{events: events}, nil }
	deps.newEdgePool = func(config.Config, edgepool.LocateFunc) (edgeRuntime, error) {
		return &fakeEdges{events: events}, nil
	}
	deps.newTCP = func(_ egress.Source, relayConfig relay.TCPConfig) (tcpRuntime, error) {
		tcpRelay.abortPending = relayConfig.AbortPending
		return tcpRelay, nil
	}
	deps.newUDP = func(egress.Source, time.Duration, int) (udpRuntime, error) {
		return &fakeUDP{events: events}, nil
	}
	deps.newNetstack = func(int, int, netstack.Handlers) (ingressRuntime, error) { return ingress, nil }
	deps.newWireGuard = func(config.IngressConfig, ingressRuntime) (io.Closer, error) {
		return &fakeCloser{name: "wireguard", events: events}, nil
	}
	deps.listen = func(string, string) (net.Listener, error) {
		return nil, errors.New("address unavailable")
	}

	application, err := newApp(cfg, deps)
	if err == nil || application != nil {
		t.Fatalf("newApp() = (%v, %v), want construction error", application, err)
	}
	want := []string{"wireguard", "ingress", "udp", "tcp", "edges", "geo"}
	if got := events.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("cleanup events = %v, want %v", got, want)
	}
}

func TestHealthHandlerRequiresThreeHealthyEdges(t *testing.T) {
	for _, test := range []struct {
		name    string
		healthy int
		status  int
	}{
		{name: "degraded", healthy: 2, status: http.StatusServiceUnavailable},
		{name: "healthy", healthy: 3, status: http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshots := fakeSnapshots{edges: edgepool.Snapshot{Healthy: test.healthy}}
			request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			response := httptest.NewRecorder()
			newControlHandler(snapshots).ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
			if response.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("Content-Type = %q, want application/json", response.Header().Get("Content-Type"))
			}
		})
	}
}

func TestMetricsHandlerReturnsCurrentSnapshots(t *testing.T) {
	snapshots := fakeSnapshots{
		edges: edgepool.Snapshot{Healthy: 3},
		tcp:   relay.TCPSnapshot{Admissions: 7, Active: 2, Wins: 5, Failures: 1},
		udp:   relay.UDPSnapshot{Mappings: 4, Expired: 6, Dropped: 2},
	}
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	response := httptest.NewRecorder()
	newControlHandler(snapshots).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	var got metricsSnapshot
	if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	want := metricsSnapshot{Edges: snapshots.edges, TCP: snapshots.tcp, UDP: snapshots.udp}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("metrics = %#v, want %#v", got, want)
	}
}

type eventLog struct {
	mu     sync.Mutex
	events []string
}

func (log *eventLog) add(event string) {
	log.mu.Lock()
	defer log.mu.Unlock()
	log.events = append(log.events, event)
}

func (log *eventLog) snapshot() []string {
	log.mu.Lock()
	defer log.mu.Unlock()
	return append([]string(nil), log.events...)
}

type fakeGeo struct {
	events *eventLog
}

func (*fakeGeo) Lookup(netip.Addr) (model.GeoPoint, bool) { return model.GeoPoint{}, false }
func (database *fakeGeo) Close() error {
	database.events.add("geo")
	return nil
}

type fakeEdges struct {
	events *eventLog
}

func (*fakeEdges) Healthy() []egress.Edge                       { return nil }
func (*fakeEdges) SelectUDP(model.FlowKey) (egress.Edge, error) { return nil, errors.New("unused") }
func (edges *fakeEdges) Start(context.Context)                  { edges.events.add("health-start") }
func (edges *fakeEdges) Close() error {
	edges.events.add("edges")
	return nil
}
func (*fakeEdges) Snapshot() edgepool.Snapshot { return edgepool.Snapshot{} }

type fakeTCP struct {
	events       *eventLog
	abortPending func()
}

func (*fakeTCP) Handle(*tcp.ForwarderRequest) {}
func (*fakeTCP) Snapshot() relay.TCPSnapshot  { return relay.TCPSnapshot{} }
func (relay *fakeTCP) Close() {
	if relay.abortPending != nil {
		relay.abortPending()
	}
	relay.events.add("tcp")
}

type fakeUDP struct {
	events *eventLog
}

func (*fakeUDP) Handler(*gvisorudp.ForwarderRequest) bool { return false }
func (*fakeUDP) Snapshot() relay.UDPSnapshot              { return relay.UDPSnapshot{} }
func (relay *fakeUDP) Close() error {
	relay.events.add("udp")
	return nil
}

type fakeIngress struct {
	events *eventLog
	once   sync.Once
}

func (ingress *fakeIngress) Close() error {
	ingress.once.Do(func() { ingress.events.add("ingress") })
	return nil
}

type fakeCloser struct {
	name   string
	events *eventLog
}

func (closer *fakeCloser) Close() error {
	closer.events.add(closer.name)
	return nil
}

type fakeSnapshots struct {
	edges edgepool.Snapshot
	tcp   relay.TCPSnapshot
	udp   relay.UDPSnapshot
}

func (snapshots fakeSnapshots) edgeSnapshot() edgepool.Snapshot { return snapshots.edges }
func (snapshots fakeSnapshots) tcpSnapshot() relay.TCPSnapshot  { return snapshots.tcp }
func (snapshots fakeSnapshots) udpSnapshot() relay.UDPSnapshot  { return snapshots.udp }

func fakeDependencies() dependencies {
	return dependencies{
		openGeo: func(string) (geoDatabase, error) { return nil, errors.New("unexpected geo open") },
		newEdgePool: func(config.Config, edgepool.LocateFunc) (edgeRuntime, error) {
			return nil, errors.New("unexpected edge pool construction")
		},
		newTCP: func(egress.Source, relay.TCPConfig) (tcpRuntime, error) {
			return nil, errors.New("unexpected TCP construction")
		},
		newUDP: func(egress.Source, time.Duration, int) (udpRuntime, error) {
			return nil, errors.New("unexpected UDP construction")
		},
		newNetstack: func(int, int, netstack.Handlers) (ingressRuntime, error) {
			return nil, errors.New("unexpected netstack construction")
		},
		newWireGuard: func(config.IngressConfig, ingressRuntime) (io.Closer, error) {
			return nil, errors.New("unexpected WireGuard construction")
		},
		listen: net.Listen,
	}
}

func validAppConfig() config.Config {
	cfg := config.Default()
	cfg.Ingress = config.IngressConfig{
		PrivateKey:     appTestKey(1),
		ListenPort:     51820,
		OverlayAddress: netip.MustParsePrefix("10.0.0.1/24"),
		Peers: []config.IngressPeerConfig{
			{PublicKey: appTestKey(2), OverlayAddress: netip.MustParseAddr("10.0.0.2")},
		},
	}
	for index := range 3 {
		octet := string(rune('1' + index))
		cfg.Edges = append(cfg.Edges, config.EdgeConfig{
			ID:                  model.EdgeID("edge-" + octet),
			PrivateKey:          appTestKey(byte(10 + index)),
			OverlayAddress:      netip.MustParsePrefix("10.10." + octet + ".2/24"),
			PeerPublicKey:       appTestKey(byte(20 + index)),
			Endpoint:            "192.0.2." + octet + ":51820",
			HealthCheckAddress:  "198.51.100." + octet + ":443",
			AllowedIPs:          []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
			PersistentKeepalive: config.Duration(25 * time.Second),
			Geo: config.GeoConfig{
				CountryCode: "US",
				Latitude:    40 + float64(index),
				Longitude:   -70 - float64(index),
			},
		})
	}
	return cfg
}

func appTestKey(fill byte) string {
	key := make([]byte, 32)
	for index := range key {
		key[index] = fill
	}
	return base64.StdEncoding.EncodeToString(key)
}
