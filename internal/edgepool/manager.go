// Package edgepool owns egress edges, monitors their health, and selects an
// eligible edge for each new flow.
package edgepool

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sync"
	"time"

	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/config"
	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/egress"
	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/model"
)

const (
	unhealthyFailureThreshold = 3
	tcpObservationTTL         = 5 * time.Minute
	maxTCPObservations        = 4096
	fiberKilometersPerSecond  = 200_000
)

// ErrNoHealthyEdges is returned when no edge is currently eligible for a new
// flow.
var ErrNoHealthyEdges = errors.New("no healthy egress edges")

// LocateFunc returns geographic coordinates for an IP address. A false result
// disables geographic selection for that destination.
type LocateFunc func(netip.Addr) (model.GeoPoint, bool)

// Factory constructs one independently owned egress edge.
type Factory func(config.EdgeConfig, int) (egress.Edge, error)

// Snapshot is a point-in-time view of edge health.
type Snapshot struct {
	Edges   []EdgeSnapshot `json:"edges"`
	Healthy int            `json:"healthy"`
}

// EdgeSnapshot is the observable health state of one configured edge.
type EdgeSnapshot struct {
	ID                  model.EdgeID    `json:"id"`
	State               model.EdgeState `json:"state"`
	ProbeRTT            time.Duration   `json:"probe_rtt"`
	ConsecutiveFailures uint32          `json:"consecutive_failures"`
}

type managedEdge struct {
	id          model.EdgeID
	edge        egress.Edge
	healthCheck netip.AddrPort
	location    model.GeoPoint

	state               model.EdgeState
	probeRTT            time.Duration
	consecutiveFailures uint32
}

type tcpObservation struct {
	edgeID     model.EdgeID
	observedAt time.Time
	sequence   uint64
}

type observationSlot struct {
	destination netip.AddrPort
	sequence    uint64
}

// Manager owns all configured egress edges and their health state.
type Manager struct {
	mu       sync.RWMutex
	edges    []*managedEdge
	byID     map[model.EdgeID]*managedEdge
	locate   LocateFunc
	interval time.Duration
	timeout  time.Duration
	now      func() time.Time

	observations    map[netip.AddrPort]tcpObservation
	observationRing []observationSlot
	nextObservation int
	sequence        uint64

	startOnce sync.Once
	closeOnce sync.Once
	cancel    context.CancelFunc
	closed    bool
	wg        sync.WaitGroup
	closeErr  error
}

var (
	_ egress.Source      = (*Manager)(nil)
	_ egress.TCPObserver = (*Manager)(nil)
)

// New validates cfg and constructs exactly one egress edge for every configured
// edge. If construction fails, every edge already created is closed.
func New(cfg config.Config, locate LocateFunc, factory Factory) (*Manager, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid edge pool configuration: %w", err)
	}
	if factory == nil {
		factory = func(edgeConfig config.EdgeConfig, mtu int) (egress.Edge, error) {
			return egress.NewBundle(edgeConfig, mtu)
		}
	}

	manager := &Manager{
		edges:           make([]*managedEdge, 0, len(cfg.Edges)),
		byID:            make(map[model.EdgeID]*managedEdge, len(cfg.Edges)),
		locate:          locate,
		interval:        cfg.Timeouts.HealthCheckInterval.Std(),
		timeout:         cfg.Timeouts.TCPConnect.Std(),
		now:             time.Now,
		observations:    make(map[netip.AddrPort]tcpObservation, maxTCPObservations),
		observationRing: make([]observationSlot, maxTCPObservations),
	}
	if manager.timeout > manager.interval {
		manager.timeout = manager.interval
	}

	for index, edgeConfig := range cfg.Edges {
		healthCheck, err := netip.ParseAddrPort(edgeConfig.HealthCheckAddress)
		if err != nil {
			manager.closeConstructed()
			return nil, fmt.Errorf("parse edges[%d].health_check_address: %w", index, err)
		}
		edge, err := factory(edgeConfig, cfg.MTU)
		if err != nil {
			cleanupErr := manager.closeConstructed()
			return nil, errors.Join(
				fmt.Errorf("create egress edge %q: %w", edgeConfig.ID, err),
				cleanupErr,
			)
		}
		if edge == nil {
			cleanupErr := manager.closeConstructed()
			return nil, errors.Join(
				fmt.Errorf("create egress edge %q: factory returned nil edge", edgeConfig.ID),
				cleanupErr,
			)
		}
		if edge.ID() != edgeConfig.ID {
			closeErr := edge.Close()
			cleanupErr := manager.closeConstructed()
			return nil, errors.Join(
				fmt.Errorf("create egress edge %q: factory returned edge ID %q", edgeConfig.ID, edge.ID()),
				closeErr,
				cleanupErr,
			)
		}

		entry := &managedEdge{
			id:          edgeConfig.ID,
			edge:        edge,
			healthCheck: netip.AddrPortFrom(healthCheck.Addr().Unmap(), healthCheck.Port()),
			location: model.GeoPoint{
				Latitude:  edgeConfig.Geo.Latitude,
				Longitude: edgeConfig.Geo.Longitude,
			},
			state: model.EdgeStateStarting,
		}
		manager.edges = append(manager.edges, entry)
		manager.byID[edgeConfig.ID] = entry
	}
	return manager, nil
}

// Start begins an immediate health probe for every edge, followed by probes at
// the configured interval. It is safe to call Start more than once.
func (manager *Manager) Start(ctx context.Context) {
	manager.startOnce.Do(func() {
		if ctx == nil {
			ctx = context.Background()
		}

		manager.mu.Lock()
		defer manager.mu.Unlock()
		if manager.closed {
			return
		}
		runContext, cancel := context.WithCancel(ctx)
		manager.cancel = cancel
		for _, entry := range manager.edges {
			manager.wg.Add(1)
			go manager.monitor(runContext, entry)
		}
	})
}

func (manager *Manager) monitor(ctx context.Context, entry *managedEdge) {
	defer manager.wg.Done()
	if !manager.probe(ctx, entry) {
		return
	}

	ticker := time.NewTicker(manager.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !manager.probe(ctx, entry) {
				return
			}
		}
	}
}

func (manager *Manager) probe(ctx context.Context, entry *managedEdge) bool {
	probeContext, cancel := context.WithTimeout(ctx, manager.timeout)
	started := manager.now()
	connection, err := entry.edge.DialTCP(probeContext, entry.healthCheck)
	latency := manager.now().Sub(started)
	cancel()
	if connection != nil {
		_ = connection.Close()
	}
	if ctx.Err() != nil {
		return false
	}
	manager.recordProbe(entry, latency, err == nil && connection != nil)
	return true
}

func (manager *Manager) recordProbe(entry *managedEdge, latency time.Duration, succeeded bool) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.closed {
		return
	}
	if succeeded {
		entry.state = model.EdgeStateHealthy
		entry.probeRTT = latency
		entry.consecutiveFailures = 0
		return
	}
	if entry.consecutiveFailures < math.MaxUint32 {
		entry.consecutiveFailures++
	}
	if entry.consecutiveFailures >= unhealthyFailureThreshold {
		entry.state = model.EdgeStateUnhealthy
	}
}

// Healthy returns all currently healthy edges in configuration order.
func (manager *Manager) Healthy() []egress.Edge {
	manager.mu.RLock()
	defer manager.mu.RUnlock()

	edges := make([]egress.Edge, 0, len(manager.edges))
	for _, entry := range manager.edges {
		if entry.state == model.EdgeStateHealthy {
			edges = append(edges, entry.edge)
		}
	}
	return edges
}

// ObserveTCP records the committed TCP race winner for an exact destination.
func (manager *Manager) ObserveTCP(destination netip.AddrPort, edgeID model.EdgeID, latency time.Duration) {
	if !destination.IsValid() || destination.Port() == 0 || latency < 0 {
		return
	}
	destination = netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())

	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.closed || manager.byID[edgeID] == nil {
		return
	}

	manager.sequence++
	if manager.sequence == 0 {
		manager.sequence++
	}
	slot := &manager.observationRing[manager.nextObservation]
	if previous, exists := manager.observations[slot.destination]; exists && previous.sequence == slot.sequence {
		delete(manager.observations, slot.destination)
	}
	observation := tcpObservation{
		edgeID:     edgeID,
		observedAt: manager.now(),
		sequence:   manager.sequence,
	}
	manager.observations[destination] = observation
	*slot = observationSlot{destination: destination, sequence: observation.sequence}
	manager.nextObservation++
	if manager.nextObservation == len(manager.observationRing) {
		manager.nextObservation = 0
	}
}

// SelectUDP selects a healthy edge for a new UDP flow. A recent exact TCP
// winner has priority, followed by geographic and measured-RTT scoring. Equal
// scores use deterministic full-flow-key rendezvous hashing.
func (manager *Manager) SelectUDP(key model.FlowKey) (egress.Edge, error) {
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("select UDP edge: %w", err)
	}
	destination := netip.AddrPortFrom(key.DestinationAddr, key.DestinationPort)

	manager.mu.RLock()
	if observed := manager.recentObservedEdge(destination); observed != nil {
		manager.mu.RUnlock()
		return observed.edge, nil
	}
	locate := manager.locate
	manager.mu.RUnlock()

	destinationLocation, hasLocation := model.GeoPoint{}, false
	if locate != nil {
		destinationLocation, hasLocation = locate(key.DestinationAddr)
		hasLocation = hasLocation && validGeoPoint(destinationLocation)
	}

	manager.mu.RLock()
	defer manager.mu.RUnlock()
	if observed := manager.recentObservedEdge(destination); observed != nil {
		return observed.edge, nil
	}

	var selected *managedEdge
	var selectedScore float64
	var selectedHash uint64
	for _, entry := range manager.edges {
		if entry.state != model.EdgeStateHealthy {
			continue
		}
		score := float64(entry.probeRTT)
		if hasLocation && validGeoPoint(entry.location) {
			distance := geoDistanceKilometers(destinationLocation, entry.location)
			score += distance * float64(2*time.Second) / fiberKilometersPerSecond
		}
		hash := rendezvousHash(key, entry.id)
		if selected == nil || score < selectedScore || score == selectedScore && hash > selectedHash {
			selected = entry
			selectedScore = score
			selectedHash = hash
		}
	}
	if selected == nil {
		return nil, ErrNoHealthyEdges
	}
	return selected.edge, nil
}

// recentObservedEdge requires manager.mu to be held for reading.
func (manager *Manager) recentObservedEdge(destination netip.AddrPort) *managedEdge {
	observation, exists := manager.observations[destination]
	if !exists || manager.now().Sub(observation.observedAt) > tcpObservationTTL {
		return nil
	}
	entry := manager.byID[observation.edgeID]
	if entry == nil || entry.state != model.EdgeStateHealthy {
		return nil
	}
	return entry
}

// Snapshot returns an immutable copy of current health state in configuration
// order.
func (manager *Manager) Snapshot() Snapshot {
	manager.mu.RLock()
	defer manager.mu.RUnlock()

	snapshot := Snapshot{Edges: make([]EdgeSnapshot, 0, len(manager.edges))}
	for _, entry := range manager.edges {
		edgeSnapshot := EdgeSnapshot{
			ID:                  entry.id,
			State:               entry.state,
			ProbeRTT:            entry.probeRTT,
			ConsecutiveFailures: entry.consecutiveFailures,
		}
		if entry.state == model.EdgeStateHealthy {
			snapshot.Healthy++
		}
		snapshot.Edges = append(snapshot.Edges, edgeSnapshot)
	}
	return snapshot
}

// Close stops health probes, closes every owned edge, and transitions all edge
// states to Stopped. It is idempotent.
func (manager *Manager) Close() error {
	manager.closeOnce.Do(func() {
		manager.mu.Lock()
		manager.closed = true
		if manager.cancel != nil {
			manager.cancel()
		}
		for _, entry := range manager.edges {
			entry.state = model.EdgeStateStopped
		}
		manager.mu.Unlock()

		manager.wg.Wait()
		manager.closeErr = manager.closeConstructed()
	})
	return manager.closeErr
}

func (manager *Manager) closeConstructed() error {
	var closeErrors []error
	for index := len(manager.edges) - 1; index >= 0; index-- {
		entry := manager.edges[index]
		if err := entry.edge.Close(); err != nil {
			closeErrors = append(closeErrors, fmt.Errorf("close egress edge %q: %w", entry.id, err))
		}
	}
	return errors.Join(closeErrors...)
}

func validGeoPoint(point model.GeoPoint) bool {
	return !math.IsNaN(point.Latitude) && !math.IsInf(point.Latitude, 0) &&
		!math.IsNaN(point.Longitude) && !math.IsInf(point.Longitude, 0) &&
		point.Latitude >= -90 && point.Latitude <= 90 &&
		point.Longitude >= -180 && point.Longitude <= 180
}

func geoDistanceKilometers(left, right model.GeoPoint) float64 {
	const earthRadiusKilometers = 6371.0088
	leftLatitude := left.Latitude * math.Pi / 180
	rightLatitude := right.Latitude * math.Pi / 180
	latitudeDelta := (right.Latitude - left.Latitude) * math.Pi / 180
	longitudeDelta := (right.Longitude - left.Longitude) * math.Pi / 180
	sineLatitude := math.Sin(latitudeDelta / 2)
	sineLongitude := math.Sin(longitudeDelta / 2)
	a := sineLatitude*sineLatitude + math.Cos(leftLatitude)*math.Cos(rightLatitude)*sineLongitude*sineLongitude
	a = math.Max(0, math.Min(1, a))
	return 2 * earthRadiusKilometers * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
}

func rendezvousHash(key model.FlowKey, edgeID model.EdgeID) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	hash := uint64(offset64)
	addByte := func(value byte) {
		hash ^= uint64(value)
		hash *= prime64
	}
	addByte(byte(key.IPVersion))
	addByte(byte(key.Protocol))
	for _, value := range key.SourceAddr.As16() {
		addByte(value)
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], key.SourcePort)
	addByte(port[0])
	addByte(port[1])
	for _, value := range key.DestinationAddr.As16() {
		addByte(value)
	}
	binary.BigEndian.PutUint16(port[:], key.DestinationPort)
	addByte(port[0])
	addByte(port[1])
	for index := 0; index < len(edgeID); index++ {
		addByte(edgeID[index])
	}
	return hash
}
