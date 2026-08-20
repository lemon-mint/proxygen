package app

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/edgepool"
	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/relay"
)

const minimumHealthyEdges = 3

type snapshotSource interface {
	edgeSnapshot() edgepool.Snapshot
	tcpSnapshot() relay.TCPSnapshot
	udpSnapshot() relay.UDPSnapshot
}

type metricsSnapshot struct {
	Edges edgepool.Snapshot `json:"edges"`
	TCP   relay.TCPSnapshot `json:"tcp"`
	UDP   relay.UDPSnapshot `json:"udp"`
}

type healthSnapshot struct {
	Healthy bool `json:"healthy"`
	Edges   int  `json:"healthy_edges"`
}

type metricsServer struct {
	server    *http.Server
	listener  net.Listener
	errors    chan error
	startOnce sync.Once
}

func newMetricsServer(listener net.Listener, snapshots snapshotSource) *metricsServer {
	server := &metricsServer{
		listener: listener,
		errors:   make(chan error, 1),
	}
	server.server = &http.Server{
		Handler:           newControlHandler(snapshots),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	return server
}

func (server *metricsServer) start() <-chan error {
	server.startOnce.Do(func() {
		go func() {
			err := server.server.Serve(server.listener)
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			server.errors <- err
			close(server.errors)
		}()
	})
	return server.errors
}

func (server *metricsServer) close(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	shutdownErr := server.server.Shutdown(ctx)
	if shutdownErr != nil {
		shutdownErr = errors.Join(shutdownErr, server.server.Close())
	}
	listenerErr := server.listener.Close()
	if errors.Is(listenerErr, net.ErrClosed) {
		listenerErr = nil
	}
	return errors.Join(shutdownErr, listenerErr)
}

func newControlHandler(snapshots snapshotSource) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) {
		edges := snapshots.edgeSnapshot()
		healthy := edges.Healthy >= minimumHealthyEdges
		status := http.StatusOK
		if !healthy {
			status = http.StatusServiceUnavailable
		}
		writeJSON(writer, status, healthSnapshot{Healthy: healthy, Edges: edges.Healthy})
	})
	mux.HandleFunc("GET /metrics", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, metricsSnapshot{
			Edges: snapshots.edgeSnapshot(),
			TCP:   snapshots.tcpSnapshot(),
			UDP:   snapshots.udpSnapshot(),
		})
	})
	return mux
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func (application *App) edgeSnapshot() edgepool.Snapshot {
	return application.edges.Snapshot()
}

func (application *App) tcpSnapshot() relay.TCPSnapshot {
	return application.tcp.Snapshot()
}

func (application *App) udpSnapshot() relay.UDPSnapshot {
	return application.udp.Snapshot()
}
