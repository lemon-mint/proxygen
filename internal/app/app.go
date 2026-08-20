// Package app wires and owns the complete proxygen runtime.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/config"
	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/edgepool"
	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/egress"
	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/geo"
	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/model"
	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/netstack"
	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/relay"
	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/wgdevice"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	gvisorudp "gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

var (
	errAlreadyRun = errors.New("application has already been run")
	errClosed     = errors.New("application is closed")
)

type geoDatabase interface {
	Lookup(netip.Addr) (model.GeoPoint, bool)
	Close() error
}

type edgeRuntime interface {
	egress.Source
	Start(context.Context)
	Close() error
	Snapshot() edgepool.Snapshot
}

type tcpRuntime interface {
	Handle(*tcp.ForwarderRequest)
	Snapshot() relay.TCPSnapshot
	Close()
}

type udpRuntime interface {
	Handler(*gvisorudp.ForwarderRequest) bool
	Snapshot() relay.UDPSnapshot
	Close() error
}

type ingressRuntime interface {
	Close() error
}

type dependencies struct {
	openGeo      func(string) (geoDatabase, error)
	newEdgePool  func(config.Config, edgepool.LocateFunc) (edgeRuntime, error)
	newTCP       func(egress.Source, relay.TCPConfig) (tcpRuntime, error)
	newUDP       func(egress.Source, time.Duration, int) (udpRuntime, error)
	newNetstack  func(int, int, netstack.Handlers) (ingressRuntime, error)
	newWireGuard func(config.IngressConfig, ingressRuntime) (io.Closer, error)
	listen       func(string, string) (net.Listener, error)
}

var defaultDependencies = dependencies{
	openGeo: func(path string) (geoDatabase, error) {
		return geo.Open(path)
	},
	newEdgePool: func(cfg config.Config, locate edgepool.LocateFunc) (edgeRuntime, error) {
		return edgepool.New(cfg, locate, nil)
	},
	newTCP: func(source egress.Source, cfg relay.TCPConfig) (tcpRuntime, error) {
		return relay.NewTCP(source, cfg)
	},
	newUDP: func(source egress.Source, idleTimeout time.Duration, maxFlows int) (udpRuntime, error) {
		return relay.NewUDP(source, idleTimeout, maxFlows)
	},
	newNetstack: func(mtu, maxTCPInFlight int, handlers netstack.Handlers) (ingressRuntime, error) {
		return netstack.NewIngress(mtu, maxTCPInFlight, handlers)
	},
	newWireGuard: func(cfg config.IngressConfig, ingress ingressRuntime) (io.Closer, error) {
		tunnel, ok := ingress.(tun.Device)
		if !ok {
			return nil, errors.New("ingress netstack does not implement a WireGuard tunnel")
		}
		return wgdevice.NewIngress(cfg, tunnel)
	},
	listen: net.Listen,
}

// App owns every runtime component from ingress through egress and metrics.
type App struct {
	shutdownTimeout time.Duration
	geo             geoDatabase
	edges           edgeRuntime
	tcp             tcpRuntime
	udp             udpRuntime
	ingress         ingressRuntime
	wireGuard       io.Closer
	metrics         *metricsServer

	stateMu sync.Mutex
	ran     bool
	closed  bool
	closing chan struct{}

	closeOnce sync.Once
	closeErr  error
}

// New constructs and owns the complete runtime.
func New(cfg config.Config) (*App, error) {
	return newApp(cfg, defaultDependencies)
}

func newApp(cfg config.Config, deps dependencies) (_ *App, resultErr error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid application configuration: %w", err)
	}
	if err := validateDependencies(deps); err != nil {
		return nil, err
	}

	var cleanups []func() error
	defer func() {
		if resultErr == nil {
			return
		}
		var cleanupErrors []error
		for index := len(cleanups) - 1; index >= 0; index-- {
			if err := cleanups[index](); err != nil {
				cleanupErrors = append(cleanupErrors, err)
			}
		}
		resultErr = errors.Join(resultErr, errors.Join(cleanupErrors...))
	}()

	application := &App{
		shutdownTimeout: cfg.Timeouts.Shutdown.Std(),
		closing:         make(chan struct{}),
	}

	var locate edgepool.LocateFunc
	if cfg.GeoDatabase != "" {
		database, err := deps.openGeo(cfg.GeoDatabase)
		if err != nil {
			return nil, fmt.Errorf("open geographic database: %w", err)
		}
		if database == nil {
			return nil, errors.New("open geographic database: opener returned nil database")
		}
		application.geo = database
		cleanups = append(cleanups, func() error {
			return wrapCloseError("close geographic database", database.Close())
		})
		locate = database.Lookup
	}

	edges, err := deps.newEdgePool(cfg, locate)
	if err != nil {
		return nil, fmt.Errorf("construct edge pool: %w", err)
	}
	if edges == nil {
		return nil, errors.New("construct edge pool: constructor returned nil")
	}
	application.edges = edges
	cleanups = append(cleanups, func() error {
		return wrapCloseError("close edge pool", edges.Close())
	})

	var ingress ingressRuntime
	tcpRelay, err := deps.newTCP(edges, relay.TCPConfig{
		Workers:          cfg.Limits.TCPRaceWorkers,
		QueueDepth:       cfg.Limits.TCPRaceQueueDepth,
		ConnectTimeout:   cfg.Timeouts.TCPConnect.Std(),
		IdleTimeout:      cfg.Timeouts.TCPIdle.Std(),
		RelayBufferBytes: cfg.Limits.RelayBufferBytes,
		AbortPending: func() {
			if ingress != nil {
				_ = ingress.Close()
			}
		},
	})
	if err != nil {
		return nil, fmt.Errorf("construct TCP relay: %w", err)
	}
	if tcpRelay == nil {
		return nil, errors.New("construct TCP relay: constructor returned nil")
	}
	application.tcp = tcpRelay
	cleanups = append(cleanups, func() error {
		tcpRelay.Close()
		return nil
	})

	udpRelay, err := deps.newUDP(edges, cfg.Timeouts.UDPIdle.Std(), cfg.Limits.MaxUDPFlows)
	if err != nil {
		return nil, fmt.Errorf("construct UDP relay: %w", err)
	}
	if udpRelay == nil {
		return nil, errors.New("construct UDP relay: constructor returned nil")
	}
	application.udp = udpRelay
	cleanups = append(cleanups, func() error {
		return wrapCloseError("close UDP relay", udpRelay.Close())
	})

	maxTCPInFlight := cfg.Limits.TCPRaceWorkers + cfg.Limits.TCPRaceQueueDepth
	ingress, err = deps.newNetstack(cfg.MTU, maxTCPInFlight, netstack.Handlers{
		TCP: tcpRelay.Handle,
		UDP: udpRelay.Handler,
	})
	if err != nil {
		return nil, fmt.Errorf("construct ingress netstack: %w", err)
	}
	if ingress == nil {
		return nil, errors.New("construct ingress netstack: constructor returned nil")
	}
	application.ingress = ingress
	cleanups = append(cleanups, func() error {
		return wrapCloseError("close ingress netstack", ingress.Close())
	})

	wireGuard, err := deps.newWireGuard(cfg.Ingress, ingress)
	if err != nil {
		return nil, fmt.Errorf("construct ingress WireGuard device: %w", err)
	}
	if wireGuard == nil {
		return nil, errors.New("construct ingress WireGuard device: constructor returned nil")
	}
	application.wireGuard = wireGuard
	cleanups = append(cleanups, func() error {
		return wrapCloseError("close ingress WireGuard device", wireGuard.Close())
	})

	if cfg.MetricsListen != "" {
		listener, err := deps.listen("tcp", cfg.MetricsListen)
		if err != nil {
			return nil, fmt.Errorf("listen for metrics: %w", err)
		}
		application.metrics = newMetricsServer(listener, application)
		cleanups = append(cleanups, func() error {
			return wrapCloseError("close metrics listener", listener.Close())
		})
	}

	return application, nil
}

func validateDependencies(deps dependencies) error {
	switch {
	case deps.openGeo == nil:
		return errors.New("geographic database opener dependency is required")
	case deps.newEdgePool == nil:
		return errors.New("edge pool constructor dependency is required")
	case deps.newTCP == nil:
		return errors.New("TCP relay constructor dependency is required")
	case deps.newUDP == nil:
		return errors.New("UDP relay constructor dependency is required")
	case deps.newNetstack == nil:
		return errors.New("ingress netstack constructor dependency is required")
	case deps.newWireGuard == nil:
		return errors.New("ingress WireGuard constructor dependency is required")
	case deps.listen == nil:
		return errors.New("listener dependency is required")
	default:
		return nil
	}
}

// Run starts edge health monitoring and serves until cancellation, an explicit
// Close, or an unexpected metrics listener failure.
func (application *App) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	application.stateMu.Lock()
	if application.closed {
		application.stateMu.Unlock()
		return errClosed
	}
	if application.ran {
		application.stateMu.Unlock()
		return errAlreadyRun
	}
	application.ran = true
	application.stateMu.Unlock()

	runContext, cancel := context.WithCancel(ctx)
	defer cancel()
	application.edges.Start(runContext)

	var metricsErrors <-chan error
	if application.metrics != nil {
		metricsErrors = application.metrics.start()
	}

	var runErr error
	select {
	case <-ctx.Done():
	case <-application.closing:
	case err := <-metricsErrors:
		if err != nil {
			runErr = fmt.Errorf("serve metrics: %w", err)
		}
	}
	cancel()
	return errors.Join(runErr, application.Close())
}

// Close stops admission and releases every runtime resource in data-flow order.
// It is safe to call more than once.
func (application *App) Close() error {
	if application == nil {
		return nil
	}
	application.closeOnce.Do(func() {
		application.stateMu.Lock()
		application.closed = true
		close(application.closing)
		application.stateMu.Unlock()

		var closeErrors []error
		if application.wireGuard != nil {
			closeErrors = appendCloseError(closeErrors, "close ingress WireGuard device", application.wireGuard.Close())
		}
		if application.ingress != nil {
			closeErrors = appendCloseError(closeErrors, "close ingress netstack", application.ingress.Close())
		}
		if application.tcp != nil {
			application.tcp.Close()
		}
		if application.udp != nil {
			closeErrors = appendCloseError(closeErrors, "close UDP relay", application.udp.Close())
		}
		if application.edges != nil {
			closeErrors = appendCloseError(closeErrors, "close edge pool", application.edges.Close())
		}
		if application.geo != nil {
			closeErrors = appendCloseError(closeErrors, "close geographic database", application.geo.Close())
		}
		if application.metrics != nil {
			closeErrors = appendCloseError(closeErrors, "stop metrics server", application.metrics.close(application.shutdownTimeout))
		}
		application.closeErr = errors.Join(closeErrors...)
	})
	return application.closeErr
}

func appendCloseError(errs []error, operation string, err error) []error {
	if wrapped := wrapCloseError(operation, err); wrapped != nil {
		return append(errs, wrapped)
	}
	return errs
}

func wrapCloseError(operation string, err error) error {
	if err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}
