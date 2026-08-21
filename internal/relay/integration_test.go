package relay_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"git.gosuda.org/lemon-mint/proxygen/internal/egress"
	"git.gosuda.org/lemon-mint/proxygen/internal/model"
	"git.gosuda.org/lemon-mint/proxygen/internal/netstack"
	"git.gosuda.org/lemon-mint/proxygen/internal/relay"
	"golang.zx2c4.com/wireguard/tun"
)

func TestIngressTCPForwarderRacesRealRelayWithoutLoserPayload(t *testing.T) {
	const mtu = 1420
	destination := netip.MustParseAddrPort("198.51.100.77:443")

	winnerRelay, winnerPeer := net.Pipe()
	defer winnerPeer.Close()
	loserRelay, loserPeer := net.Pipe()
	defer loserPeer.Close()
	winner := newIntegrationConn(winnerRelay)
	loser := newIntegrationConn(loserRelay)

	attempted := make(chan model.EdgeID, 2)
	releaseWinner := make(chan struct{})
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			close(releaseWinner)
		})
	}
	edges := []egress.Edge{
		&integrationEdge{
			id: "winner",
			dialTCP: func(_ context.Context, remote netip.AddrPort) (net.Conn, error) {
				if remote != destination {
					return nil, fmt.Errorf("winner destination = %v, want %v", remote, destination)
				}
				attempted <- "winner"
				<-releaseWinner
				return winner, nil
			},
		},
		&integrationEdge{
			id: "loser",
			dialTCP: func(ctx context.Context, remote netip.AddrPort) (net.Conn, error) {
				if remote != destination {
					return nil, fmt.Errorf("loser destination = %v, want %v", remote, destination)
				}
				attempted <- "loser"
				<-ctx.Done()
				// Deliberately return a successful connection after cancellation. The
				// race must close it without ever exposing it to a relay copy loop.
				return loser, nil
			},
		},
	}
	source := integrationSource{edges: edges}

	var ingress *netstack.Ingress
	tcpRelay, err := relay.NewTCP(source, relay.TCPConfig{
		Workers:          1,
		QueueDepth:       0,
		ConnectTimeout:   5 * time.Second,
		IdleTimeout:      time.Minute,
		RelayBufferBytes: 1024,
		AllowDestination: func(model.FlowKey) bool { return true },
		AbortPending: func() {
			if ingress != nil {
				_ = ingress.Close()
			}
		},
	})
	if err != nil {
		t.Fatalf("NewTCP: %v", err)
	}
	udpRelay, err := relay.NewUDP(source, time.Minute, 8, func(model.FlowKey) bool { return true })
	if err != nil {
		tcpRelay.Close()
		t.Fatalf("NewUDP: %v", err)
	}
	ingress, err = netstack.NewIngress(mtu, 1, netstack.Handlers{
		TCP: tcpRelay.Handle,
		UDP: udpRelay.Handler,
	})
	if err != nil {
		_ = udpRelay.Close()
		tcpRelay.Close()
		t.Fatalf("NewIngress: %v", err)
	}
	client, err := netstack.NewEgress(netip.MustParseAddr("192.0.2.10"), mtu)
	if err != nil {
		_ = ingress.Close()
		_ = udpRelay.Close()
		tcpRelay.Close()
		t.Fatalf("NewEgress client stack: %v", err)
	}

	bridgeExited := make(chan error, 2)
	var clientPackets, ingressPackets atomic.Int32
	go pumpTUN(client, ingress, mtu, &clientPackets, bridgeExited)
	go pumpTUN(ingress, client, mtu, &ingressPackets, bridgeExited)
	cleaned := false
	cleanup := func() {
		if cleaned {
			return
		}
		cleaned = true
		release()
		tcpRelay.Close()
		_ = udpRelay.Close()
		_ = ingress.Close()
		_ = client.Close()
		for range 2 {
			select {
			case bridgeErr := <-bridgeExited:
				if bridgeErr != nil && !errors.Is(bridgeErr, os.ErrClosed) {
					t.Errorf("packet bridge shutdown: %v", bridgeErr)
				}
			case <-time.After(time.Second):
				t.Error("packet bridge did not stop")
			}
		}
	}
	defer cleanup()

	type dialResult struct {
		conn net.Conn
		err  error
	}
	var dialed chan dialResult = make(chan dialResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, dialErr := client.DialTCP(ctx, destination)
		dialed <- dialResult{conn: conn, err: dialErr}
	}()

	var clientConn net.Conn
	seen := make(map[model.EdgeID]bool, 2)
	for len(seen) < len(edges) {
		select {
		case edgeID := <-attempted:
			seen[edgeID] = true
		case bridgeErr := <-bridgeExited:
			t.Fatalf("packet bridge exited during TCP assembly: %v", bridgeErr)
		case result := <-dialed:
			dialed = nil
			if result.err != nil {
				t.Fatalf("client gVisor DialTCP: %v", result.err)
			}
			clientConn = result.conn
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for both edge race attempts (client packets %d, ingress packets %d, snapshot %+v)", clientPackets.Load(), ingressPackets.Load(), tcpRelay.Snapshot())
		}
	}
	if !seen["winner"] || !seen["loser"] {
		t.Fatalf("attempted edges = %v, want winner and loser", seen)
	}
	release()

	if clientConn == nil {
		select {
		case result := <-dialed:
			if result.err != nil {
				t.Fatalf("client gVisor DialTCP: %v", result.err)
			}
			clientConn = result.conn
		case bridgeErr := <-bridgeExited:
			t.Fatalf("packet bridge exited during TCP handshake: %v", bridgeErr)
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for client TCP handshake")
		}
	}
	defer clientConn.Close()

	waitIntegrationSignal(t, loser.closed, "race loser close")
	if reads, writes := loser.reads.Load(), loser.writes.Load(); reads != 0 || writes != 0 {
		t.Fatalf("loser payload operations = reads %d, writes %d; want none", reads, writes)
	}

	request := []byte("request through injected TCP packets")
	if err := clientConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}
	if err := winnerPeer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set winner deadline: %v", err)
	}
	if _, err := clientConn.Write(request); err != nil {
		t.Fatalf("client write: %v", err)
	}
	received := make([]byte, len(request))
	if _, err := readFull(winnerPeer, received); err != nil {
		t.Fatalf("winner read: %v", err)
	}
	if string(received) != string(request) {
		t.Fatalf("winner payload = %q, want %q", received, request)
	}

	response := []byte("response through real relay handler")
	if _, err := winnerPeer.Write(response); err != nil {
		t.Fatalf("winner write: %v", err)
	}
	received = make([]byte, len(response))
	if _, err := readFull(clientConn, received); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(received) != string(response) {
		t.Fatalf("client payload = %q, want %q", received, response)
	}

	snapshot := tcpRelay.Snapshot()
	if snapshot.Admissions != 1 || snapshot.Wins != 1 || snapshot.Failures != 0 {
		t.Fatalf("TCP snapshot = %+v, want one admission and one winning race", snapshot)
	}
	cleanup()
}

func pumpTUN(source, destination tun.Device, mtu int, forwarded *atomic.Int32, exited chan<- error) {
	buffers := make([][]byte, source.BatchSize())
	for index := range buffers {
		buffers[index] = make([]byte, mtu)
	}
	sizes := make([]int, len(buffers))
	packets := make([][]byte, len(buffers))
	for {
		count, err := source.Read(buffers, sizes, 0)
		if err != nil {
			exited <- err
			return
		}
		for index := range count {
			packets[index] = buffers[index][:sizes[index]]
		}
		if _, err := destination.Write(packets[:count], 0); err != nil {
			exited <- err
			return
		}
		forwarded.Add(int32(count))
	}
}

func readFull(connection net.Conn, buffer []byte) (int, error) {
	read := 0
	for read < len(buffer) {
		count, err := connection.Read(buffer[read:])
		read += count
		if err != nil {
			return read, err
		}
	}
	return read, nil
}

type integrationSource struct {
	edges []egress.Edge
}

func (source integrationSource) Healthy() []egress.Edge {
	return source.edges
}

func (source integrationSource) SelectUDP(model.FlowKey) (egress.Edge, error) {
	return source.edges[0], nil
}

type integrationEdge struct {
	id      model.EdgeID
	dialTCP func(context.Context, netip.AddrPort) (net.Conn, error)
}

func (edge *integrationEdge) ID() model.EdgeID {
	return edge.id
}

func (edge *integrationEdge) DialTCP(ctx context.Context, remote netip.AddrPort) (net.Conn, error) {
	return edge.dialTCP(ctx, remote)
}

func (*integrationEdge) DialUDP(context.Context, netip.AddrPort) (net.Conn, error) {
	return nil, errors.New("unexpected UDP dial")
}

func (*integrationEdge) Close() error {
	return nil
}

type integrationConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
	reads  atomic.Int32
	writes atomic.Int32
}

func newIntegrationConn(connection net.Conn) *integrationConn {
	return &integrationConn{Conn: connection, closed: make(chan struct{})}
}

func (connection *integrationConn) Read(buffer []byte) (int, error) {
	connection.reads.Add(1)
	return connection.Conn.Read(buffer)
}

func (connection *integrationConn) Write(buffer []byte) (int, error) {
	connection.writes.Add(1)
	return connection.Conn.Write(buffer)
}

func (connection *integrationConn) Close() error {
	connection.once.Do(func() {
		close(connection.closed)
	})
	return connection.Conn.Close()
}

func waitIntegrationSignal(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}
