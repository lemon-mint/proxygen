package egress

import (
	"errors"
	"net"
	"sync"
)

const (
	udpFirstEphemeralPort uint16 = 16000
	udpLastEphemeralPort  uint16 = 65535
	udpEphemeralPortCount        = int(udpLastEphemeralPort-udpFirstEphemeralPort) + 1
)

type udpPortAllocator struct {
	mu     sync.Mutex
	next   uint16
	closed bool
	active map[uint16]*reservedUDPConn
}

func newUDPPortAllocator() *udpPortAllocator {
	return &udpPortAllocator{
		next:   udpFirstEphemeralPort,
		active: make(map[uint16]*reservedUDPConn),
	}
}

func (allocator *udpPortAllocator) reserve() (uint16, error) {
	allocator.mu.Lock()
	defer allocator.mu.Unlock()
	if allocator.closed {
		return 0, net.ErrClosed
	}

	for range udpEphemeralPortCount {
		port := allocator.next
		if allocator.next == udpLastEphemeralPort {
			allocator.next = udpFirstEphemeralPort
		} else {
			allocator.next++
		}
		if _, exists := allocator.active[port]; exists {
			continue
		}
		allocator.active[port] = nil
		return port, nil
	}
	return 0, errors.New("no UDP source ports are available on this edge")
}

func (allocator *udpPortAllocator) wrap(port uint16, connection net.Conn) (*reservedUDPConn, error) {
	if connection == nil {
		allocator.release(port, nil)
		return nil, errors.New("UDP dial returned a nil connection")
	}
	wrapped := &reservedUDPConn{
		Conn:      connection,
		allocator: allocator,
		port:      port,
	}

	allocator.mu.Lock()
	if allocator.closed {
		if current, exists := allocator.active[port]; exists && current == nil {
			delete(allocator.active, port)
		}
		allocator.mu.Unlock()
		_ = connection.Close()
		return nil, net.ErrClosed
	}
	if current, exists := allocator.active[port]; !exists || current != nil {
		allocator.mu.Unlock()
		_ = connection.Close()
		return nil, errors.New("UDP source-port reservation was lost")
	}
	allocator.active[port] = wrapped
	allocator.mu.Unlock()
	return wrapped, nil
}

func (allocator *udpPortAllocator) release(port uint16, expected *reservedUDPConn) {
	allocator.mu.Lock()
	if current, exists := allocator.active[port]; exists && current == expected {
		delete(allocator.active, port)
	}
	allocator.mu.Unlock()
}

func (allocator *udpPortAllocator) closeAll() {
	allocator.mu.Lock()
	if allocator.closed {
		allocator.mu.Unlock()
		return
	}
	allocator.closed = true
	connections := make([]*reservedUDPConn, 0, len(allocator.active))
	for port, connection := range allocator.active {
		if connection == nil {
			delete(allocator.active, port)
			continue
		}
		connections = append(connections, connection)
	}
	allocator.mu.Unlock()

	for _, connection := range connections {
		_ = connection.Close()
	}
}

type reservedUDPConn struct {
	net.Conn
	allocator *udpPortAllocator
	port      uint16
	closeOnce sync.Once
	closeErr  error
}

func (connection *reservedUDPConn) Close() error {
	connection.closeOnce.Do(func() {
		connection.closeErr = connection.Conn.Close()
		connection.allocator.release(connection.port, connection)
	})
	return connection.closeErr
}
