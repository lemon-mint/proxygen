package egress

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/config"
	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/model"
	localnetstack "git.sepolia.gosuda.org/lemon-mint/proxygen/internal/netstack"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type wireGuardDevice interface {
	IpcSet(string) error
	Up() error
	Close()
}

type bundleNetwork interface {
	DialTCP(context.Context, netip.AddrPort) (net.Conn, error)
	DialUDP(uint16, netip.AddrPort) (net.Conn, error)
}

type bundleDependencies struct {
	createNetwork func(netip.Addr, int) (tun.Device, bundleNetwork, error)
	newBind       func() conn.Bind
	newDevice     func(tun.Device, conn.Bind, *device.Logger) wireGuardDevice
}

var defaultBundleDependencies = bundleDependencies{
	createNetwork: func(local netip.Addr, mtu int) (tun.Device, bundleNetwork, error) {
		network, err := localnetstack.NewEgress(local, mtu)
		if err != nil {
			return nil, nil, err
		}
		return network, network, nil
	},
	newBind: conn.NewDefaultBind,
	newDevice: func(tunnel tun.Device, bind conn.Bind, logger *device.Logger) wireGuardDevice {
		return device.NewDevice(tunnel, bind, logger)
	},
}

// Bundle is one completely independent WireGuard device, userspace network
// stack, tunnel, and host UDP bind.
type Bundle struct {
	id       model.EdgeID
	tunnel   tun.Device
	network  bundleNetwork
	bind     conn.Bind
	device   wireGuardDevice
	udpPorts *udpPortAllocator

	closeOnce sync.Once
}

var _ Edge = (*Bundle)(nil)

// NewBundle creates and brings up one independent egress edge.
func NewBundle(cfg config.EdgeConfig, mtu int) (*Bundle, error) {
	return newBundle(cfg, mtu, defaultBundleDependencies)
}

func newBundle(cfg config.EdgeConfig, mtu int, dependencies bundleDependencies) (*Bundle, error) {
	if mtu < 1280 || mtu > device.MaxContentSize {
		return nil, fmt.Errorf("egress MTU must be between 1280 and %d", device.MaxContentSize)
	}
	configuration, err := edgeUAPI(cfg)
	if err != nil {
		return nil, fmt.Errorf("invalid egress configuration: %w", err)
	}

	tunnel, network, err := dependencies.createNetwork(
		cfg.OverlayAddress.Addr().Unmap(),
		mtu,
	)
	if err != nil {
		return nil, fmt.Errorf("create egress %q network stack: %w", cfg.ID, err)
	}
	bind := dependencies.newBind()
	wireGuard := dependencies.newDevice(
		tunnel,
		bind,
		device.NewLogger(device.LogLevelSilent, ""),
	)
	bundle := &Bundle{
		id:       cfg.ID,
		tunnel:   tunnel,
		network:  network,
		bind:     bind,
		device:   wireGuard,
		udpPorts: newUDPPortAllocator(),
	}
	if err := wireGuard.IpcSet(configuration); err != nil {
		_ = bundle.Close()
		return nil, fmt.Errorf("configure egress %q WireGuard device: configuration rejected", cfg.ID)
	}
	if err := wireGuard.Up(); err != nil {
		_ = bundle.Close()
		return nil, fmt.Errorf("bring up egress %q WireGuard device: %w", cfg.ID, err)
	}
	return bundle, nil
}

// ID returns this edge's stable configured identity.
func (bundle *Bundle) ID() model.EdgeID {
	return bundle.id
}

// DialTCP opens a connected TCP socket in this edge's private network stack.
func (bundle *Bundle) DialTCP(ctx context.Context, remote netip.AddrPort) (net.Conn, error) {
	if ctx == nil {
		return nil, errors.New("TCP dial context is required")
	}
	if !remote.IsValid() || remote.Port() == 0 {
		return nil, errors.New("TCP remote address and port are invalid")
	}
	remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	return bundle.network.DialTCP(ctx, remote)
}

// DialUDP opens a connected UDP socket in this edge's private network stack.
func (bundle *Bundle) DialUDP(ctx context.Context, remote netip.AddrPort) (net.Conn, error) {
	if ctx == nil {
		return nil, errors.New("UDP dial context is required")
	}
	if !remote.IsValid() || remote.Port() == 0 {
		return nil, errors.New("UDP remote address and port are invalid")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	port, err := bundle.udpPorts.reserve()
	if err != nil {
		return nil, err
	}
	remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	connection, err := bundle.network.DialUDP(port, remote)
	if err != nil {
		bundle.udpPorts.release(port, nil)
		return nil, err
	}
	wrapped, err := bundle.udpPorts.wrap(port, connection)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		_ = wrapped.Close()
		return nil, err
	}
	return wrapped, nil
}

// Close synchronously closes active UDP sockets and then the WireGuard device
// exactly once. Device shutdown owns the bundle's tunnel and bind.
func (bundle *Bundle) Close() error {
	bundle.closeOnce.Do(func() {
		bundle.udpPorts.closeAll()
		bundle.device.Close()
	})
	return nil
}

func edgeUAPI(cfg config.EdgeConfig) (string, error) {
	if err := cfg.Validate(); err != nil {
		return "", err
	}
	privateKey, err := keyToHex(cfg.PrivateKey)
	if err != nil {
		return "", errors.New("edge.private_key must be a base64-encoded 32-byte key")
	}
	publicKey, err := keyToHex(cfg.PeerPublicKey)
	if err != nil {
		return "", errors.New("edge.peer_public_key must be a base64-encoded 32-byte key")
	}
	var presharedKey string
	if cfg.PresharedKey != "" {
		presharedKey, err = keyToHex(cfg.PresharedKey)
		if err != nil {
			return "", errors.New("edge.preshared_key must be a base64-encoded 32-byte key")
		}
	}

	var configuration strings.Builder
	fmt.Fprintf(&configuration, "private_key=%s\n", privateKey)
	if cfg.ListenPort != 0 {
		fmt.Fprintf(&configuration, "listen_port=%d\n", cfg.ListenPort)
	}
	configuration.WriteString("replace_peers=true\n")
	fmt.Fprintf(&configuration, "public_key=%s\n", publicKey)
	if presharedKey != "" {
		fmt.Fprintf(&configuration, "preshared_key=%s\n", presharedKey)
	}
	fmt.Fprintf(&configuration, "endpoint=%s\n", cfg.Endpoint)
	fmt.Fprintf(&configuration, "persistent_keepalive_interval=%d\n", int64(cfg.PersistentKeepalive.Std().Seconds()))
	configuration.WriteString("replace_allowed_ips=true\n")
	for _, prefix := range cfg.AllowedIPs {
		fmt.Fprintf(&configuration, "allowed_ip=%s\n", prefix)
	}
	configuration.WriteByte('\n')
	return configuration.String(), nil
}

func keyToHex(encoded string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(key) != 32 {
		return "", errors.New("invalid WireGuard key")
	}
	var combined byte
	for _, value := range key {
		combined |= value
	}
	if combined == 0 {
		return "", errors.New("invalid WireGuard key")
	}
	return hex.EncodeToString(key), nil
}
