// Package wgdevice owns the ingress WireGuard device lifecycle.
package wgdevice

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/config"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type wireGuardDevice interface {
	IpcSet(string) error
	Up() error
	Close()
}

type ingressDependencies struct {
	newBind   func() conn.Bind
	newDevice func(tun.Device, conn.Bind, *device.Logger) wireGuardDevice
}

var defaultIngressDependencies = ingressDependencies{
	newBind: conn.NewDefaultBind,
	newDevice: func(tunnel tun.Device, bind conn.Bind, logger *device.Logger) wireGuardDevice {
		return device.NewDevice(tunnel, bind, logger)
	},
}

// Ingress owns one WireGuard device configured to accept ingress peers. Its
// Device is the sole lifecycle owner of the supplied tunnel after construction
// reaches device creation.
type Ingress struct {
	device    wireGuardDevice
	closeOnce sync.Once
}

// NewIngress configures and brings up a WireGuard device over tunnel.
func NewIngress(cfg config.IngressConfig, tunnel tun.Device) (*Ingress, error) {
	return newIngress(cfg, tunnel, defaultIngressDependencies)
}

func newIngress(cfg config.IngressConfig, tunnel tun.Device, dependencies ingressDependencies) (*Ingress, error) {
	if tunnel == nil {
		return nil, errors.New("ingress tunnel is required")
	}
	configuration, err := ingressUAPI(cfg)
	if err != nil {
		return nil, fmt.Errorf("invalid ingress configuration: %w", err)
	}

	wireGuard := dependencies.newDevice(
		tunnel,
		dependencies.newBind(),
		device.NewLogger(device.LogLevelSilent, ""),
	)
	ingress := &Ingress{device: wireGuard}
	if err := wireGuard.IpcSet(configuration); err != nil {
		_ = ingress.Close()
		return nil, errors.New("configure ingress WireGuard device: configuration rejected")
	}
	if err := wireGuard.Up(); err != nil {
		_ = ingress.Close()
		return nil, fmt.Errorf("bring up ingress WireGuard device: %w", err)
	}
	return ingress, nil
}

// Close synchronously closes the ingress WireGuard device exactly once.
func (ingress *Ingress) Close() error {
	ingress.closeOnce.Do(ingress.device.Close)
	return nil
}

func ingressUAPI(cfg config.IngressConfig) (string, error) {
	if err := cfg.Validate(); err != nil {
		return "", err
	}
	privateKey, err := keyToHex(cfg.PrivateKey)
	if err != nil {
		return "", errors.New("ingress.private_key must be a base64-encoded 32-byte key")
	}

	var configuration strings.Builder
	fmt.Fprintf(&configuration, "private_key=%s\n", privateKey)
	fmt.Fprintf(&configuration, "listen_port=%d\n", cfg.ListenPort)
	configuration.WriteString("replace_peers=true\n")
	for index, peer := range cfg.Peers {
		publicKey, err := keyToHex(peer.PublicKey)
		if err != nil {
			return "", fmt.Errorf("ingress.peers[%d].public_key must be a base64-encoded 32-byte key", index)
		}
		address := peer.OverlayAddress.Unmap()
		bits := 128
		if address.Is4() {
			bits = 32
		}
		fmt.Fprintf(&configuration, "public_key=%s\n", publicKey)
		configuration.WriteString("replace_allowed_ips=true\n")
		fmt.Fprintf(&configuration, "allowed_ip=%s\n", netip.PrefixFrom(address, bits))
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
