// internal/wgdevice/outbound.go
package wgdevice

import (
	"context"
	"net"
)

// Outbound implements forwarder.packetDialer by dialing through the WireGuard tunnel.
type Outbound struct {
	dev *Device
}

// NewOutbound wraps a Device as a packet dialer.
func NewOutbound(d *Device) *Outbound {
	return &Outbound{dev: d}
}

// Dial implements packetDialer.
func (o *Outbound) Dial(network, address string) (net.Conn, error) {
	return o.dev.tnet.DialContext(context.Background(), network, address)
}

// DialContext implements packetDialer.
func (o *Outbound) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return o.dev.tnet.DialContext(ctx, network, address)
}
