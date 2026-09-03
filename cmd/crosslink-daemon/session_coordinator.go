package main

import (
	"context"
	"errors"
	"sync"

	"github.com/limauriga-ux/crosslink/internal/corplink"
	"github.com/limauriga-ux/crosslink/internal/daemonipc"
)

var errSessionUnavailable = errors.New("vpn session is unavailable during reconnect")

// sessionCoordinator serializes server-side session renewal with registration
// of a replacement WireGuard peer. A successful /vpn/conn invalidates the old
// public key, so an old /vpn/report must never cross that boundary.
type sessionCoordinator struct {
	mu        sync.Mutex
	ref       sessionRef
	available bool
}

func newSessionCoordinator(ref sessionRef) *sessionCoordinator {
	return &sessionCoordinator{ref: ref, available: true}
}

func (s *sessionCoordinator) Report(ctx context.Context, report func(context.Context, sessionRef) (*corplink.VPNSettings, error)) (*corplink.VPNSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.available {
		return nil, errSessionUnavailable
	}
	return report(ctx, s.ref)
}

// Reconnect keeps reports paused from before the replacement registration
// starts until the caller confirms that the new local connection may be
// adopted. Failed and superseded attempts leave reporting paused: the previous
// identity may already have been invalidated by the server.
func (s *sessionCoordinator) Reconnect(connect func() (daemonipc.Response, connectDetails), adopt func() bool) (daemonipc.Response, connectDetails, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.available = false

	resp, details := connect()
	if !resp.OK {
		// ListNodes/key generation/GetWGConfig failures happen before the
		// server accepts a replacement key, so the old live tunnel may safely
		// resume renewal. A later local setup failure cannot: /vpn/conn has
		// already invalidated that identity.
		if !details.serverRegistered {
			s.available = true
		}
		return resp, details, false
	}
	if adopt == nil || !adopt() {
		return resp, details, false
	}
	s.ref = sessionRef{
		node:   details.node,
		vpnIP:  details.wgInfo.VpnIP.String(),
		pubB64: details.pubB64,
	}
	s.available = true
	return resp, details, true
}
