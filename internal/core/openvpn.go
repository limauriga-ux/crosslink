package core

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/limauriga-ux/crosslink/internal/openvpnprofile"

	"github.com/sagernet/sing-box/adapter"
)

// OpenVPNChallenge is safe to expose over IPC. It contains server prompts but
// never includes a submitted password or response.
type OpenVPNChallenge struct {
	ID            string `json:"id"`
	Kind          string `json:"kind"`
	Username      string `json:"username,omitempty"`
	Message       string `json:"message,omitempty"`
	URL           string `json:"url,omitempty"`
	URLAllowed    bool   `json:"url_allowed,omitempty"`
	SecretMessage string `json:"secret_message,omitempty"`
	Echo          bool   `json:"echo,omitempty"`
	PreviousError string `json:"previous_error,omitempty"`
	Deadline      int64  `json:"deadline,omitempty"`
}

type OpenVPNStatus struct {
	Configured  bool              `json:"configured"`
	Active      bool              `json:"active"`
	ProfileName string            `json:"profile_name,omitempty"`
	State       string            `json:"state"`
	Error       string            `json:"error,omitempty"`
	Server      string            `json:"server,omitempty"`
	Network     string            `json:"network,omitempty"`
	Cipher      string            `json:"cipher,omitempty"`
	IPv4        []string          `json:"ipv4,omitempty"`
	IPv6        []string          `json:"ipv6,omitempty"`
	DNS         []string          `json:"dns,omitempty"`
	MTU         uint32            `json:"mtu,omitempty"`
	ConnectedAt int64             `json:"connected_at,omitempty"`
	RouteCount  int               `json:"route_count,omitempty"`
	DomainCount int               `json:"domain_count,omitempty"`
	Challenge   *OpenVPNChallenge `json:"challenge,omitempty"`
}

const openVPNAuthScopeGrace = 10 * time.Minute

// PrepareOpenVPNChallenge arms the short-lived public authentication scope
// after the user explicitly opens a trusted live browser challenge. The daemon
// never fetches the one-time URL itself: the scope is derived only from the
// managed profile, and the browser follows the OAuth flow through the public
// final outbound ahead of OpenVPN-owned and imported Profile routes.
func (m *Manager) PrepareOpenVPNChallenge(challengeID string) error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()

	endpoint, err := m.openVPNEndpointLocked()
	if err != nil {
		return err
	}
	current := endpoint.OpenVPNStatus().Challenge
	if current == nil || current.ID != challengeID {
		return errors.New("OpenVPN challenge is no longer active")
	}
	if current.Kind != "open-url" {
		return errors.New("OpenVPN challenge is not a browser authentication flow")
	}
	deadline := openVPNChallengeDeadline(current)
	if !openVPNChallengeLive(deadline) {
		return errors.New("OpenVPN authentication challenge has expired")
	}
	return m.armOpenVPNChallengeLocked(challengeID, current.URL, deadline)
}

func openVPNChallengeDeadline(status *adapter.OpenVPNChallenge) int64 {
	if status == nil || status.Deadline.IsZero() {
		return 0
	}
	return status.Deadline.Unix()
}

func openVPNChallengeLive(deadline int64) bool {
	return deadline == 0 || deadline > time.Now().Unix()
}

// armOpenVPNChallengeLocked publishes the narrowest profile-derived scope for
// a trusted live browser challenge. If the server rotates an expired
// generation, a bounded grace period keeps an in-flight SSO page reachable.
func (m *Manager) armOpenVPNChallengeLocked(challengeID, challengeURL string, deadline int64) error {
	if challengeID == "" || challengeURL == "" {
		return errors.New("OpenVPN authentication challenge is invalid")
	}
	scope, ok := openvpnprofile.ChallengeURLScope(challengeURL, m.openVPN.profile.Remotes, m.openVPN.profile.Domains...)
	if !ok {
		return errors.New("OpenVPN authentication URL is not trusted")
	}
	m.openVPNChallengeID = challengeID
	m.openVPNChallengeURL = challengeURL
	m.openVPNChallengeGraceID = ""
	m.runtime.SetPublicAuthScope(scope, deadline)
	return nil
}

func (m *Manager) clearOpenVPNChallengeLocked() {
	m.openVPNChallengeID = ""
	m.openVPNChallengeURL = ""
	m.openVPNChallengeGraceID = ""
	if m.runtime != nil {
		m.runtime.SetPublicAuthScope("", 0)
	}
}

// graceOpenVPNChallengeLocked drops the stale challenge identity but retains
// its trusted public scope for one bounded retry window. Repeated status polls
// for the same expired generation never slide that window forward.
func (m *Manager) graceOpenVPNChallengeLocked(challengeID string) {
	m.openVPNChallengeID = ""
	m.openVPNChallengeURL = ""
	if challengeID == "" || m.openVPNChallengeGraceID == challengeID {
		return
	}
	m.openVPNChallengeGraceID = challengeID
	if m.runtime != nil {
		m.runtime.ExtendPublicAuthDeadline(time.Now().Add(openVPNAuthScopeGrace).Unix())
	}
}

// syncOpenVPNClaimsLocked republishes the explicit OpenVPN profile claims so
// CorpLink's server-pushed routes and domains yield overlapping segments to
// the OpenVPN endpoint. Caller must hold lifecycleMu.
func (m *Manager) syncOpenVPNClaimsLocked() {
	if m.runtime == nil {
		return
	}
	if m.openVPN == nil {
		m.runtime.SetOpenVPNClaims(nil, nil)
		return
	}
	m.runtime.SetOpenVPNClaims(m.openVPN.profile.Routes, m.openVPN.profile.Domains)
}

func (m *Manager) ConnectOpenVPN(profile openvpnprofile.Profile, username, password string) error {
	if err := profile.Validate(); err != nil {
		return fmt.Errorf("validate OpenVPN profile: %w", err)
	}
	if profile.AuthUserPass && strings.TrimSpace(username) == "" {
		return errors.New("OpenVPN username is required")
	}

	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	candidate := &openVPNRuntimeConfig{profile: profile, username: username, password: password}
	if _, err := compileConfigWithOpenVPN(m.cfg, candidate); err != nil {
		return fmt.Errorf("validate OpenVPN core: %w", err)
	}
	m.clearOpenVPNChallengeLocked()
	previous := m.openVPN
	wasRunning := m.instance != nil
	if wasRunning {
		if err := m.stopCoreLocked(); err != nil {
			return fmt.Errorf("stop unified core before enabling OpenVPN: %w", err)
		}
	}
	m.openVPN = candidate
	m.syncOpenVPNClaimsLocked()
	if err := m.startCoreLocked(); err != nil {
		m.openVPN = previous
		m.syncOpenVPNClaimsLocked()
		if wasRunning {
			if recoveryErr := m.startCoreLocked(); recoveryErr != nil {
				return fmt.Errorf("rebuild unified core with OpenVPN: %v; restore pre-change unified core: %w", err, recoveryErr)
			}
			return fmt.Errorf("rebuild unified core with OpenVPN: %w; pre-change unified core restored", err)
		}
		return fmt.Errorf("start unified core with OpenVPN: %w", err)
	}
	return nil
}

func (m *Manager) DisconnectOpenVPN() error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if m.openVPN == nil {
		return nil
	}
	previous := m.openVPN
	wasRunning := m.instance != nil
	if wasRunning {
		if err := m.stopCoreLocked(); err != nil {
			return fmt.Errorf("stop unified core before disconnecting OpenVPN: %w", err)
		}
	}
	m.openVPN = nil
	m.syncOpenVPNClaimsLocked()
	if !wasRunning {
		m.clearOpenVPNChallengeLocked()
		return nil
	}
	if err := m.startCoreLocked(); err != nil {
		m.openVPN = previous
		m.syncOpenVPNClaimsLocked()
		if recoveryErr := m.startCoreLocked(); recoveryErr != nil {
			return fmt.Errorf("rebuild unified core without OpenVPN: %v; restore previous unified core with OpenVPN still active: %w", err, recoveryErr)
		}
		return fmt.Errorf("rebuild unified core without OpenVPN: %w; previous unified core restored and OpenVPN remains active", err)
	}
	m.clearOpenVPNChallengeLocked()
	return nil
}

func (m *Manager) OpenVPNStatus() OpenVPNStatus {
	status := OpenVPNStatus{State: "disconnected"}

	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if m.openVPN != nil {
		status.Active = true
		status.Configured = true
		status.ProfileName = m.openVPN.profile.Name
		status.RouteCount = len(m.openVPN.profile.Routes)
		status.DomainCount = len(m.openVPN.profile.Domains)
		status.State = adapter.OpenVPNStateConnecting
	}
	endpoint, err := m.openVPNEndpointLocked()
	if err != nil {
		if m.openVPN != nil {
			status.State = adapter.OpenVPNStateError
			status.Error = err.Error()
		}
		return m.finalizeOpenVPNStatus(status)
	}
	return m.finalizeOpenVPNStatus(mergeOpenVPNStatus(status, endpoint.OpenVPNStatus()))
}

func (m *Manager) finalizeOpenVPNStatus(status OpenVPNStatus) OpenVPNStatus {
	if status.Challenge == nil || m.openVPN == nil {
		m.clearOpenVPNChallengeLocked()
		return status
	}

	// The ownership verdict is returned to the GUI even when the challenge is
	// not safe to open. Only a trusted, live browser challenge may arm DNS.
	status.Challenge.URLAllowed = openvpnprofile.ChallengeURLAllowed(
		status.Challenge.URL,
		m.openVPN.profile.Remotes,
		m.openVPN.profile.Domains...,
	)
	if status.Challenge.Kind != "open-url" || !status.Challenge.URLAllowed {
		m.clearOpenVPNChallengeLocked()
		return status
	}
	if !openVPNChallengeLive(status.Challenge.Deadline) {
		m.graceOpenVPNChallengeLocked(status.Challenge.ID)
		return status
	}
	// A regenerated challenge must re-arm explicitly, but the previous trusted
	// scope gets one bounded grace window so an in-flight SSO page stays usable.
	if m.openVPNChallengeID != "" && m.openVPNChallengeID != status.Challenge.ID {
		m.graceOpenVPNChallengeLocked(status.Challenge.ID)
	}
	return status
}

func (m *Manager) CompleteOpenVPNChallenge(challengeID, username, password, secret string) error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	endpoint, err := m.openVPNEndpointLocked()
	if err != nil {
		return err
	}
	current := endpoint.OpenVPNStatus().Challenge
	if current == nil || current.ID != challengeID {
		return errors.New("OpenVPN challenge is no longer active")
	}
	if err := endpoint.CompleteChallenge(challengeID, adapter.OpenVPNChallengeResponse{
		Username: username,
		Password: password,
		Secret:   secret,
	}); err != nil {
		return err
	}
	m.clearOpenVPNChallengeLocked()
	return nil
}

func (m *Manager) CancelOpenVPNChallenge(challengeID string) error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	endpoint, err := m.openVPNEndpointLocked()
	if err != nil {
		return err
	}
	current := endpoint.OpenVPNStatus().Challenge
	if current == nil || current.ID != challengeID {
		return errors.New("OpenVPN challenge is no longer active")
	}
	if err := endpoint.CancelChallenge(challengeID); err != nil {
		return err
	}
	m.clearOpenVPNChallengeLocked()
	return nil
}

func (m *Manager) WaitOpenVPNState(timeout time.Duration) OpenVPNStatus {
	deadline := time.Now().Add(timeout)
	for {
		status := m.OpenVPNStatus()
		if status.State == adapter.OpenVPNStateConnected || status.State == adapter.OpenVPNStateAuthPending || status.State == adapter.OpenVPNStateError || time.Now().After(deadline) {
			return status
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (m *Manager) openVPNEndpointLocked() (adapter.OpenVPNEndpoint, error) {
	if m.instance == nil || m.openVPN == nil {
		return nil, ErrCoreNotRunning
	}
	endpoint, found := m.instance.Endpoint().Get(openvpnprofile.EndpointTag)
	if !found {
		return nil, errors.New("OpenVPN endpoint is unavailable")
	}
	openVPNEndpoint, ok := endpoint.(adapter.OpenVPNEndpoint)
	if !ok {
		return nil, fmt.Errorf("OpenVPN endpoint has unexpected type %T", endpoint)
	}
	return openVPNEndpoint, nil
}

func mergeOpenVPNStatus(result OpenVPNStatus, status adapter.OpenVPNStatus) OpenVPNStatus {
	result.State = status.State
	result.Error = status.Error
	if status.Challenge != nil {
		result.Challenge = &OpenVPNChallenge{
			ID:            status.Challenge.ID,
			Kind:          status.Challenge.Kind,
			Username:      status.Challenge.Username,
			Message:       status.Challenge.Message,
			URL:           status.Challenge.URL,
			SecretMessage: status.Challenge.SecretMessage,
			Echo:          status.Challenge.Echo,
			PreviousError: status.Challenge.PreviousError,
			Deadline:      status.Challenge.Deadline.Unix(),
		}
		if status.Challenge.Deadline.IsZero() {
			result.Challenge.Deadline = 0
		}
	}
	if status.TunnelInfo != nil {
		result.Server = status.TunnelInfo.Server
		result.Network = status.TunnelInfo.Network
		result.Cipher = status.TunnelInfo.Cipher
		result.MTU = status.TunnelInfo.MTU
		result.ConnectedAt = status.TunnelInfo.ConnectedSince.Unix()
		for _, prefix := range status.TunnelInfo.IPv4 {
			result.IPv4 = append(result.IPv4, prefix.String())
		}
		for _, prefix := range status.TunnelInfo.IPv6 {
			result.IPv6 = append(result.IPv6, prefix.String())
		}
		for _, address := range status.TunnelInfo.DNS {
			result.DNS = append(result.DNS, address.String())
		}
	}
	return result
}
