package core

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	appconfig "github.com/limauriga-ux/crosslink/internal/config"
	"github.com/limauriga-ux/crosslink/internal/corpendpoint"
	"github.com/limauriga-ux/crosslink/internal/netroute"
	"github.com/limauriga-ux/crosslink/internal/wgdevice"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

const (
	probeInterval         = 30 * time.Second
	probeTimeout          = 5 * time.Second
	probeFailureThreshold = 3
	initialHandshakeGrace = 60 * time.Second
	handshakeStaleAfter   = 5 * time.Minute
	recentTrafficWindow   = 60 * time.Second
)

// ConnectConfig contains the dynamic CorpLink configuration returned by the
// selected gateway. sing-box owns system capture; this object configures only
// the corporate endpoint and its dynamic routing preference.
type ConnectConfig struct {
	WG                wgdevice.Config
	SplitRoutes       []string
	DomainSuffixes    []string
	PhysicalIface     string
	ServerIP          string
	FollowSplitRoutes bool
}

type Status struct {
	Connected                     bool
	Reconnecting                  bool
	NodeName                      string
	VpnIP                         string
	DNS                           string
	Protocol                      string
	ConnectedAt                   int64
	MixedAddr                     string
	RouteModeKnown                bool
	FollowSplitRoutes             bool
	CorporateRouteCount           int
	CorporateDomainCount          int
	CorporateIgnoredPublicRoutes  int
	CorporateIgnoredPublicDomains int
}

type ProbeStats struct {
	Cycles              int64
	Failures            int64
	Consecutive         int32
	Threshold           int32
	DNSFlakySkips       int64
	HostStallSkips      int64
	LastCycleUnix       int64
	LastOutcome         string
	TotalCycles         int64
	TotalFailures       int64
	TotalDNSFlakySkips  int64
	TotalHostStallSkips int64
	TrafficVetoes       int64
	TotalTrafficVetoes  int64
	LastTunnelOKUnix    int64
	LastDeadReason      string
	LastDeadAt          int64
}

type probeState struct {
	cycles      atomic.Int64
	failures    atomic.Int64
	consecutive atomic.Int64
	lastAt      atomic.Int64
	lastOutcome atomic.Value
}

// Manager coordinates one embedded sing-box instance and the replaceable
// CorpLink endpoint generation. Public proxy traffic remains alive while the
// corporate endpoint reconnects.
type Manager struct {
	lifecycleMu sync.Mutex
	mu          sync.Mutex
	cfg         *appconfig.Config
	runtime     *corpendpoint.Runtime
	instance    *box.Box
	cancelCore  context.CancelFunc
	coreRunning atomic.Bool
	// openVPN is guarded by lifecycleMu. Credentials exist only in daemon
	// memory and are never exposed by status or serialized to disk.
	openVPN *openVPNRuntimeConfig

	openVPNChallengeID      string
	openVPNChallengeURL     string
	openVPNChallengeGraceID string

	status          Status
	reconnecting    bool
	lastFollow      bool
	lastValid       bool
	lastRoutes      []string
	lastDomains     []string
	lastDNS         []netip.Addr
	lastRx          int64
	probe           probeState
	proxySelections map[string]string
	proxyDelays     proxyDelayStore
	probeStop       chan struct{}
	probeDone       chan struct{}
	lastDeadAt      atomic.Int64
	lastDeadWhy     atomic.Value
}

func New(cfg *appconfig.Config) *Manager {
	m := &Manager{
		cfg:             cfg,
		runtime:         corpendpoint.NewRuntime(),
		proxySelections: loadProxySelections(cfg),
	}
	m.probe.lastOutcome.Store("")
	m.lastDeadWhy.Store("")
	return m
}

// Start brings up the sing-box TUN and public proxy graph before CorpLink is
// connected. The corporate endpoint can be adopted later without restarting
// the core.
func (m *Manager) Start() error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if m.instance != nil {
		return nil
	}
	return m.startCoreLocked()
}

func (m *Manager) Connect(nodeName string, cc ConnectConfig) error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()

	if cc.ServerIP != "" && cc.PhysicalIface != "" {
		if err := netroute.AddScopedHostRoute(cc.ServerIP, cc.PhysicalIface); err != nil {
			return fmt.Errorf("pin corporate gateway %s to %s: %w", cc.ServerIP, cc.PhysicalIface, err)
		}
	}

	device, err := wgdevice.New(cc.WG)
	if err != nil {
		return fmt.Errorf("create corporate WireGuard device: %w", err)
	}

	m.lastRoutes = append([]string(nil), cc.SplitRoutes...)
	m.lastDomains = append([]string(nil), cc.DomainSuffixes...)
	m.lastDNS = append([]netip.Addr(nil), cc.WG.DNSServers...)
	m.lastFollow = cc.FollowSplitRoutes
	m.lastValid = true
	m.runtime.UpdateRoutes(m.lastRoutes, m.lastDomains, m.lastDNS, !cc.FollowSplitRoutes)
	policyStats := m.runtime.PolicyStats()

	if m.instance == nil {
		if err := m.startCoreLocked(); err != nil {
			device.Close()
			return err
		}
	}
	m.runtime.Adopt(device, m.lastRoutes, m.lastDomains, m.lastDNS, !cc.FollowSplitRoutes)
	m.restartProbeLocked()

	protocol := "UDP"
	if cc.WG.ProtocolMode == 2 {
		protocol = "TCP"
	}
	dnsServer := ""
	if len(cc.WG.DNSServers) > 0 {
		dnsServer = cc.WG.DNSServers[0].String()
	}
	m.mu.Lock()
	m.status = Status{
		Connected:                     true,
		Reconnecting:                  m.reconnecting,
		NodeName:                      nodeName,
		VpnIP:                         cc.WG.VpnIP.String(),
		DNS:                           dnsServer,
		Protocol:                      protocol,
		ConnectedAt:                   time.Now().Unix(),
		MixedAddr:                     m.mixedAddr(),
		RouteModeKnown:                true,
		FollowSplitRoutes:             cc.FollowSplitRoutes,
		CorporateRouteCount:           policyStats.EffectiveRoutes,
		CorporateDomainCount:          policyStats.EffectiveDomains,
		CorporateIgnoredPublicRoutes:  policyStats.IgnoredPublicRoutes,
		CorporateIgnoredPublicDomains: policyStats.IgnoredPublicSuffixes,
	}
	m.mu.Unlock()
	m.lastRx = 0
	log.Printf("[core] unified network active: node=%s corp=%s public=%s", nodeName, protocol, m.mixedAddr())
	return nil
}

func (m *Manager) startCoreLocked() error {
	if err := m.cfg.Validate(); err != nil {
		return fmt.Errorf("validate core config: %w", err)
	}
	if err := validateConfiguredTUNAvailability(m.cfg, ""); err != nil {
		return err
	}
	compileConfig := m.cfg
	if m.cfg.Core.TUNEnabled && m.cfg.DirectOutbound.Interface == "" {
		resolved, err := detectPhysicalInterface()
		if err != nil {
			return fmt.Errorf("resolve physical interface for bootstrap DNS: %w", err)
		}
		configCopy := *m.cfg
		configCopy.DirectOutbound.Interface = resolved
		compileConfig = &configCopy
	}
	compiled, err := compileConfigWithOpenVPN(compileConfig, m.openVPN)
	if err != nil {
		return err
	}

	registries := newRegistries(m.runtime)
	ctx, cancel := context.WithCancel(context.Background())
	ctx = registries.context(ctx)
	options, err := singjson.UnmarshalExtendedContext[option.Options](ctx, compiled.content)
	if err != nil {
		cancel()
		return fmt.Errorf("parse generated sing-box configuration: %w", err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		cancel()
		return fmt.Errorf("create sing-box core: %w", err)
	}
	if err := instance.Start(); err != nil {
		_ = instance.Close()
		cancel()
		return fmt.Errorf("start sing-box core: %w", err)
	}
	m.instance = instance
	m.applyProxySelectionsLocked()
	if err := guardSystemCapture(m.cfg.Core.TUNEnabled, func() error {
		return runStartupProbe(
			ctx,
			instance.Outbound(),
			service.FromContext[adapter.DNSTransportManager](ctx),
			service.FromContext[adapter.DNSRouter](ctx),
		)
	}, instance.Close); err != nil {
		m.instance = nil
		cancel()
		return err
	}
	m.coreRunning.Store(true)
	m.proxyDelays.clear()
	m.cancelCore = cancel
	log.Printf("[core] sing-box started: final=%s outbounds=%v tun=%v mixed=%s", compiled.defaultRoute, compiled.outboundTags, m.cfg.Core.TUNEnabled, m.mixedAddr())
	return nil
}

func validateConfiguredTUNAvailability(cfg *appconfig.Config, allowedName string) error {
	if cfg == nil || !cfg.Core.TUNEnabled || strings.TrimSpace(cfg.TUN.Name) == "" || strings.TrimSpace(cfg.TUN.Name) == allowedName {
		return nil
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("list network interfaces: %w", err)
	}
	return validateConfiguredTUNAvailabilityFrom(cfg, allowedName, interfaces)
}

func validateConfiguredTUNAvailabilityFrom(cfg *appconfig.Config, allowedName string, interfaces []net.Interface) error {
	if cfg == nil || !cfg.Core.TUNEnabled {
		return nil
	}
	name := strings.TrimSpace(cfg.TUN.Name)
	if name == "" || name == allowedName {
		return nil
	}
	for _, networkInterface := range interfaces {
		if networkInterface.Name == name {
			return fmt.Errorf("configured TUN interface %s is already in use; clear tun.name to allocate an available utun automatically", name)
		}
	}
	return nil
}

func guardSystemCapture(tunEnabled bool, probe func() error, closeCore func() error) error {
	if !tunEnabled {
		return nil
	}
	if err := probe(); err != nil {
		closeErr := closeCore()
		if closeErr != nil {
			return fmt.Errorf("startup network preflight failed: %v; close TUN: %w", err, closeErr)
		}
		return fmt.Errorf("startup network preflight failed; TUN rolled back: %w", err)
	}
	return nil
}

func (m *Manager) stopCoreLocked() error {
	instance := m.instance
	cancel := m.cancelCore
	m.instance = nil
	m.coreRunning.Store(false)
	m.cancelCore = nil
	m.clearOpenVPNChallengeLocked()
	var err error
	if instance != nil {
		err = instance.Close()
	}
	if cancel != nil {
		cancel()
	}
	return err
}

func (m *Manager) Reload(cfg *appconfig.Config) error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("validate core reload: %w", err)
	}
	allowedTUN := ""
	if m.instance != nil {
		allowedTUN = inspectTUNOwnership(m.cfg.TUN.IP).ownInterface
	}
	if err := validateConfiguredTUNAvailability(cfg, allowedTUN); err != nil {
		return fmt.Errorf("validate core reload: %w", err)
	}

	// Compile before touching the live core. A malformed profile or unusable
	// bundled rule-set cache must not tear down working public connectivity.
	if _, err := compileConfigWithOpenVPN(cfg, m.openVPN); err != nil {
		return fmt.Errorf("validate core reload: %w", err)
	}

	previousConfig := m.cfg
	previousSelections := m.proxySelections
	m.cfg = cfg
	m.proxySelections = loadProxySelections(cfg)
	if m.instance == nil {
		if err := m.startCoreLocked(); err != nil {
			m.cfg = previousConfig
			m.proxySelections = previousSelections
			return err
		}
		return nil
	}
	if err := m.stopCoreLocked(); err != nil {
		m.cfg = previousConfig
		m.proxySelections = previousSelections
		return fmt.Errorf("stop core for reload: %w", err)
	}
	if err := m.startCoreLocked(); err != nil {
		m.cfg = previousConfig
		m.proxySelections = previousSelections
		if recoveryErr := m.startCoreLocked(); recoveryErr != nil {
			return fmt.Errorf("start reloaded core: %v; recover previous core: %w", err, recoveryErr)
		}
		return fmt.Errorf("start reloaded core: %w; previous core restored", err)
	}
	return nil
}

func (m *Manager) Disconnect() error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	m.stopProbeLocked()
	m.runtime.Deactivate()
	m.openVPN = nil
	m.syncOpenVPNClaimsLocked()
	err := m.stopCoreLocked()
	m.mu.Lock()
	m.status = Status{}
	m.reconnecting = false
	m.mu.Unlock()
	return err
}

// DisconnectForReconnect removes only the corporate generation. The sing-box
// TUN and public proxy graph stay alive, so a CorpLink outage does not become a
// whole-machine internet outage.
func (m *Manager) DisconnectForReconnect() (bool, error) {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	m.stopProbeLocked()
	m.runtime.Deactivate()
	m.mu.Lock()
	m.status.Connected = false
	m.status.Reconnecting = true
	m.reconnecting = true
	m.mu.Unlock()
	return m.instance != nil, nil
}

func (m *Manager) GetStatus() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	status := m.status
	status.Reconnecting = m.reconnecting
	if status.MixedAddr == "" && m.coreRunning.Load() {
		status.MixedAddr = m.mixedAddr()
	}
	return status
}

func (m *Manager) SetReconnecting(value bool) {
	m.mu.Lock()
	m.reconnecting = value
	m.status.Reconnecting = value
	m.mu.Unlock()
}

func (m *Manager) SetFollowSplitRoutes(value bool) {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	m.lastFollow = value
	m.lastValid = true
	m.runtime.UpdateRoutes(m.lastRoutes, m.lastDomains, m.lastDNS, !value)
	policyStats := m.runtime.PolicyStats()
	m.mu.Lock()
	m.status.RouteModeKnown = true
	m.status.FollowSplitRoutes = value
	m.status.CorporateRouteCount = policyStats.EffectiveRoutes
	m.status.CorporateDomainCount = policyStats.EffectiveDomains
	m.status.CorporateIgnoredPublicRoutes = policyStats.IgnoredPublicRoutes
	m.status.CorporateIgnoredPublicDomains = policyStats.IgnoredPublicSuffixes
	m.mu.Unlock()
	log.Printf("[core] corporate route mode updated: split=%v routes=%d domains=%d ignored_public_routes=%d ignored_public_suffixes=%d", value, policyStats.EffectiveRoutes, policyStats.EffectiveDomains, policyStats.IgnoredPublicRoutes, policyStats.IgnoredPublicSuffixes)
}

func (m *Manager) UpdateSplitRoutes(routes, domains []string) {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	m.lastRoutes = append([]string(nil), routes...)
	m.lastDomains = append([]string(nil), domains...)
	m.runtime.UpdateRoutes(m.lastRoutes, m.lastDomains, m.lastDNS, !m.lastFollow)
	policyStats := m.runtime.PolicyStats()
	m.mu.Lock()
	m.status.CorporateRouteCount = policyStats.EffectiveRoutes
	m.status.CorporateDomainCount = policyStats.EffectiveDomains
	m.status.CorporateIgnoredPublicRoutes = policyStats.IgnoredPublicRoutes
	m.status.CorporateIgnoredPublicDomains = policyStats.IgnoredPublicSuffixes
	m.mu.Unlock()
}

func (m *Manager) LastFollowSplitRoutes() (followSplitRoutes, ok bool) {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	return m.lastFollow, m.lastValid
}

func (m *Manager) GetStats() wgdevice.Stats {
	stats, err := m.runtime.Stats()
	if err != nil {
		return wgdevice.Stats{}
	}
	return stats
}

func (m *Manager) IsConnectionDead() bool {
	status := m.GetStatus()
	if !status.Connected {
		return false
	}
	if lastSuccess := m.runtime.LastSuccessUnix(); lastSuccess > 0 && time.Since(time.Unix(lastSuccess, 0)) <= recentTrafficWindow {
		m.probe.consecutive.Store(0)
		return false
	}
	if m.probe.consecutive.Load() >= probeFailureThreshold {
		m.recordDead("corporate data-plane probe failed")
		return true
	}
	stats, err := m.runtime.Stats()
	if err != nil {
		return false
	}
	now := time.Now()
	connectedAt := time.Unix(status.ConnectedAt, 0)
	if stats.LastHandshakeSec == 0 {
		if now.Sub(connectedAt) > initialHandshakeGrace {
			m.recordDead("WireGuard never completed its initial handshake")
			return true
		}
		return false
	}
	if now.Sub(time.Unix(stats.LastHandshakeSec, 0)) > handshakeStaleAfter && stats.RxBytes == m.lastRx {
		m.recordDead("WireGuard handshake and receive counters are stale")
		return true
	}
	m.lastRx = stats.RxBytes
	return false
}

func (m *Manager) recordDead(reason string) {
	m.lastDeadAt.Store(time.Now().Unix())
	m.lastDeadWhy.Store(reason)
}

func (m *Manager) ProbeStats() ProbeStats {
	lastOutcome, _ := m.probe.lastOutcome.Load().(string)
	lastReason, _ := m.lastDeadWhy.Load().(string)
	return ProbeStats{
		Cycles:           m.probe.cycles.Load(),
		Failures:         m.probe.failures.Load(),
		Consecutive:      int32(m.probe.consecutive.Load()),
		Threshold:        int32(probeFailureThreshold),
		LastCycleUnix:    m.probe.lastAt.Load(),
		LastOutcome:      lastOutcome,
		TotalCycles:      m.probe.cycles.Load(),
		TotalFailures:    m.probe.failures.Load(),
		LastTunnelOKUnix: m.runtime.LastSuccessUnix(),
		LastDeadReason:   lastReason,
		LastDeadAt:       m.lastDeadAt.Load(),
	}
}

func (m *Manager) restartProbeLocked() {
	m.stopProbeLocked()
	stop := make(chan struct{})
	done := make(chan struct{})
	m.probeStop = stop
	m.probeDone = done
	m.probe.consecutive.Store(0)
	go m.probeLoop(stop, done)
}

func (m *Manager) stopProbeLocked() {
	if m.probeStop == nil {
		return
	}
	close(m.probeStop)
	<-m.probeDone
	m.probeStop = nil
	m.probeDone = nil
}

func (m *Manager) probeLoop(stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
			alive := m.runtime.TunnelReachable(ctx)
			cancel()
			m.probe.cycles.Add(1)
			m.probe.lastAt.Store(time.Now().Unix())
			if alive {
				m.probe.consecutive.Store(0)
				m.probe.lastOutcome.Store("ok")
				continue
			}
			m.probe.failures.Add(1)
			m.probe.consecutive.Add(1)
			m.probe.lastOutcome.Store("failed")
		}
	}
}

func (m *Manager) mixedAddr() string {
	if m.cfg == nil || m.cfg.Core.MixedPort <= 0 {
		return ""
	}
	return net.JoinHostPort("127.0.0.1", fmt.Sprint(m.cfg.Core.MixedPort))
}
