package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	M "github.com/sagernet/sing/common/metadata"
)

var ErrCoreNotRunning = errors.New("sing-box core is not running")

var egressInfoURL = "https://ipinfo.io/json"

type ProxyGroup struct {
	Tag      string      `json:"tag"`
	Type     string      `json:"type"`
	Selected string      `json:"selected,omitempty"`
	Items    []ProxyItem `json:"items"`
}

type ProxyItem struct {
	Tag      string `json:"tag"`
	Type     string `json:"type"`
	DelayMs  int    `json:"delay_ms,omitempty"`
	Selected bool   `json:"selected,omitempty"`
}

type PublicProxyStatus struct {
	CoreRunning          bool     `json:"core_running"`
	TUNEnabled           bool     `json:"tun_enabled"`
	ProxyAvailable       bool     `json:"proxy_available"`
	SystemProxyEnabled   bool     `json:"system_proxy_enabled"`
	MixedAddr            string   `json:"mixed_addr,omitempty"`
	DefaultOutbound      string   `json:"default_outbound,omitempty"`
	SelectedOutbound     string   `json:"selected_outbound,omitempty"`
	SelectedType         string   `json:"selected_type,omitempty"`
	Chain                []string `json:"chain,omitempty"`
	SystemTUNInterface   string   `json:"system_tun_interface,omitempty"`
	ExternalTUNs         []string `json:"external_tuns,omitempty"`
	CompatibleTUNs       []string `json:"compatible_tuns,omitempty"`
	PublicRouteConflicts []string `json:"public_route_conflicts,omitempty"`
	DNSMode              string   `json:"dns_mode,omitempty"`
	DNSServers           []string `json:"dns_servers,omitempty"`
	DNSProtected         bool     `json:"dns_protected"`
	DomesticDirect       bool     `json:"domestic_direct"`
	DomesticRuleSets     []string `json:"domestic_rule_sets,omitempty"`
}

func (m *Manager) PublicProxyStatus() PublicProxyStatus {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	ownership := inspectTUNOwnership(m.cfg.TUN.IP)
	status := PublicProxyStatus{
		CoreRunning:          m.instance != nil,
		TUNEnabled:           m.cfg.Core.TUNEnabled && ownership.ownInterface != "",
		MixedAddr:            m.mixedAddr(),
		SystemTUNInterface:   ownership.ownInterface,
		ExternalTUNs:         ownership.externalInterfaces,
		CompatibleTUNs:       ownership.compatibleInterfaces,
		PublicRouteConflicts: ownership.publicRouteConflicts,
		DNSServers:           append([]string(nil), m.cfg.DNS.Upstream...),
		DomesticDirect:       m.cfg.Core.DomesticDirect,
	}
	if m.cfg.Core.DomesticDirect {
		status.DomesticRuleSets = []string{domesticDomainRuleSetTag, domesticIPRuleSetTag}
	}
	if m.instance == nil {
		return status
	}
	current := m.instance.Outbound().Default()
	if current == nil {
		return status
	}
	status.DefaultOutbound = current.Tag()
	seen := make(map[string]bool)
	for current != nil && !seen[current.Tag()] {
		seen[current.Tag()] = true
		status.Chain = append(status.Chain, current.Tag())
		group, isGroup := current.(adapter.OutboundGroup)
		if !isGroup || group.Now() == "" {
			break
		}
		next, found := m.instance.Outbound().Outbound(group.Now())
		if !found {
			break
		}
		current = next
	}
	status.SelectedOutbound = current.Tag()
	status.SelectedType = current.Type()
	status.ProxyAvailable = status.SelectedType != "direct" && status.SelectedType != "block" && status.SelectedType != "corplink"
	status.SystemProxyEnabled = status.CoreRunning && status.TUNEnabled && status.ProxyAvailable && len(status.PublicRouteConflicts) == 0
	if status.ProxyAvailable {
		status.DNSMode = "proxy-doh"
	} else {
		status.DNSMode = "direct-doh"
	}
	status.DNSProtected = status.SystemProxyEnabled && status.DNSMode == "proxy-doh"
	return status
}

type EgressInfo struct {
	IP       string `json:"ip"`
	City     string `json:"city"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	Loc      string `json:"loc"`
	Org      string `json:"org"`
	Timezone string `json:"timezone"`
}

// PublicEgressInfo dials the IP service through the configured public default
// outbound itself. Unlike a normal system request, this probe cannot be
// captured by the corporate route preference and therefore proves which exit
// the selected ISP/public node provides.
func (m *Manager) PublicEgressInfo(ctx context.Context) (EgressInfo, error) {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if m.instance == nil {
		return EgressInfo{}, ErrCoreNotRunning
	}
	outbound := m.instance.Outbound().Default()
	if outbound == nil {
		return EgressInfo{}, errors.New("public default outbound is unavailable")
	}
	return probeEgressInfo(ctx, "selected public outbound", func(ctx context.Context, network, address string) (net.Conn, error) {
		destination := M.ParseSocksaddr(address)
		if !destination.IsValid() {
			return nil, fmt.Errorf("invalid egress probe destination %q", address)
		}
		return outbound.DialContext(ctx, network, destination)
	})
}

// CorporateEgressInfo bypasses every public rule and probes through the active
// CorpLink WireGuard netstack itself. It lets the UI identify a company exit
// without guessing from the selected route-mode switch.
func (m *Manager) CorporateEgressInfo(ctx context.Context) (EgressInfo, error) {
	return probeEgressInfo(ctx, "corporate tunnel", func(ctx context.Context, network, address string) (net.Conn, error) {
		lease, err := m.runtime.Acquire()
		if err != nil {
			return nil, err
		}
		conn, err := lease.Device().Net().DialContext(ctx, network, address)
		if err != nil {
			lease.Release()
			return nil, err
		}
		m.runtime.RecordSuccess()
		return &egressLeaseConn{Conn: conn, release: lease.Release}, nil
	})
}

type egressLeaseConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *egressLeaseConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func probeEgressInfo(ctx context.Context, label string, dial func(context.Context, string, string) (net.Conn, error)) (EgressInfo, error) {
	transport := &http.Transport{DisableKeepAlives: true, DialContext: dial}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, egressInfoURL, nil)
	if err != nil {
		return EgressInfo{}, err
	}
	request.Header.Set("User-Agent", "CrossLink/1")
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return EgressInfo{}, fmt.Errorf("probe %s: %w", label, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
		return EgressInfo{}, fmt.Errorf("probe %s: %s", label, response.Status)
	}
	var result EgressInfo
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&result); err != nil {
		return EgressInfo{}, fmt.Errorf("decode %s: %w", label, err)
	}
	if result.IP == "" {
		return EgressInfo{}, fmt.Errorf("%s returned an empty IP", label)
	}
	return result, nil
}

type selectableGroup interface {
	adapter.OutboundGroup
	SelectOutbound(tag string) bool
}

type proxyDelayStore struct {
	access sync.RWMutex
	values map[string]uint16
}

func (s *proxyDelayStore) replace(values map[string]uint16) {
	s.access.Lock()
	defer s.access.Unlock()
	if s.values == nil {
		s.values = make(map[string]uint16)
	}
	for tag, delay := range values {
		s.values[tag] = delay
	}
}

func (s *proxyDelayStore) clear() {
	s.access.Lock()
	s.values = nil
	s.access.Unlock()
}

func (s *proxyDelayStore) get(tag string) int {
	s.access.RLock()
	defer s.access.RUnlock()
	if delay, found := s.values[tag]; found {
		return int(delay)
	}
	return -1
}

func (m *Manager) ProxyGroups() ([]ProxyGroup, error) {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if m.instance == nil {
		return nil, ErrCoreNotRunning
	}

	outboundManager := m.instance.Outbound()
	var groups []ProxyGroup
	for _, rawOutbound := range outboundManager.Outbounds() {
		group, isGroup := rawOutbound.(adapter.OutboundGroup)
		if !isGroup {
			continue
		}
		selected := group.Now()
		itemTags := group.All()
		items := make([]ProxyItem, 0, len(itemTags))
		for _, tag := range itemTags {
			child, found := outboundManager.Outbound(tag)
			if !found {
				continue
			}
			items = append(items, ProxyItem{
				Tag:      tag,
				Type:     child.Type(),
				DelayMs:  m.proxyDelays.get(tag),
				Selected: tag == selected,
			})
		}
		groups = append(groups, ProxyGroup{
			Tag:      group.Tag(),
			Type:     group.Type(),
			Selected: selected,
			Items:    items,
		})
	}
	return groups, nil
}

func (m *Manager) applyProxySelectionsLocked() {
	if m.instance == nil {
		return
	}
	for groupTag, outboundTag := range m.proxySelections {
		rawGroup, found := m.instance.Outbound().Outbound(groupTag)
		if !found {
			continue
		}
		if selector, selectable := rawGroup.(selectableGroup); selectable {
			selector.SelectOutbound(outboundTag)
		}
	}
}

func (m *Manager) SelectProxy(groupTag, outboundTag string) error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if m.instance == nil {
		return ErrCoreNotRunning
	}
	rawGroup, found := m.instance.Outbound().Outbound(groupTag)
	if !found {
		return fmt.Errorf("proxy group %q not found", groupTag)
	}
	selector, selectable := rawGroup.(selectableGroup)
	if !selectable {
		return fmt.Errorf("proxy group %q is not selectable", groupTag)
	}
	previous := selector.Now()
	if !selector.SelectOutbound(outboundTag) {
		return fmt.Errorf("outbound %q is not in group %q", outboundTag, groupTag)
	}
	if m.proxySelections == nil {
		m.proxySelections = make(map[string]string)
	}
	previousStored, hadStored := m.proxySelections[groupTag]
	m.proxySelections[groupTag] = outboundTag
	if err := saveProxySelections(m.cfg, m.proxySelections); err != nil {
		selector.SelectOutbound(previous)
		if hadStored {
			m.proxySelections[groupTag] = previousStored
		} else {
			delete(m.proxySelections, groupTag)
		}
		return fmt.Errorf("persist proxy selection: %w", err)
	}
	return nil
}

func (m *Manager) TestProxyGroup(groupTag string) (map[string]uint16, error) {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if m.instance == nil {
		return nil, ErrCoreNotRunning
	}
	rawGroup, found := m.instance.Outbound().Outbound(groupTag)
	if !found {
		return nil, fmt.Errorf("proxy group %q not found", groupTag)
	}
	group, isGroup := rawGroup.(adapter.OutboundGroup)
	if !isGroup {
		return nil, fmt.Errorf("outbound %q is not a proxy group", groupTag)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if urlTestGroup, testable := rawGroup.(adapter.URLTestGroup); testable {
		delays, err := urlTestGroup.URLTest(ctx)
		if err != nil {
			return nil, err
		}
		if len(delays) > 0 {
			m.proxyDelays.replace(delays)
			return delays, nil
		}
		// A just-started urltest group can report an empty aggregate before its
		// worker publishes results. Fall through to explicit child probes so a
		// user click never succeeds with an empty delay map.
	}

	delays := make(map[string]uint16, len(group.All()))
	var access sync.Mutex
	var workers sync.WaitGroup
	for _, tag := range group.All() {
		child, loaded := m.instance.Outbound().Outbound(tag)
		if !loaded {
			continue
		}
		workers.Add(1)
		go func(outboundTag string, detour adapter.Outbound) {
			defer workers.Done()
			delay, testErr := urltest.URLTest(ctx, "", detour)
			if testErr != nil {
				delay = ^uint16(0)
			}
			access.Lock()
			delays[outboundTag] = delay
			access.Unlock()
		}(tag, child)
	}
	workers.Wait()
	m.proxyDelays.replace(delays)
	return delays, nil
}
