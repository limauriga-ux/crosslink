package corpendpoint

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/limauriga-ux/crosslink/internal/wgdevice"
	"go4.org/netipx"
	"golang.org/x/net/publicsuffix"
)

var ErrUnavailable = errors.New("corporate tunnel is unavailable")

const retiredGenerationGrace = 5 * time.Minute

type RoutePolicyStats struct {
	EffectiveRoutes       int
	EffectiveDomains      int
	IgnoredPublicRoutes   int
	IgnoredPublicSuffixes int
}

type routeSnapshot struct {
	fullTunnel     bool
	prefixes       *netipx.IPSet
	domains        []string
	dnsServers     []netip.Addr
	stats          RoutePolicyStats
	dnsEnvironment string
}

type publicAuthSnapshot struct {
	domain         string
	address        netip.Addr
	deadline       int64
	dnsEnvironment string
}

// openVPNClaimSnapshot holds the explicit OpenVPN profile's static routes and
// split-DNS domains. CorpLink's server-pushed claims must never shadow them:
// when both tunnels claim the same company segment, the user-imported OpenVPN
// profile is the explicit policy and wins.
type openVPNClaimSnapshot struct {
	prefixes *netipx.IPSet
	domains  []string
}

type generation struct {
	device    *wgdevice.Device
	refs      atomic.Int64
	retired   atomic.Bool
	closeOnce sync.Once
}

func (g *generation) acquire() bool {
	if g == nil || g.retired.Load() {
		return false
	}
	g.refs.Add(1)
	if g.retired.Load() {
		g.release()
		return false
	}
	return true
}

func (g *generation) release() {
	if g.refs.Add(-1) == 0 && g.retired.Load() {
		g.close()
	}
}

func (g *generation) retire() {
	if g == nil || !g.retired.CompareAndSwap(false, true) {
		return
	}
	if g.refs.Load() == 0 {
		g.close()
		return
	}
	time.AfterFunc(retiredGenerationGrace, g.close)
}

func (g *generation) close() {
	g.closeOnce.Do(func() {
		if g.device != nil {
			g.device.Close()
		}
	})
}

// Lease pins one WireGuard generation while a dial or DNS exchange is being
// established. Long-lived connections transfer the release callback to their
// connection wrapper, so a make-before-break replacement cannot close their
// userspace netstack underneath them.
type Lease struct {
	generation *generation
	released   atomic.Bool
}

func (l *Lease) Device() *wgdevice.Device {
	if l == nil || l.generation == nil {
		return nil
	}
	return l.generation.device
}

func (l *Lease) Release() {
	if l == nil || l.generation == nil || !l.released.CompareAndSwap(false, true) {
		return
	}
	l.generation.release()
}

// Runtime owns the active CorpLink WireGuard generation and a separate route
// snapshot. Routes deliberately survive a tunnel outage: known corporate names
// continue to select the corporate endpoint and fail closed instead of leaking
// to DIRECT or a public proxy.
type Runtime struct {
	current       atomic.Pointer[generation]
	routes        atomic.Pointer[routeSnapshot]
	publicAuth    atomic.Pointer[publicAuthSnapshot]
	openVPNClaims atomic.Pointer[openVPNClaimSnapshot]
	authPolicyMu  sync.Mutex
	routeEpoch    atomic.Uint64
	lastSuccess   atomic.Int64
}

func NewRuntime() *Runtime {
	r := &Runtime{}
	r.routes.Store(&routeSnapshot{prefixes: emptyIPSet(), dnsEnvironment: "0"})
	r.publicAuth.Store(&publicAuthSnapshot{dnsEnvironment: "0"})
	return r
}

func emptyIPSet() *netipx.IPSet {
	var builder netipx.IPSetBuilder
	set, _ := builder.IPSet()
	return set
}

func (r *Runtime) Acquire() (*Lease, error) {
	for {
		current := r.current.Load()
		if current == nil {
			return nil, ErrUnavailable
		}
		if current.acquire() {
			return &Lease{generation: current}, nil
		}
	}
}

// Adopt atomically publishes a fully initialized userspace WireGuard device.
// Existing flows may finish on the old generation; new flows use next.
func (r *Runtime) Adopt(next *wgdevice.Device, routes, domains []string, dnsServers []netip.Addr, fullTunnel bool) {
	r.UpdateRoutes(routes, domains, dnsServers, fullTunnel)
	old := r.current.Swap(&generation{device: next})
	old.retire()
}

// Deactivate removes the active data plane but retains the last route snapshot
// to preserve fail-closed classification during reconnect or logout.
func (r *Runtime) Deactivate() {
	old := r.current.Swap(nil)
	old.retire()
}

func (r *Runtime) Close() {
	r.Deactivate()
}

func (r *Runtime) UpdateRoutes(routes, domains []string, dnsServers []netip.Addr, fullTunnel bool) {
	dnsEnvironment := strconv.FormatUint(r.routeEpoch.Add(1), 10)
	var builder netipx.IPSetBuilder
	stats := RoutePolicyStats{}
	for _, raw := range routes {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		prefix = prefix.Masked()
		// CorpLink often resolves protected SaaS domains into public CDN IPs
		// and returns those shared addresses as split routes. Routing by those
		// addresses captures unrelated tenants (for example IP check sites on
		// the same Cloudflare edge). In split mode, public corporate services
		// are selected by their domain suffix; only non-public network ranges
		// are safe as address rules. Full-tunnel mode still matches everything.
		if !fullTunnel && !isNonPublicSplitPrefix(prefix) {
			stats.IgnoredPublicRoutes++
			continue
		}
		builder.AddPrefix(prefix)
		stats.EffectiveRoutes++
	}
	for _, address := range dnsServers {
		if address.IsValid() {
			builder.AddPrefix(netip.PrefixFrom(address, address.BitLen()))
		}
	}
	prefixes, err := builder.IPSet()
	if err != nil {
		prefixes = emptyIPSet()
	}

	canonicalDomains := make([]string, 0, len(domains))
	seen := make(map[string]struct{}, len(domains))
	for _, raw := range domains {
		domain := canonicalDomain(raw)
		if domain == "" {
			continue
		}
		if suffix, icann := publicsuffix.PublicSuffix(domain); icann && suffix == domain {
			stats.IgnoredPublicSuffixes++
			continue
		}
		if _, exists := seen[domain]; exists {
			continue
		}
		seen[domain] = struct{}{}
		canonicalDomains = append(canonicalDomains, domain)
		stats.EffectiveDomains++
	}
	r.routes.Store(&routeSnapshot{
		fullTunnel:     fullTunnel,
		prefixes:       prefixes,
		domains:        canonicalDomains,
		dnsServers:     append([]netip.Addr(nil), dnsServers...),
		stats:          stats,
		dnsEnvironment: dnsEnvironment,
	})
}

// DNSEnvironment changes whenever corporate routes or the transient public
// authentication scope changes. Expiry changes the cache key without relying
// on a UI/status poll, so a post-challenge query cannot reuse a public answer.
func (r *Runtime) DNSEnvironment() []string {
	routeSnapshot := r.routes.Load()
	authSnapshot := r.publicAuth.Load()
	if routeSnapshot == nil || authSnapshot == nil {
		return nil
	}
	authEnvironment := authSnapshot.dnsEnvironment
	if authSnapshot.expired(time.Now().Unix()) {
		authEnvironment += ":expired"
	}
	return []string{routeSnapshot.dnsEnvironment, authEnvironment}
}

// SetPublicAuthScope atomically replaces the one managed domain suffix or
// exact remote IP that browser HTTPS traffic may route through the public
// outbound while an OpenVPN OAuth challenge is live. An empty scope clears it.
func (r *Runtime) SetPublicAuthScope(scope string, deadline int64) bool {
	r.authPolicyMu.Lock()
	defer r.authPolicyMu.Unlock()

	rawScope := strings.Trim(strings.TrimSpace(scope), "[]")
	address, addressErr := netip.ParseAddr(rawScope)
	domain := ""
	if addressErr == nil && address.IsValid() {
		address = address.Unmap()
	} else {
		address = netip.Addr{}
		domain = canonicalDomain(rawScope)
	}
	if domain == "" && !address.IsValid() {
		deadline = 0
	}
	current := r.publicAuth.Load()
	if current != nil && current.domain == domain && current.address == address && current.deadline == deadline {
		return false
	}
	r.publicAuth.Store(&publicAuthSnapshot{
		domain:         domain,
		address:        address,
		deadline:       deadline,
		dnsEnvironment: strconv.FormatUint(r.routeEpoch.Add(1), 10),
	})
	return true
}

// ExtendPublicAuthDeadline keeps an already armed scope usable while the
// OpenVPN server rotates an expired browser challenge. It never broadens the
// scope, revives a cleared scope, or shortens a non-expiring/later deadline.
func (r *Runtime) ExtendPublicAuthDeadline(deadline int64) bool {
	if deadline <= 0 {
		return false
	}
	r.authPolicyMu.Lock()
	defer r.authPolicyMu.Unlock()

	current := r.publicAuth.Load()
	if current == nil || current.deadline == 0 || current.deadline >= deadline || current.domain == "" && !current.address.IsValid() {
		return false
	}
	r.publicAuth.Store(&publicAuthSnapshot{
		domain:         current.domain,
		address:        current.address,
		deadline:       deadline,
		dnsEnvironment: current.dnsEnvironment,
	})
	return true
}

func (s *publicAuthSnapshot) expired(now int64) bool {
	return s != nil && s.deadline > 0 && now >= s.deadline
}

func (r *Runtime) MatchPublicAuthDomain(domain string) bool {
	snapshot := r.publicAuth.Load()
	if snapshot == nil || snapshot.expired(time.Now().Unix()) || snapshot.domain == "" {
		return false
	}
	domain = canonicalDomain(domain)
	return domain == snapshot.domain || strings.HasSuffix(domain, "."+snapshot.domain)
}

func (r *Runtime) MatchPublicAuthAddress(address netip.Addr) bool {
	snapshot := r.publicAuth.Load()
	return snapshot != nil && !snapshot.expired(time.Now().Unix()) && snapshot.address.IsValid() && address.IsValid() && snapshot.address == address.Unmap()
}

func (r *Runtime) PolicyStats() RoutePolicyStats {
	snapshot := r.routes.Load()
	if snapshot == nil {
		return RoutePolicyStats{}
	}
	return snapshot.stats
}

var nonPublicSplitPrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

func isNonPublicSplitPrefix(prefix netip.Prefix) bool {
	for _, allowed := range nonPublicSplitPrefixes {
		if allowed.Addr().BitLen() == prefix.Addr().BitLen() &&
			prefix.Bits() >= allowed.Bits() && allowed.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

// SetOpenVPNClaims publishes the explicit OpenVPN profile claims that the
// CorpLink endpoint must yield to. An empty claim set restores full CorpLink
// ownership. Claims follow the profile's configured state, matching the
// lifetime of the static OpenVPN route rules in the compiled core.
func (r *Runtime) SetOpenVPNClaims(routes, domains []string) {
	if len(routes) == 0 && len(domains) == 0 {
		r.openVPNClaims.Store(nil)
		return
	}
	var builder netipx.IPSetBuilder
	for _, raw := range routes {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		builder.AddPrefix(prefix.Masked())
	}
	prefixes, err := builder.IPSet()
	if err != nil {
		prefixes = emptyIPSet()
	}
	canonical := make([]string, 0, len(domains))
	for _, raw := range domains {
		if domain := canonicalDomain(raw); domain != "" {
			canonical = append(canonical, domain)
		}
	}
	slices.Sort(canonical)
	canonical = slices.Compact(canonical)
	r.openVPNClaims.Store(&openVPNClaimSnapshot{prefixes: prefixes, domains: canonical})
}

func (r *Runtime) openVPNClaimsDomain(domain string) bool {
	snapshot := r.openVPNClaims.Load()
	if snapshot == nil {
		return false
	}
	domain = canonicalDomain(domain)
	if domain == "" {
		return false
	}
	for _, suffix := range snapshot.domains {
		if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
			return true
		}
	}
	return false
}

func (r *Runtime) openVPNClaimsAddress(address netip.Addr) bool {
	snapshot := r.openVPNClaims.Load()
	return snapshot != nil && address.IsValid() && snapshot.prefixes.Contains(address)
}

func (r *Runtime) MatchDomain(domain string) bool {
	if r.openVPNClaimsDomain(domain) {
		return false
	}
	snapshot := r.routes.Load()
	if snapshot == nil {
		return false
	}
	return snapshot.fullTunnel || matchCorporateDomain(snapshot, domain)
}

// MatchCorporateDomain ignores full-tunnel mode and is used for split DNS:
// public names still resolve through public DNS before their resulting IP is
// sent through a full corporate tunnel.
func (r *Runtime) MatchCorporateDomain(domain string) bool {
	return matchCorporateDomain(r.routes.Load(), domain)
}

func matchCorporateDomain(snapshot *routeSnapshot, domain string) bool {
	if snapshot == nil {
		return false
	}
	domain = canonicalDomain(domain)
	if domain == "" {
		return false
	}
	for _, suffix := range snapshot.domains {
		if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
			return true
		}
	}
	return false
}

func (r *Runtime) MatchAddress(address netip.Addr) bool {
	if r.openVPNClaimsAddress(address) {
		return false
	}
	snapshot := r.routes.Load()
	if snapshot == nil || !address.IsValid() {
		return false
	}
	return snapshot.fullTunnel || snapshot.prefixes.Contains(address)
}

func (r *Runtime) DNSServers() []netip.Addr {
	snapshot := r.routes.Load()
	if snapshot == nil {
		return nil
	}
	return append([]netip.Addr(nil), snapshot.dnsServers...)
}

func (r *Runtime) Stats() (wgdevice.Stats, error) {
	lease, err := r.Acquire()
	if err != nil {
		return wgdevice.Stats{}, err
	}
	defer lease.Release()
	return lease.Device().GetStats()
}

func (r *Runtime) TunnelReachable(ctx context.Context) bool {
	lease, err := r.Acquire()
	if err != nil {
		return false
	}
	defer lease.Release()
	return lease.Device().TunnelReachable(ctx)
}

func (r *Runtime) RecordSuccess() {
	r.lastSuccess.Store(time.Now().Unix())
}

func (r *Runtime) LastSuccessUnix() int64 {
	return r.lastSuccess.Load()
}

func canonicalDomain(domain string) string {
	domain = strings.Trim(strings.ToLower(strings.TrimSpace(domain)), ".")
	return strings.TrimPrefix(domain, "*.")
}

// leasedConn releases its WireGuard generation when the flow closes.
type leasedConn struct {
	net.Conn
	lease *Lease
	once  sync.Once
}

func (c *leasedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.lease.Release)
	return err
}

// leasedPacketConn is the packet equivalent of leasedConn.
type leasedPacketConn struct {
	net.PacketConn
	lease *Lease
	once  sync.Once
}

func (c *leasedPacketConn) Close() error {
	err := c.PacketConn.Close()
	c.once.Do(c.lease.Release)
	return err
}
