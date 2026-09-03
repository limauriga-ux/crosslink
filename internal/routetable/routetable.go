package routetable

import (
	"net"
	"sync"
	"time"
)

// RouteTable provides cached route lookups with OS-event-driven refresh + TTL fallback.
type RouteTable struct {
	skipIface string        // our TUN interface name — excluded from results
	ttl       time.Duration // fallback refresh interval
	table     Table
	mu        sync.Mutex
	lastFetch time.Time
	stopWatch func()
	onRefresh func() // called after each successful table refresh
}

// New creates a new RouteTable. skipIface is the TUN interface name to exclude.
// ttl is the fallback cache refresh interval when no OS event is received.
func New(skipIface string, ttl time.Duration) *RouteTable {
	return &RouteTable{skipIface: skipIface, ttl: ttl}
}

// OnRefresh registers a callback invoked after each successful route table refresh.
// Used by the forwarder to flush its host-route cache when the underlying topology changes.
func (rt *RouteTable) OnRefresh(fn func()) {
	rt.mu.Lock()
	rt.onRefresh = fn
	rt.mu.Unlock()
}

// Start fetches the initial routing table snapshot and starts the OS watcher.
func (rt *RouteTable) Start() error {
	if err := rt.refresh(); err != nil {
		return err
	}
	stop, err := startWatcher(func() {
		rt.mu.Lock()
		rt.lastFetch = time.Time{} // invalidate
		rt.mu.Unlock()
		rt.refresh() //nolint:errcheck
	})
	if err != nil {
		// watcher failed — TTL fallback only
		return nil
	}
	rt.stopWatch = stop
	return nil
}

// RefreshNow invalidates the cached snapshot and synchronously refreshes it.
// Callers that need to observe topology changes without issuing a route Lookup
// use this instead of relying solely on the OS watcher.
func (rt *RouteTable) RefreshNow() error {
	rt.mu.Lock()
	rt.lastFetch = time.Time{}
	rt.mu.Unlock()
	return rt.refresh()
}

// Stop shuts down the OS watcher.
func (rt *RouteTable) Stop() {
	if rt.stopWatch != nil {
		rt.stopWatch()
	}
}

// SetSkipIface updates the interface excluded from monitored route entries and
// invalidates the cache so the next lookup uses the new value.
func (rt *RouteTable) SetSkipIface(name string) {
	rt.mu.Lock()
	rt.skipIface = name
	rt.lastFetch = time.Time{}
	rt.mu.Unlock()
}

func (rt *RouteTable) refresh() error {
	rt.mu.Lock()
	if time.Since(rt.lastFetch) < rt.ttl {
		rt.mu.Unlock()
		return nil
	}
	entries, err := fetchEntries(rt.skipIface)
	if err != nil {
		rt.mu.Unlock()
		return err
	}
	rt.table.replace(entries)
	rt.lastFetch = time.Now()
	cb := rt.onRefresh
	rt.mu.Unlock()
	if cb != nil {
		cb()
	}
	return nil
}

// Lookup returns the interface and gateway for ip from the (possibly cached) routing table.
func (rt *RouteTable) Lookup(ip net.IP) (iface string, gateway net.IP, err error) {
	rt.mu.Lock()
	stale := time.Since(rt.lastFetch) >= rt.ttl
	rt.mu.Unlock()
	if stale {
		rt.refresh() //nolint:errcheck
	}
	return rt.table.Lookup(ip)
}

// Entries returns a snapshot of the monitored routing table.
func (rt *RouteTable) Entries() []Entry {
	rt.mu.Lock()
	stale := time.Since(rt.lastFetch) >= rt.ttl
	rt.mu.Unlock()
	if stale {
		rt.refresh() //nolint:errcheck
	}
	return rt.table.Entries()
}
