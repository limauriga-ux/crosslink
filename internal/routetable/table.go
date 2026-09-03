package routetable

import (
	"fmt"
	"net"
	"sort"
	"sync"
)

// Entry represents a single routing table entry.
type Entry struct {
	Dest    *net.IPNet
	Gateway net.IP
	Iface   string
}

// Table is a thread-safe in-memory routing table with longest-prefix-match lookup.
type Table struct {
	mu      sync.RWMutex
	entries []Entry // sorted by prefix length descending (longest first)
}

// replace atomically swaps in a new set of entries.
func (t *Table) replace(entries []Entry) {
	sort.Slice(entries, func(i, j int) bool {
		oi, _ := entries[i].Dest.Mask.Size()
		oj, _ := entries[j].Dest.Mask.Size()
		return oi > oj
	})
	t.mu.Lock()
	t.entries = entries
	t.mu.Unlock()
}

// Lookup returns the best-matching interface and gateway for ip.
func (t *Table) Lookup(ip net.IP) (iface string, gateway net.IP, err error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, e := range t.entries {
		if e.Dest.Contains(ip) {
			return e.Iface, e.Gateway, nil
		}
	}
	return "", nil, fmt.Errorf("routetable: no route for %s", ip)
}

// Entries returns a snapshot copy of the routing table entries.
func (t *Table) Entries() []Entry {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]Entry, len(t.entries))
	copy(out, t.entries)
	return out
}
