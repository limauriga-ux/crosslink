package netstack

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestDNSCacheReusesFreshLookup(t *testing.T) {
	now := time.Unix(1_000, 0)
	cache := newDNSCache(time.Minute, 5*time.Minute)
	cache.now = func() time.Time { return now }
	lookups := 0
	lookup := func(ctx context.Context, host string) ([]string, error) {
		lookups++
		return []string{"203.0.113.10"}, nil
	}

	for i := 0; i < 2; i++ {
		ips, err := cache.lookup(context.Background(), "www.google.com", lookup)
		if err != nil {
			t.Fatal(err)
		}
		if len(ips) != 1 || ips[0] != "203.0.113.10" {
			t.Fatalf("ips = %v, want [203.0.113.10]", ips)
		}
	}
	if lookups != 1 {
		t.Fatalf("lookups = %d, want 1", lookups)
	}
}

func TestDNSCacheServesStaleAndRefreshesInBackground(t *testing.T) {
	now := time.Unix(1_000, 0)
	cache := newDNSCache(time.Minute, 5*time.Minute)
	cache.now = func() time.Time { return now }
	answers := []string{"203.0.113.10", "203.0.113.11"}
	refreshDone := make(chan struct{})
	lookup := func(ctx context.Context, host string) ([]string, error) {
		ip := answers[0]
		answers = answers[1:]
		if ip == "203.0.113.11" {
			defer close(refreshDone)
		}
		return []string{ip}, nil
	}

	if ips, err := cache.lookup(context.Background(), "www.google.com", lookup); err != nil || ips[0] != "203.0.113.10" {
		t.Fatalf("first lookup ips=%v err=%v", ips, err)
	}
	now = now.Add(2 * time.Minute)
	if ips, err := cache.lookup(context.Background(), "www.google.com", lookup); err != nil || ips[0] != "203.0.113.10" {
		t.Fatalf("stale lookup ips=%v err=%v", ips, err)
	}
	select {
	case <-refreshDone:
	case <-time.After(time.Second):
		t.Fatal("background refresh did not run")
	}
	if ips, err := cache.lookup(context.Background(), "www.google.com", lookup); err != nil || ips[0] != "203.0.113.11" {
		t.Fatalf("refreshed lookup ips=%v err=%v", ips, err)
	}
}

func TestDNSCacheKeepsStaleWhenBackgroundRefreshFails(t *testing.T) {
	now := time.Unix(1_000, 0)
	cache := newDNSCache(time.Minute, 5*time.Minute)
	cache.now = func() time.Time { return now }
	refreshDone := make(chan struct{})
	var refreshDoneOnce sync.Once
	lookups := 0
	lookup := func(ctx context.Context, host string) ([]string, error) {
		lookups++
		if lookups == 1 {
			return []string{"203.0.113.10"}, nil
		}
		refreshDoneOnce.Do(func() { close(refreshDone) })
		return nil, errors.New("temporary dns failure")
	}

	if ips, err := cache.lookup(context.Background(), "www.google.com", lookup); err != nil || ips[0] != "203.0.113.10" {
		t.Fatalf("first lookup ips=%v err=%v", ips, err)
	}
	now = now.Add(2 * time.Minute)
	if ips, err := cache.lookup(context.Background(), "www.google.com", lookup); err != nil || ips[0] != "203.0.113.10" {
		t.Fatalf("stale lookup ips=%v err=%v", ips, err)
	}
	select {
	case <-refreshDone:
	case <-time.After(time.Second):
		t.Fatal("background refresh did not run")
	}
	if ips, err := cache.lookup(context.Background(), "www.google.com", lookup); err != nil || ips[0] != "203.0.113.10" {
		t.Fatalf("failed refresh should keep stale ips=%v err=%v", ips, err)
	}
}

func TestDNSCacheBlocksAfterHardTTL(t *testing.T) {
	now := time.Unix(1_000, 0)
	cache := newDNSCache(time.Minute, 5*time.Minute)
	cache.now = func() time.Time { return now }
	answers := []string{"203.0.113.10", "203.0.113.12"}
	lookup := func(ctx context.Context, host string) ([]string, error) {
		ip := answers[0]
		answers = answers[1:]
		return []string{ip}, nil
	}

	if ips, err := cache.lookup(context.Background(), "www.google.com", lookup); err != nil || ips[0] != "203.0.113.10" {
		t.Fatalf("first lookup ips=%v err=%v", ips, err)
	}
	now = now.Add(6 * time.Minute)
	if ips, err := cache.lookup(context.Background(), "www.google.com", lookup); err != nil || ips[0] != "203.0.113.12" {
		t.Fatalf("hard-expired lookup ips=%v err=%v", ips, err)
	}
}
