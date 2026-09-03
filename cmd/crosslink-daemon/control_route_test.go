package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/limauriga-ux/crosslink/internal/config"
)

func TestPinCorplinkControlRoutesPinsEveryPhysicalDNSAddress(t *testing.T) {
	var resolved bool
	var calls []string
	err := pinCorplinkControlRoutes(
		context.Background(),
		func(context.Context) ([]string, error) {
			resolved = true
			return []string{"192.0.2.10", "198.51.100.20", "203.0.113.30"}, nil
		},
		"en0",
		func(ip, iface string) error {
			calls = append(calls, ip+"@"+iface)
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.10@en0", "198.51.100.20@en0", "203.0.113.30@en0"}
	if !resolved || !reflect.DeepEqual(calls, want) {
		t.Fatalf("resolved=%v routes=%v want=%v", resolved, calls, want)
	}
}

func TestPinCorplinkControlRoutesReturnsResolverAndRouteErrors(t *testing.T) {
	resolverErr := errors.New("bootstrap DNS unavailable")
	if err := pinCorplinkControlRoutes(context.Background(), func(context.Context) ([]string, error) {
		return nil, resolverErr
	}, "en0", func(string, string) error { return nil }); !errors.Is(err, resolverErr) {
		t.Fatalf("resolver error = %v", err)
	}

	routeErr := errors.New("route failed")
	err := pinCorplinkControlRoutes(context.Background(), func(context.Context) ([]string, error) {
		return []string{"192.0.2.10", "198.51.100.20"}, nil
	}, "en0", func(ip, _ string) error {
		if ip == "192.0.2.10" {
			return routeErr
		}
		return nil
	})
	if !errors.Is(err, routeErr) || !strings.Contains(err.Error(), "192.0.2.10") {
		t.Fatalf("route error = %v", err)
	}
}

func TestResolvePhysicalInterfaceHonorsConfiguredInterface(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DirectOutbound.Interface = " en7 "
	if got := resolvePhysicalInterface(cfg); got != "en7" {
		t.Fatalf("physical interface = %q, want en7", got)
	}
}
