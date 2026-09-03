//go:build darwin

package netroute

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestAddHostRouteKeepsMatchingLiveRouteUntouched(t *testing.T) {
	var calls [][]string
	stubRouteCombinedOutput(t, func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return []byte(`   route to: 192.0.2.40
destination: 192.0.2.40
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,HOST,DONE,STATIC>
`), nil
	})

	if err := addHostRoute("192.0.2.40", "en0", net.ParseIP("192.168.1.1")); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"route", "-n", "get", "192.0.2.40"}}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("route commands = %v, want %v; matching route must see zero add/delete", calls, want)
	}
}

func TestAddHostRouteDoesNotMistakeDefaultRouteForOwnedHostRoute(t *testing.T) {
	var calls [][]string
	stubRouteCombinedOutput(t, func(name string, args ...string) ([]byte, error) {
		call := append([]string{name}, args...)
		calls = append(calls, call)
		if reflect.DeepEqual(call, []string{"route", "-n", "get", "192.0.2.40"}) {
			return []byte(`   route to: 192.0.2.40
destination: default
    gateway: 192.168.1.1
  interface: en0
`), nil
		}
		return nil, nil
	})

	if err := addHostRoute("192.0.2.40", "en0", net.ParseIP("192.168.1.1")); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"route", "-n", "get", "192.0.2.40"},
		{"route", "add", "-host", "192.0.2.40", "192.168.1.1"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("route commands = %v, want %v", calls, want)
	}
}

func TestAddHostRouteRequiresHostFlagForExactDestination(t *testing.T) {
	var calls [][]string
	stubRouteCombinedOutput(t, func(name string, args ...string) ([]byte, error) {
		call := append([]string{name}, args...)
		calls = append(calls, call)
		if len(calls) == 1 {
			return []byte(`destination: 192.0.2.40
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC>
`), nil
		}
		return nil, nil
	})

	if err := addHostRoute("192.0.2.40", "en0", net.ParseIP("192.168.1.1")); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"route", "-n", "get", "192.0.2.40"},
		{"route", "add", "-host", "192.0.2.40", "192.168.1.1"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("route commands = %v, want %v", calls, want)
	}
}

func TestAddHostRouteNeverDeletesWhenExistingRouteCannotBeInspected(t *testing.T) {
	var calls [][]string
	inspectErr := errors.New("routing socket busy")
	fileExists := errors.New("exit status 1")
	stubRouteCombinedOutput(t, func(name string, args ...string) ([]byte, error) {
		call := append([]string{name}, args...)
		calls = append(calls, call)
		switch len(calls) {
		case 1, 3:
			return nil, inspectErr
		case 2:
			return []byte("route: writing to routing socket: File exists\n"), fileExists
		default:
			t.Fatalf("unexpected route command %v", call)
			return nil, nil
		}
	})

	err := addHostRoute("192.0.2.40", "en0", net.ParseIP("192.168.1.1"))
	if err == nil {
		t.Fatal("expected ambiguous File exists to fail safely")
	}
	for _, call := range calls {
		if len(call) > 1 && call[1] == "delete" {
			t.Fatalf("ambiguous route inspection issued destructive delete: %v", calls)
		}
	}
}

func TestAddHostRouteReplacesVerifiedConflictingHostRoute(t *testing.T) {
	var calls [][]string
	fileExists := errors.New("exit status 1")
	stubRouteCombinedOutput(t, func(name string, args ...string) ([]byte, error) {
		call := append([]string{name}, args...)
		calls = append(calls, call)
		switch len(calls) {
		case 1, 3:
			return []byte(`   route to: 192.0.2.40
destination: 192.0.2.40
    gateway: 10.0.0.1
  interface: en5
      flags: <UP,GATEWAY,HOST,DONE,STATIC>
`), nil
		case 2:
			return []byte("route: writing to routing socket: File exists\n"), fileExists
		case 4:
			return nil, nil
		default:
			t.Fatalf("unexpected route command %v", call)
			return nil, nil
		}
	})

	if err := addHostRoute("192.0.2.40", "en0", net.ParseIP("192.168.1.1")); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"route", "-n", "get", "192.0.2.40"},
		{"route", "add", "-host", "192.0.2.40", "192.168.1.1"},
		{"route", "-n", "get", "192.0.2.40"},
		{"route", "change", "-host", "192.0.2.40", "192.168.1.1"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("route commands = %v, want %v", calls, want)
	}
}

func TestAddHostRouteLogsCrossInterfaceRepin(t *testing.T) {
	var calls [][]string
	fileExists := errors.New("exit status 1")
	var logs bytes.Buffer
	originalLogWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() {
		log.SetOutput(originalLogWriter)
	})
	stubRouteCombinedOutput(t, func(name string, args ...string) ([]byte, error) {
		call := append([]string{name}, args...)
		calls = append(calls, call)
		switch len(calls) {
		case 1, 3:
			return []byte(`destination: 192.0.2.40
    gateway: 10.0.0.1
  interface: en0
      flags: <UP,GATEWAY,HOST,DONE,STATIC>
`), nil
		case 2:
			return []byte("File exists"), fileExists
		case 4:
			return nil, nil
		default:
			t.Fatalf("unexpected route command %v", call)
			return nil, nil
		}
	})

	if err := addHostRoute("192.0.2.40", "en5", net.ParseIP("192.168.1.1")); err != nil {
		t.Fatal(err)
	}
	got := logs.String()
	if !strings.Contains(got, "re-pinned 192.0.2.40 from en0 to en5") ||
		!strings.Contains(got, "any still-live generation on en0 has lost its underlay") {
		t.Fatalf("cross-interface re-pin log = %q", got)
	}
}

func TestAddHostRouteLogsSameInterfaceGatewayRepin(t *testing.T) {
	var calls [][]string
	fileExists := errors.New("exit status 1")
	var logs bytes.Buffer
	originalLogWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() {
		log.SetOutput(originalLogWriter)
	})
	stubRouteCombinedOutput(t, func(name string, args ...string) ([]byte, error) {
		call := append([]string{name}, args...)
		calls = append(calls, call)
		switch len(calls) {
		case 1, 3:
			return []byte(`destination: 192.0.2.40
    gateway: 10.0.0.1
  interface: en0
      flags: <UP,GATEWAY,HOST,DONE,STATIC>
`), nil
		case 2:
			return []byte("File exists"), fileExists
		case 4:
			return nil, nil
		default:
			t.Fatalf("unexpected route command %v", call)
			return nil, nil
		}
	})

	if err := addHostRoute("192.0.2.40", "en0", net.ParseIP("192.168.1.1")); err != nil {
		t.Fatal(err)
	}
	if got := logs.String(); !strings.Contains(got, "re-pinned 192.0.2.40 on en0: gateway 10.0.0.1 -> 192.168.1.1") {
		t.Fatalf("same-interface re-pin log = %q", got)
	}
}

func TestAddHostRouteFallsBackWhenAtomicChangeFails(t *testing.T) {
	var calls [][]string
	fileExists := errors.New("exit status 1")
	changeErr := errors.New("change unsupported")
	stubRouteCombinedOutput(t, func(name string, args ...string) ([]byte, error) {
		call := append([]string{name}, args...)
		calls = append(calls, call)
		switch len(calls) {
		case 1, 3:
			return []byte(`destination: 192.0.2.40
    gateway: 10.0.0.1
  interface: en5
      flags: <UP,GATEWAY,HOST,DONE,STATIC>
`), nil
		case 2:
			return []byte("File exists"), fileExists
		case 4:
			return []byte("not supported"), changeErr
		case 5, 6:
			return nil, nil
		default:
			t.Fatalf("unexpected route command %v", call)
			return nil, nil
		}
	})

	if err := addHostRoute("192.0.2.40", "en0", net.ParseIP("192.168.1.1")); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"route", "-n", "get", "192.0.2.40"},
		{"route", "add", "-host", "192.0.2.40", "192.168.1.1"},
		{"route", "-n", "get", "192.0.2.40"},
		{"route", "change", "-host", "192.0.2.40", "192.168.1.1"},
		{"route", "delete", "-host", "192.0.2.40"},
		{"route", "add", "-host", "192.0.2.40", "192.168.1.1"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("route commands = %v, want %v", calls, want)
	}
}

func TestAddHostRouteDoesNotDeleteAfterAtomicChangeTimeout(t *testing.T) {
	var calls [][]string
	fileExists := errors.New("exit status 1")
	stubRouteCombinedOutput(t, func(name string, args ...string) ([]byte, error) {
		call := append([]string{name}, args...)
		calls = append(calls, call)
		switch len(calls) {
		case 1, 3:
			return []byte(`destination: 192.0.2.40
    gateway: 10.0.0.1
  interface: en5
      flags: <UP,GATEWAY,HOST,DONE,STATIC>
`), nil
		case 2:
			return []byte("File exists"), fileExists
		case 4:
			return []byte("command timed out"), context.DeadlineExceeded
		case 5:
			return []byte(`destination: 192.0.2.40
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,HOST,DONE,STATIC>
`), nil
		default:
			t.Fatalf("unexpected destructive retry after timeout: %v", call)
			return nil, nil
		}
	})

	if err := addHostRoute("192.0.2.40", "en0", net.ParseIP("192.168.1.1")); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"route", "-n", "get", "192.0.2.40"},
		{"route", "add", "-host", "192.0.2.40", "192.168.1.1"},
		{"route", "-n", "get", "192.0.2.40"},
		{"route", "change", "-host", "192.0.2.40", "192.168.1.1"},
		{"route", "-n", "get", "192.0.2.40"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("route commands = %v, want %v", calls, want)
	}
}

func TestAddScopedHostRoutePersistsPhysicalGateway(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "host-routes.json")
	if err := ConfigureHostRouteState(statePath); err != nil {
		t.Fatal(err)
	}
	stubRouteCombinedOutput(t, func(name string, args ...string) ([]byte, error) {
		call := append([]string{name}, args...)
		switch {
		case reflect.DeepEqual(call, []string{"route", "-n", "get", "default", "-ifscope", "en0"}):
			return []byte("gateway: 192.168.1.1\ninterface: en0\n"), nil
		case reflect.DeepEqual(call, []string{"route", "-n", "get", "192.0.2.40"}):
			return []byte("destination: default\ngateway: 192.168.1.1\ninterface: en0\n"), nil
		case reflect.DeepEqual(call, []string{"route", "add", "-host", "192.0.2.40", "192.168.1.1"}):
			return nil, nil
		default:
			t.Fatalf("unexpected route command: %v", call)
			return nil, nil
		}
	})

	if err := AddScopedHostRoute("192.0.2.40", "en0"); err != nil {
		t.Fatal(err)
	}
	routes, err := loadPersistedHostRoutes()
	if err != nil {
		t.Fatal(err)
	}
	if routes["192.0.2.40"] != "192.168.1.1" {
		t.Fatalf("persisted routes = %#v", routes)
	}
}

func TestHostRouteInterfaceMatchingAcceptsRenderedInterfaceGateway(t *testing.T) {
	route := hostRoute{iface: "en0", gateway: "en0", flags: "<UP,HOST>"}
	if !route.matches("en0", nil) {
		t.Fatal("interface-form route rendered with interface gateway should match")
	}
}

func stubRouteCombinedOutput(t *testing.T, fn func(string, ...string) ([]byte, error)) {
	t.Helper()
	orig := routeCombinedOutput
	routeCombinedOutput = fn
	t.Cleanup(func() {
		routeCombinedOutput = orig
	})
}
