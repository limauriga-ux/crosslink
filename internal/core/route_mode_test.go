package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	appconfig "github.com/limauriga-ux/crosslink/internal/config"
	"github.com/limauriga-ux/crosslink/internal/corpendpoint"
)

func TestSetFollowSplitRoutesUpdatesObservableStatus(t *testing.T) {
	manager := &Manager{runtime: corpendpoint.NewRuntime()}
	manager.lastRoutes = []string{"10.20.0.0/16", "10.30.0.0/16", "104.21.79.4/32"}
	manager.lastDomains = []string{"corp.example", "com"}
	manager.SetFollowSplitRoutes(true)

	status := manager.GetStatus()
	if !status.RouteModeKnown || !status.FollowSplitRoutes || status.CorporateRouteCount != 2 || status.CorporateDomainCount != 1 || status.CorporateIgnoredPublicRoutes != 1 || status.CorporateIgnoredPublicDomains != 1 {
		t.Fatalf("split status = %+v", status)
	}
	manager.SetFollowSplitRoutes(false)
	status = manager.GetStatus()
	if !status.RouteModeKnown || status.FollowSplitRoutes {
		t.Fatalf("full-tunnel status = %+v", status)
	}
}

func TestPublicEgressInfoUsesDefaultOutbound(t *testing.T) {
	// The behavior is covered end-to-end by the existing embedded core smoke
	// setup; this guard documents that an absent core cannot fall back to the
	// system route (which would make the two IP cards lie).
	manager := &Manager{}
	_, err := manager.PublicEgressInfo(context.Background())
	if err != ErrCoreNotRunning {
		t.Fatalf("PublicEgressInfo error = %v", err)
	}
}

func TestPublicEgressInfoDialsThroughCoreDefault(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"ip":"203.0.113.8","country":"TEST","org":"AS64500 CrossLink"}`))
	}))
	defer server.Close()
	previousURL := egressInfoURL
	egressInfoURL = server.URL
	defer func() { egressInfoURL = previousURL }()

	cfg := appconfig.DefaultConfig()
	cfg.Core.Profile = ""
	cfg.Core.Rules = ""
	cfg.Core.DomesticDirect = false
	cfg.Core.TUNEnabled = false
	cfg.Core.MixedPort = 0
	manager := New(cfg)
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	defer manager.Disconnect()
	info, err := manager.PublicEgressInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.IP != "203.0.113.8" || info.Org != "AS64500 CrossLink" {
		t.Fatalf("egress info = %+v", info)
	}
}
