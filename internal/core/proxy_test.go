package core

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	appconfig "github.com/limauriga-ux/crosslink/internal/config"
)

func TestProxyGroupsAndSelection(t *testing.T) {
	profilePath := filepath.Join(t.TempDir(), "proxy.json")
	content := []byte(`{
		"outbounds":[
			{"type":"direct","tag":"edge-a"},
			{"type":"socks","tag":"edge-b","server":"127.0.0.1","server_port":1080},
			{"type":"selector","tag":"Proxy","outbounds":["edge-a","edge-b"],"default":"edge-a"}
		],
		"route":{"final":"Proxy"}
	}`)
	if err := os.WriteFile(profilePath, content, 0o600); err != nil {
		t.Fatal(err)
	}

	statePath := filepath.Join(t.TempDir(), "proxy-state.json")
	cfg := appconfig.DefaultConfig()
	cfg.Core.StateFile = statePath
	cfg.Core.Profile = profilePath
	cfg.Core.Rules = ""
	cfg.Core.DomesticDirect = false
	cfg.Core.TUNEnabled = false
	cfg.Core.MixedPort = 0
	manager := New(cfg)
	manager.lifecycleMu.Lock()
	err := manager.startCoreLocked()
	manager.lifecycleMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Disconnect()

	groups, err := manager.ProxyGroups()
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].Tag != "Proxy" || groups[0].Selected != "edge-a" {
		t.Fatalf("groups = %+v", groups)
	}
	if err := manager.SelectProxy("Proxy", "edge-b"); err != nil {
		t.Fatal(err)
	}
	groups, err = manager.ProxyGroups()
	if err != nil {
		t.Fatal(err)
	}
	if groups[0].Selected != "edge-b" {
		t.Fatalf("selected = %q, want edge-b", groups[0].Selected)
	}
	stateInfo, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if stateInfo.Mode().Perm() != 0o600 {
		t.Fatalf("proxy state permissions = %o, want 600", stateInfo.Mode().Perm())
	}
	if err := manager.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	groups, err = manager.ProxyGroups()
	if err != nil {
		t.Fatal(err)
	}
	if groups[0].Selected != "edge-b" {
		t.Fatalf("selected after reload = %q, want edge-b", groups[0].Selected)
	}
	publicStatus := manager.PublicProxyStatus()
	if !publicStatus.CoreRunning || publicStatus.TUNEnabled || publicStatus.SystemProxyEnabled {
		t.Fatalf("public status = %+v", publicStatus)
	}
	if publicStatus.SelectedOutbound != "edge-b" || publicStatus.SelectedType != "socks" || !publicStatus.ProxyAvailable {
		t.Fatalf("selected public route = %+v", publicStatus)
	}
}

func TestURLTestProxyGroupRecordsDelay(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	profilePath := filepath.Join(t.TempDir(), "proxy.json")
	content := []byte(fmt.Sprintf(`{
		"outbounds":[
			{"type":"direct","tag":"edge"},
			{"type":"urltest","tag":"Auto","outbounds":["edge"],"url":%q,"interval":"10m"}
		],
		"route":{"final":"Auto"}
	}`, target.URL))
	if err := os.WriteFile(profilePath, content, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := appconfig.DefaultConfig()
	cfg.Core.Profile = profilePath
	cfg.Core.Rules = ""
	cfg.Core.DomesticDirect = false
	cfg.Core.TUNEnabled = false
	cfg.Core.MixedPort = 0
	cfg.Core.StateFile = filepath.Join(t.TempDir(), "proxy-state.json")
	manager := New(cfg)
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	defer manager.Disconnect()

	delays, err := manager.TestProxyGroup("Auto")
	if err != nil {
		t.Fatal(err)
	}
	if _, found := delays["edge"]; !found {
		t.Fatalf("delays = %#v", delays)
	}
	groups, err := manager.ProxyGroups()
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || len(groups[0].Items) != 1 || groups[0].Items[0].DelayMs < 0 {
		t.Fatalf("groups after speed test = %+v", groups)
	}
}
