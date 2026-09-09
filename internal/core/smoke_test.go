package core

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	appconfig "github.com/limauriga-ux/crosslink/internal/config"
)

func TestEmbeddedCoreMixedInboundRoutesWithoutCorporateTunnel(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	cfg := appconfig.DefaultConfig()
	cfg.Core.Profile = ""
	cfg.Core.Rules = ""
	cfg.Core.DomesticDirect = false
	cfg.Core.TUNEnabled = false
	cfg.Core.MixedPort = port

	manager := New(cfg)
	manager.lifecycleMu.Lock()
	err = manager.startCoreLocked()
	manager.lifecycleMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Disconnect()

	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	proxyURL, err := url.Parse("http://127.0.0.1:" + strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
	response, err := client.Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusNoContent)
	}
}

func TestEmbeddedCoreMixedInboundExplicitRuleOverridesCorporateClaim(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dataDir := filepath.Join(home, ".crosslink")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(dataDir, "proxy.json")
	if err := os.WriteFile(profilePath, []byte(`{
		"outbounds":[
			{"type":"socks","tag":"edge","server":"127.0.0.1","server_port":1},
			{"type":"selector","tag":"Proxy","outbounds":["edge"],"default":"edge"}
		],
		"route":{
			"rules":[{"ip_cidr":["127.0.0.1/32"],"action":"route","outbound":"direct"}],
			"final":"Proxy"
		}
	}`), 0o600); err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	cfg := appconfig.DefaultConfig()
	cfg.Core.Profile = profilePath
	cfg.Core.Rules = ""
	cfg.Core.DomesticDirect = false
	cfg.Core.TUNEnabled = false
	cfg.Core.MixedPort = port
	manager := New(cfg)
	manager.runtime.UpdateRoutes([]string{"127.0.0.1/32"}, nil, nil, false)
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	defer manager.Disconnect()

	proxyURL, err := url.Parse("http://127.0.0.1:" + strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
	response, err := client.Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusNoContent)
	}
}
