package core

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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
