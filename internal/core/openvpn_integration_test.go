package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	appconfig "github.com/limauriga-ux/crosslink/internal/config"
	"github.com/limauriga-ux/crosslink/internal/corpendpoint"
	"github.com/limauriga-ux/crosslink/internal/openvpnprofile"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
)

func TestOpenVPNLoopbackLifecycle(t *testing.T) {
	caPEM, serverCertPEM, serverKeyPEM, clientCertPEM, clientKeyPEM := loopbackOpenVPNIdentities(t)
	port := freeOpenVPNTestPort(t)
	server := startLoopbackOpenVPNServer(t, port, caPEM, serverCertPEM, serverKeyPEM)
	defer server.Close()

	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg := appconfig.DefaultConfig()
	if err := cfg.BindConfigPath(filepath.Join(home, ".crosslink", "config.json")); err != nil {
		t.Fatal(err)
	}
	cfg.Core.Profile = ""
	cfg.Core.Rules = ""
	cfg.Core.DomesticDirect = false
	cfg.Core.TUNEnabled = false
	cfg.Core.MixedPort = 0
	cfg.Core.LogLevel = "error"
	manager := New(cfg)
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	defer manager.Disconnect()
	previousInstance := manager.instance

	clientProfile := openvpnprofile.Profile{
		Version:              openvpnprofile.Version,
		Name:                 "Loopback Enterprise",
		Remotes:              []openvpnprofile.Remote{{Server: "127.0.0.1", Port: port, Network: "tcp"}},
		CertificateAuthority: caPEM,
		ClientCertificate:    clientCertPEM,
		ClientKey:            clientKeyPEM,
		RemoteCertificateTLS: "server",
		DataCiphers:          []string{"AES-256-GCM"},
		AuthUserPass:         true,
	}
	if err := manager.ConnectOpenVPN(clientProfile, "employee", "correct-password"); err != nil {
		t.Fatal(err)
	}
	if manager.instance == previousInstance {
		t.Fatal("OpenVPN connect did not replace the core generation")
	}

	status := waitForOpenVPNStatus(t, manager, adapter.OpenVPNStateConnected, 8*time.Second)
	if !status.Active || status.ProfileName != clientProfile.Name || status.Server == "" || status.Network != "tcp" {
		t.Fatalf("connected status = %+v", status)
	}
	if len(status.IPv4) != 1 || len(status.DNS) != 1 || status.DNS[0] != "10.20.0.53" {
		t.Fatalf("pushed tunnel info = %+v", status)
	}

	ipDecision := selectAdversarialRoute(manager.instance.Router(), ipMetadata("10.20.1.10"), directTag)
	if ipDecision.action != "route(openvpn-enterprise)" {
		t.Fatalf("pushed route decision = %+v", ipDecision)
	}
	domainDecision := selectAdversarialRoute(manager.instance.Router(), domainMetadata("api.corp.example"), directTag)
	if domainDecision.action != "route(openvpn-enterprise)" {
		t.Fatalf("pushed domain decision = %+v", domainDecision)
	}

	if err := manager.DisconnectOpenVPN(); err != nil {
		t.Fatal(err)
	}
	offline := manager.OpenVPNStatus()
	if offline.Active || offline.State != "disconnected" || manager.instance == nil || !manager.coreRunning.Load() {
		t.Fatalf("disconnected status = %+v, core=%v", offline, manager.instance != nil)
	}
	outbound, found := manager.instance.Outbound().Outbound(openvpnprofile.EndpointTag)
	if !found || outbound.Type() != "block" {
		t.Fatalf("offline OpenVPN target = %T found=%v", outbound, found)
	}
}

func startLoopbackOpenVPNServer(t *testing.T, port uint16, caPEM, serverCertPEM, serverKeyPEM string) *box.Box {
	t.Helper()
	root := map[string]any{
		"log": map[string]any{"level": "error"},
		"dns": map[string]any{
			"servers": []any{map[string]any{"type": "udp", "tag": "loopback-dns", "server": "127.0.0.1", "server_port": 9}},
			"final":   "loopback-dns",
		},
		"endpoints": []any{map[string]any{
			"type": "openvpn-server", "tag": "loopback-openvpn-server",
			"listen": "127.0.0.1", "listen_port": port,
			"system": false, "mode": "tls", "network": "tcp",
			"address": []string{"10.8.0.1/24"},
			"users":   []any{map[string]any{"username": "employee", "password": "correct-password"}},
			"tls": map[string]any{
				"certificate": serverCertPEM, "key": serverKeyPEM,
				"client_certificate": caPEM, "verify_client_certificate": "require",
				"remote_certificate_tls": "client", "version_min": "1.2",
			},
			"data_ciphers": []string{"AES-256-GCM"},
			"push": map[string]any{
				"routes":         []string{"10.20.0.0/16"},
				"dns":            []string{"10.20.0.53"},
				"search_domains": []string{"corp.example"},
			},
		}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"final": "direct", "auto_detect_interface": true, "default_domain_resolver": "loopback-dns"},
	}
	content, err := singjson.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	registries := newRegistries(corpendpoint.NewRuntime())
	ctx, cancel := context.WithCancel(context.Background())
	ctx = registries.context(ctx)
	options, err := singjson.UnmarshalExtendedContext[option.Options](ctx, content)
	if err != nil {
		cancel()
		t.Fatalf("parse loopback OpenVPN server: %v\n%s", err, content)
	}
	server, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		server.Close()
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(cancel)
	return server
}

func waitForOpenVPNStatus(t *testing.T, manager *Manager, state string, timeout time.Duration) OpenVPNStatus {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var status OpenVPNStatus
	for time.Now().Before(deadline) {
		status = manager.OpenVPNStatus()
		if status.State == state {
			return status
		}
		if status.State == adapter.OpenVPNStateError {
			t.Fatalf("OpenVPN endpoint failed: %+v", status)
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("OpenVPN state = %+v, want %s", status, state)
	return OpenVPNStatus{}
}

func loopbackOpenVPNIdentities(t *testing.T) (caPEM, serverCertPEM, serverKeyPEM, clientCertPEM, clientKeyPEM string) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CrossLink Loopback CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	serverCert, serverKey := signedLoopbackCertificate(t, ca, caKey, 2, "loopback-server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	clientCert, clientKey := signedLoopbackCertificate(t, ca, caKey, 3, "loopback-client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	return pemCertificate(ca.Raw), pemCertificate(serverCert.Raw), pemPrivateKey(t, serverKey), pemCertificate(clientCert.Raw), pemPrivateKey(t, clientKey)
}

func signedLoopbackCertificate(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, serial int64, commonName string, usages []x509.ExtKeyUsage) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: commonName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}

func pemCertificate(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func pemPrivateKey(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}
