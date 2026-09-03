package openvpnprofile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestImportCreatesPathFreeManagedProfile(t *testing.T) {
	dir := t.TempDir()
	caPEM, p12 := openVPNTestIdentity(t, "bundle-password")
	ovpnPath := filepath.Join(dir, "enterprise.ovpn")
	caPath := filepath.Join(dir, "ca.crt")
	p12Path := filepath.Join(dir, "client.p12")
	content := `client
proto tcp-client
dev tun
remote vpn.example.com 12294
remote 192.0.2.20 1194 udp
remote-random
ca ca.crt
pkcs12 client.p12
auth-user-pass
static-challenge "OTP code" 0
remote-cert-tls server
route-nopull
route 10.130.0.0 255.255.0.0 vpn_gateway
route-ipv6 2001:db8:1234::/48
dhcp-option DNS 10.20.0.53
dhcp-option DOMAIN corp.example
reneg-sec 86400
tun-mtu 1400
`
	if err := os.WriteFile(ovpnPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p12Path, p12, 0o600); err != nil {
		t.Fatal(err)
	}

	profile, report, err := Import(ImportOptions{
		OVPNPath:       ovpnPath,
		CAPath:         caPath,
		PKCS12Path:     p12Path,
		PKCS12Password: "bundle-password",
	})
	if err != nil {
		t.Fatal(err)
	}
	if profile.Name != "enterprise" || len(profile.Remotes) != 2 || profile.Remotes[0].Network != "tcp" || profile.Remotes[1].Network != "udp" {
		t.Fatalf("profile remotes = %+v", profile.Remotes)
	}
	if !profile.RouteNoPull || !profile.AuthUserPass || profile.StaticChallenge != "OTP code" || profile.StaticChallengeEcho || len(profile.Routes) != 2 || len(profile.DNSServers) != 1 || len(profile.Domains) != 1 {
		t.Fatalf("profile routing and MFA = %+v", profile)
	}
	if report.Server != "vpn.example.com:12294" || report.Routes != 2 || report.Domains != 1 || report.DNSServers != 1 || !report.RequiresCredentials || report.CertificateExpiresAt <= time.Now().Unix() {
		t.Fatalf("report = %+v", report)
	}
	encoded, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	serialized := string(encoded)
	for _, secret := range []string{ovpnPath, caPath, p12Path, "bundle-password"} {
		if strings.Contains(serialized, secret) {
			t.Fatalf("managed profile retained source path or password %q", secret)
		}
	}
}

func TestEndpointIncludesStaticChallengeWithoutPersistingSessionCredentials(t *testing.T) {
	profile := Profile{StaticChallenge: "One-time password", StaticChallengeEcho: false}
	endpoint := profile.Endpoint("employee", "session-password", "en0", "bootstrap")
	if endpoint["static_challenge"] != "One-time password" || endpoint["static_challenge_echo"] != false {
		t.Fatalf("endpoint challenge = %#v", endpoint)
	}
	if endpoint["username"] != "employee" || endpoint["password"] != "session-password" {
		t.Fatalf("endpoint session credentials missing: %#v", endpoint)
	}
	content, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), "employee") || strings.Contains(string(content), "session-password") {
		t.Fatalf("profile retained session credentials: %s", content)
	}
}

func TestImportRejectsExecutableAndCredentialFileDirectives(t *testing.T) {
	dir := t.TempDir()
	caPEM, p12 := openVPNTestIdentity(t, "password")
	caPath := filepath.Join(dir, "ca.crt")
	p12Path := filepath.Join(dir, "client.p12")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p12Path, p12, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		directive string
		want      string
	}{
		{name: "script", directive: `up "/tmp/owned"`, want: "forbidden"},
		{name: "plugin", directive: `plugin malicious.so`, want: "forbidden"},
		{name: "management", directive: `management 127.0.0.1 7505`, want: "forbidden"},
		{name: "credential file", directive: `auth-user-pass credentials.txt`, want: "credential files are not allowed"},
		{name: "unknown", directive: `compress lz4-v2`, want: "unsupported directive"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ovpnPath := filepath.Join(dir, test.name+".ovpn")
			content := "client\nproto tcp\ndev tun\nremote vpn.example.com 443\nca ca.crt\npkcs12 client.p12\n" + test.directive + "\n"
			if err := os.WriteFile(ovpnPath, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, _, err := Import(ImportOptions{OVPNPath: ovpnPath, CAPath: caPath, PKCS12Path: p12Path, PKCS12Password: "password"})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestParseIPv4RouteRejectsNonContiguousMask(t *testing.T) {
	_, err := parseIPv4Route([]string{"10.0.0.0", "255.0.255.0", "vpn_gateway"})
	if err == nil || !strings.Contains(err.Error(), "non-contiguous") {
		t.Fatalf("non-contiguous route mask error = %v", err)
	}
}

func TestImportRejectsWrongPKCS12Password(t *testing.T) {
	dir := t.TempDir()
	caPEM, p12 := openVPNTestIdentity(t, "correct-password")
	ovpnPath := filepath.Join(dir, "enterprise.ovpn")
	caPath := filepath.Join(dir, "ca.crt")
	p12Path := filepath.Join(dir, "client.p12")
	if err := os.WriteFile(ovpnPath, []byte("client\nremote vpn.example.com 1194\nca ca.crt\npkcs12 client.p12\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p12Path, p12, 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := Import(ImportOptions{OVPNPath: ovpnPath, CAPath: caPath, PKCS12Path: p12Path, PKCS12Password: "wrong-password"})
	if err == nil || !strings.Contains(err.Error(), "check its password") {
		t.Fatalf("wrong password error = %v", err)
	}
}

func openVPNTestIdentity(t *testing.T, password string) ([]byte, []byte) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CrossLink Test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "CrossLink Test Client"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, ca, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	client, err := x509.ParseCertificate(clientDER)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := pkcs12.Modern.Encode(clientKey, client, []*x509.Certificate{ca}, password)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), bundle
}
