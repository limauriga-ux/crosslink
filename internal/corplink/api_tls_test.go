package corplink

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTLSServerNameForIPUsesAuthenticatedCompanyHost(t *testing.T) {
	session := LoadSession(t.TempDir() + "/session.json")
	session.Server = "https://gateway.example.com:10443"
	if got := tlsServerNameForAddress(session, "192.0.2.10:8001"); got != "gateway.example.com" {
		t.Fatalf("TLS server name = %q, want gateway.example.com", got)
	}
	if got := tlsServerNameForAddress(session, "public.example.net:443"); got != "public.example.net" {
		t.Fatalf("hostname TLS server name = %q", got)
	}
}

func TestHTTPTransportVerifiesDNSCertificateWhenDialingNodeIP(t *testing.T) {
	certificate, parsedCertificate := dnsOnlyTestCertificate(t, "gateway.example.com")
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	defer server.Close()

	roots := x509.NewCertPool()
	roots.AddCert(parsedCertificate)
	session := LoadSession(t.TempDir() + "/session.json")
	session.Server = "https://gateway.example.com:10443"
	dialer := &net.Dialer{}
	client := &http.Client{
		Transport: newHTTPTransport(session, &tls.Config{RootCAs: roots}, dialer.DialContext),
		Timeout:   5 * time.Second,
	}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("request through IP with DNS-only certificate failed: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusNoContent)
	}
}

func dnsOnlyTestCertificate(t *testing.T, dnsName string) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	parsedCertificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{certificateDER}, PrivateKey: privateKey}, parsedCertificate
}
