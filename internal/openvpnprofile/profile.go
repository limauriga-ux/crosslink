package openvpnprofile

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const (
	Version         = 1
	EndpointTag     = "openvpn-enterprise"
	PushedDNSTag    = "crosslink-openvpn-pushed-dns"
	StaticDNSTag    = "crosslink-openvpn-static-dns"
	MaxSourceBytes  = 2 << 20
	MaxManagedBytes = 2 << 20
)

type Remote struct {
	Server  string `json:"server"`
	Port    uint16 `json:"port"`
	Network string `json:"network"`
}

type ControlWrap struct {
	Type      string `json:"type"`
	Key       string `json:"key"`
	Direction string `json:"direction,omitempty"`
}

// Profile is the complete, path-free OpenVPN client material CrossLink owns.
// Source paths, PKCS#12 passwords and OpenVPN login credentials are deliberately
// absent. The managed file itself is mode 0600 because ClientKey is sensitive.
type Profile struct {
	Version              int          `json:"version"`
	Name                 string       `json:"name"`
	Remotes              []Remote     `json:"remotes"`
	RemoteRandom         bool         `json:"remote_random,omitempty"`
	CertificateAuthority string       `json:"certificate_authority"`
	ClientCertificate    string       `json:"client_certificate"`
	ClientKey            string       `json:"client_key"`
	ServerName           string       `json:"server_name,omitempty"`
	ServerNameType       string       `json:"server_name_type,omitempty"`
	RemoteCertificateTLS string       `json:"remote_certificate_tls,omitempty"`
	CertificateProfile   string       `json:"certificate_profile,omitempty"`
	ControlWrap          *ControlWrap `json:"control_wrap,omitempty"`
	DataCiphers          []string     `json:"data_ciphers,omitempty"`
	DataCiphersFallback  string       `json:"data_ciphers_fallback,omitempty"`
	Auth                 string       `json:"auth,omitempty"`
	RouteNoPull          bool         `json:"route_no_pull,omitempty"`
	Routes               []string     `json:"routes,omitempty"`
	DNSServers           []string     `json:"dns_servers,omitempty"`
	Domains              []string     `json:"domains,omitempty"`
	RenegotiateInterval  string       `json:"renegotiate_interval,omitempty"`
	MTU                  uint32       `json:"mtu,omitempty"`
	AuthUserPass         bool         `json:"auth_user_pass,omitempty"`
	StaticChallenge      string       `json:"static_challenge,omitempty"`
	StaticChallengeEcho  bool         `json:"static_challenge_echo,omitempty"`
}

type ImportOptions struct {
	OVPNPath       string
	CAPath         string
	PKCS12Path     string
	PKCS12Password string
	LegacyBFCompat bool
}

type ImportReport struct {
	Name                 string
	Server               string
	Network              string
	Routes               int
	Domains              int
	DNSServers           int
	RequiresCredentials  bool
	LegacyCipherFallback bool
	CertificateExpiresAt int64
	Warnings             []string
}

type parsedSource struct {
	profile       Profile
	inlineCA      string
	inlineCert    string
	inlineKey     string
	caReference   string
	p12Reference  string
	controlBlocks map[string]string
	warnings      []string
}

func (p Profile) Report() ImportReport {
	report := ImportReport{
		Name:                 p.Name,
		Routes:               len(p.Routes),
		Domains:              len(p.Domains),
		DNSServers:           len(p.DNSServers),
		RequiresCredentials:  p.AuthUserPass,
		LegacyCipherFallback: p.DataCiphersFallback == "BF-CBC",
	}
	if len(p.Remotes) > 0 {
		report.Server = net.JoinHostPort(p.Remotes[0].Server, strconv.Itoa(int(p.Remotes[0].Port)))
		report.Network = p.Remotes[0].Network
	}
	if certificatePEM, err := normalizeCertificatePEM([]byte(p.ClientCertificate)); err == nil {
		if block, _ := pem.Decode([]byte(certificatePEM)); block != nil {
			if certificate, parseErr := x509.ParseCertificate(block.Bytes); parseErr == nil {
				report.CertificateExpiresAt = certificate.NotAfter.Unix()
			}
		}
	}
	return report
}

func Import(options ImportOptions) (Profile, ImportReport, error) {
	ovpnPath := strings.TrimSpace(options.OVPNPath)
	if ovpnPath == "" {
		return Profile{}, ImportReport{}, errors.New("OpenVPN profile path is empty")
	}
	content, err := readRegularFile(ovpnPath, MaxSourceBytes)
	if err != nil {
		return Profile{}, ImportReport{}, fmt.Errorf("read OpenVPN profile: %w", err)
	}
	parsed, err := parseOVPN(content, filepath.Base(ovpnPath))
	if err != nil {
		return Profile{}, ImportReport{}, err
	}

	caPEM := parsed.inlineCA
	if caPath := strings.TrimSpace(options.CAPath); caPath != "" {
		externalCA, readErr := readRegularFile(caPath, MaxSourceBytes)
		if readErr != nil {
			return Profile{}, ImportReport{}, fmt.Errorf("read CA certificate: %w", readErr)
		}
		if caPEM != "" {
			equal, compareErr := sameFirstCertificate([]byte(caPEM), externalCA)
			if compareErr != nil {
				return Profile{}, ImportReport{}, fmt.Errorf("compare inline and selected CA certificates: %w", compareErr)
			}
			if !equal {
				return Profile{}, ImportReport{}, errors.New("selected CA certificate does not match the CA embedded in the OpenVPN profile")
			}
		}
		caPEM = string(externalCA)
	}
	if caPEM == "" {
		if parsed.caReference != "" {
			return Profile{}, ImportReport{}, fmt.Errorf("OpenVPN profile references CA file %q; select that CA file explicitly", parsed.caReference)
		}
		return Profile{}, ImportReport{}, errors.New("OpenVPN profile contains no CA certificate; select a CA file")
	}
	caPEM, err = normalizeCertificatePEM([]byte(caPEM))
	if err != nil {
		return Profile{}, ImportReport{}, fmt.Errorf("CA certificate: %w", err)
	}

	clientCertificate := parsed.inlineCert
	clientKey := parsed.inlineKey
	var leaf *x509.Certificate
	if p12Path := strings.TrimSpace(options.PKCS12Path); p12Path != "" {
		p12Data, readErr := readRegularFile(p12Path, MaxSourceBytes)
		if readErr != nil {
			return Profile{}, ImportReport{}, fmt.Errorf("read PKCS#12 bundle: %w", readErr)
		}
		privateKey, certificate, chain, decodeErr := pkcs12.DecodeChain(p12Data, options.PKCS12Password)
		clear(p12Data)
		if decodeErr != nil {
			return Profile{}, ImportReport{}, fmt.Errorf("decode PKCS#12 bundle (check its password): %w", decodeErr)
		}
		clientCertificate, clientKey, err = encodeClientIdentity(privateKey, certificate, chain)
		if err != nil {
			return Profile{}, ImportReport{}, err
		}
		leaf = certificate
	} else if parsed.p12Reference != "" {
		return Profile{}, ImportReport{}, fmt.Errorf("OpenVPN profile references PKCS#12 file %q; select that file explicitly", parsed.p12Reference)
	}
	if clientCertificate == "" || clientKey == "" {
		return Profile{}, ImportReport{}, errors.New("a client certificate and private key are required; select the client PKCS#12 file")
	}
	clientCertificate, err = normalizeCertificatePEM([]byte(clientCertificate))
	if err != nil {
		return Profile{}, ImportReport{}, fmt.Errorf("client certificate: %w", err)
	}
	clientKey, err = normalizePrivateKeyPEM([]byte(clientKey))
	if err != nil {
		return Profile{}, ImportReport{}, fmt.Errorf("client private key: %w", err)
	}
	pair, err := tls.X509KeyPair([]byte(clientCertificate), []byte(clientKey))
	if err != nil {
		return Profile{}, ImportReport{}, fmt.Errorf("client certificate and key do not match: %w", err)
	}
	if leaf == nil && len(pair.Certificate) > 0 {
		leaf, err = x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return Profile{}, ImportReport{}, fmt.Errorf("parse client certificate: %w", err)
		}
	}
	if leaf == nil {
		return Profile{}, ImportReport{}, errors.New("client certificate bundle has no leaf certificate")
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return Profile{}, ImportReport{}, fmt.Errorf("client certificate is not valid before %s", leaf.NotBefore.Format(time.RFC3339))
	}
	if !now.Before(leaf.NotAfter) {
		return Profile{}, ImportReport{}, fmt.Errorf("client certificate expired at %s", leaf.NotAfter.Format(time.RFC3339))
	}

	profile := parsed.profile
	profile.CertificateAuthority = caPEM
	profile.ClientCertificate = clientCertificate
	profile.ClientKey = clientKey
	if profile.RemoteCertificateTLS == "" {
		profile.RemoteCertificateTLS = "server"
	}
	if options.LegacyBFCompat && profile.DataCiphersFallback == "" {
		profile.DataCiphersFallback = "BF-CBC"
		parsed.warnings = append(parsed.warnings, "已启用旧式 BF-CBC 数据通道兼容；仅用于该 OpenVPN 企业端点")
	}
	if err := profile.Validate(); err != nil {
		return Profile{}, ImportReport{}, err
	}
	report := profile.Report()
	report.CertificateExpiresAt = leaf.NotAfter.Unix()
	report.Warnings = append([]string(nil), parsed.warnings...)
	return profile, report, nil
}

func (p Profile) Validate() error {
	if p.Version != Version {
		return fmt.Errorf("unsupported managed OpenVPN profile version %d", p.Version)
	}
	if strings.TrimSpace(p.Name) == "" {
		return errors.New("managed OpenVPN profile name is empty")
	}
	if len(p.Remotes) == 0 {
		return errors.New("managed OpenVPN profile has no remote server")
	}
	for index, remote := range p.Remotes {
		if err := validateRemote(remote); err != nil {
			return fmt.Errorf("remote %d: %w", index+1, err)
		}
	}
	if _, err := normalizeCertificatePEM([]byte(p.CertificateAuthority)); err != nil {
		return fmt.Errorf("managed CA certificate: %w", err)
	}
	certificate, err := normalizeCertificatePEM([]byte(p.ClientCertificate))
	if err != nil {
		return fmt.Errorf("managed client certificate: %w", err)
	}
	key, err := normalizePrivateKeyPEM([]byte(p.ClientKey))
	if err != nil {
		return fmt.Errorf("managed client key: %w", err)
	}
	if _, err := tls.X509KeyPair([]byte(certificate), []byte(key)); err != nil {
		return fmt.Errorf("managed client identity: %w", err)
	}
	for _, route := range p.Routes {
		prefix, parseErr := netip.ParsePrefix(route)
		if parseErr != nil || !prefix.IsValid() || prefix != prefix.Masked() {
			return fmt.Errorf("invalid managed OpenVPN route %q", route)
		}
	}
	for _, server := range p.DNSServers {
		if address, parseErr := netip.ParseAddr(server); parseErr != nil || !address.IsValid() {
			return fmt.Errorf("invalid managed OpenVPN DNS server %q", server)
		}
	}
	for _, domain := range p.Domains {
		if err := validateDomain(domain); err != nil {
			return fmt.Errorf("invalid managed OpenVPN domain %q: %w", domain, err)
		}
	}
	if len(p.StaticChallenge) > 512 {
		return errors.New("managed OpenVPN static challenge exceeds 512 bytes")
	}
	if p.ControlWrap != nil {
		switch p.ControlWrap.Type {
		case "tls_auth", "tls_crypt", "tls_crypt_v2":
		default:
			return fmt.Errorf("unsupported managed control wrap %q", p.ControlWrap.Type)
		}
		if strings.TrimSpace(p.ControlWrap.Key) == "" {
			return errors.New("managed OpenVPN control key is empty")
		}
		if p.ControlWrap.Direction != "" && p.ControlWrap.Direction != "client" && p.ControlWrap.Direction != "server" {
			return fmt.Errorf("unsupported managed control key direction %q", p.ControlWrap.Direction)
		}
	}
	return nil
}

func (p Profile) Endpoint(username, password, directInterface, domainResolver string) map[string]any {
	endpoint := map[string]any{
		"type":       "openvpn-client",
		"tag":        EndpointTag,
		"system":     false,
		"mode":       "tls",
		"auth_retry": "interact",
		"tls": map[string]any{
			"certificate":            p.CertificateAuthority,
			"client_certificate":     p.ClientCertificate,
			"client_key":             p.ClientKey,
			"remote_certificate_tls": nonEmpty(p.RemoteCertificateTLS, "server"),
		},
	}
	if len(p.Remotes) == 1 {
		endpoint["server"] = p.Remotes[0].Server
		endpoint["server_port"] = p.Remotes[0].Port
		endpoint["network"] = p.Remotes[0].Network
	} else {
		remotes := make([]any, 0, len(p.Remotes))
		for _, remote := range p.Remotes {
			remotes = append(remotes, map[string]any{"server": remote.Server, "server_port": remote.Port, "network": remote.Network})
		}
		endpoint["servers"] = remotes
		endpoint["remote_random"] = p.RemoteRandom
	}
	if username != "" || password != "" {
		endpoint["username"] = username
		endpoint["password"] = password
	}
	if p.StaticChallenge != "" {
		endpoint["static_challenge"] = p.StaticChallenge
		endpoint["static_challenge_echo"] = p.StaticChallengeEcho
	}
	if p.RouteNoPull {
		endpoint["route_no_pull"] = true
	}
	if len(p.Routes) > 0 {
		endpoint["routes"] = append([]string(nil), p.Routes...)
	}
	if len(p.DataCiphers) > 0 {
		endpoint["data_ciphers"] = append([]string(nil), p.DataCiphers...)
	}
	if p.DataCiphersFallback != "" {
		endpoint["data_ciphers_fallback"] = p.DataCiphersFallback
	}
	if p.Auth != "" {
		endpoint["auth"] = p.Auth
	}
	if p.RenegotiateInterval != "" {
		endpoint["renegotiate_interval"] = p.RenegotiateInterval
	}
	if p.MTU != 0 {
		endpoint["mtu"] = p.MTU
	}
	if directInterface != "" {
		endpoint["bind_interface"] = directInterface
	}
	if domainResolver != "" && anyRemoteIsDomain(p.Remotes) {
		endpoint["domain_resolver"] = domainResolver
	}
	tlsOptions := endpoint["tls"].(map[string]any)
	if p.ServerName != "" {
		tlsOptions["server_name"] = p.ServerName
	}
	if p.ServerNameType != "" {
		tlsOptions["server_name_type"] = p.ServerNameType
	}
	if p.CertificateProfile != "" {
		tlsOptions["certificate_profile"] = p.CertificateProfile
	}
	if p.ControlWrap != nil {
		tlsOptions["control_wrap"] = map[string]any{
			"type":      p.ControlWrap.Type,
			"key":       p.ControlWrap.Key,
			"direction": p.ControlWrap.Direction,
		}
	}
	return endpoint
}

func parseOVPN(content []byte, sourceName string) (parsedSource, error) {
	if len(content) > MaxSourceBytes {
		return parsedSource{}, fmt.Errorf("OpenVPN profile exceeds %d bytes", MaxSourceBytes)
	}
	result := parsedSource{
		profile: Profile{
			Version: Version,
			Name:    strings.TrimSuffix(sourceName, filepath.Ext(sourceName)),
		},
		controlBlocks: make(map[string]string),
	}
	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	proto := "udp"
	clientMode := false
	for index := 0; index < len(lines); index++ {
		raw := strings.TrimSpace(lines[index])
		if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, ";") {
			continue
		}
		if strings.HasPrefix(raw, "<") {
			name, ok := inlineBlockName(raw)
			if !ok {
				return parsedSource{}, fmt.Errorf("OpenVPN line %d: unsupported inline block %q", index+1, raw)
			}
			var blockLines []string
			closed := false
			for index++; index < len(lines); index++ {
				if strings.EqualFold(strings.TrimSpace(lines[index]), "</"+name+">") {
					closed = true
					break
				}
				blockLines = append(blockLines, lines[index])
			}
			if !closed {
				return parsedSource{}, fmt.Errorf("OpenVPN inline block <%s> is not closed", name)
			}
			block := strings.TrimSpace(strings.Join(blockLines, "\n")) + "\n"
			switch name {
			case "ca":
				result.inlineCA = block
			case "cert":
				result.inlineCert = block
			case "key":
				result.inlineKey = block
			case "tls-auth", "tls-crypt", "tls-crypt-v2":
				result.controlBlocks[name] = block
			}
			continue
		}
		fields, err := splitDirective(raw)
		if err != nil {
			return parsedSource{}, fmt.Errorf("OpenVPN line %d: %w", index+1, err)
		}
		if len(fields) == 0 {
			continue
		}
		directive := strings.ToLower(strings.TrimLeft(fields[0], "-"))
		args := fields[1:]
		switch directive {
		case "client":
			if len(args) != 0 {
				return parsedSource{}, directiveArity(index, directive)
			}
			clientMode = true
		case "proto":
			if len(args) != 1 {
				return parsedSource{}, directiveArity(index, directive)
			}
			proto, err = normalizeNetwork(args[0])
			if err != nil {
				return parsedSource{}, fmt.Errorf("OpenVPN line %d: %w", index+1, err)
			}
		case "remote":
			if len(args) < 1 || len(args) > 3 {
				return parsedSource{}, directiveArity(index, directive)
			}
			port := uint64(1194)
			if len(args) >= 2 {
				port, err = strconv.ParseUint(args[1], 10, 16)
				if err != nil || port == 0 {
					return parsedSource{}, fmt.Errorf("OpenVPN line %d: invalid remote port %q", index+1, args[1])
				}
			}
			remoteNetwork := proto
			if len(args) == 3 {
				remoteNetwork, err = normalizeNetwork(args[2])
				if err != nil {
					return parsedSource{}, fmt.Errorf("OpenVPN line %d: %w", index+1, err)
				}
			}
			remote := Remote{Server: strings.Trim(args[0], "[]"), Port: uint16(port), Network: remoteNetwork}
			if err := validateRemote(remote); err != nil {
				return parsedSource{}, fmt.Errorf("OpenVPN line %d: %w", index+1, err)
			}
			result.profile.Remotes = append(result.profile.Remotes, remote)
		case "remote-random":
			result.profile.RemoteRandom = true
		case "ca":
			if len(args) != 1 {
				return parsedSource{}, directiveArity(index, directive)
			}
			result.caReference = args[0]
		case "pkcs12":
			if len(args) != 1 {
				return parsedSource{}, directiveArity(index, directive)
			}
			result.p12Reference = args[0]
		case "cert", "key":
			return parsedSource{}, fmt.Errorf("OpenVPN line %d: external %s paths are not imported; use a selected PKCS#12 bundle or inline material", index+1, directive)
		case "auth-user-pass":
			if len(args) != 0 {
				return parsedSource{}, fmt.Errorf("OpenVPN line %d: credential files are not allowed; CrossLink accepts credentials only over IPC", index+1)
			}
			result.profile.AuthUserPass = true
		case "remote-cert-tls":
			if len(args) != 1 || (args[0] != "server" && args[0] != "client") {
				return parsedSource{}, fmt.Errorf("OpenVPN line %d: remote-cert-tls must be server or client", index+1)
			}
			result.profile.RemoteCertificateTLS = args[0]
		case "verify-x509-name":
			if len(args) < 1 || len(args) > 2 {
				return parsedSource{}, directiveArity(index, directive)
			}
			result.profile.ServerName = args[0]
			if len(args) == 2 {
				switch args[1] {
				case "name", "name-prefix", "subject":
					result.profile.ServerNameType = args[1]
				default:
					return parsedSource{}, fmt.Errorf("OpenVPN line %d: unsupported verify-x509-name type %q", index+1, args[1])
				}
			}
		case "tls-cert-profile":
			if len(args) != 1 {
				return parsedSource{}, directiveArity(index, directive)
			}
			switch args[0] {
			case "legacy", "preferred", "insecure", "suiteb":
				result.profile.CertificateProfile = args[0]
			default:
				return parsedSource{}, fmt.Errorf("OpenVPN line %d: unsupported TLS certificate profile %q", index+1, args[0])
			}
		case "data-ciphers":
			if len(args) != 1 {
				return parsedSource{}, directiveArity(index, directive)
			}
			result.profile.DataCiphers = splitNonEmpty(args[0], ":")
		case "data-ciphers-fallback", "cipher":
			if len(args) != 1 {
				return parsedSource{}, directiveArity(index, directive)
			}
			result.profile.DataCiphersFallback = strings.ToUpper(args[0])
		case "auth":
			if len(args) != 1 {
				return parsedSource{}, directiveArity(index, directive)
			}
			result.profile.Auth = strings.ToUpper(args[0])
		case "static-challenge":
			if len(args) != 2 {
				return parsedSource{}, directiveArity(index, directive)
			}
			if len(args[0]) > 512 {
				return parsedSource{}, fmt.Errorf("OpenVPN line %d: static challenge exceeds 512 bytes", index+1)
			}
			echo, parseErr := strconv.ParseUint(args[1], 10, 1)
			if parseErr != nil {
				return parsedSource{}, fmt.Errorf("OpenVPN line %d: static-challenge echo must be 0 or 1", index+1)
			}
			result.profile.StaticChallenge = args[0]
			result.profile.StaticChallengeEcho = echo == 1
		case "route-nopull":
			result.profile.RouteNoPull = true
		case "route":
			route, parseErr := parseIPv4Route(args)
			if parseErr != nil {
				return parsedSource{}, fmt.Errorf("OpenVPN line %d: %w", index+1, parseErr)
			}
			result.profile.Routes = append(result.profile.Routes, route)
		case "route-ipv6":
			route, parseErr := parseIPv6Route(args)
			if parseErr != nil {
				return parsedSource{}, fmt.Errorf("OpenVPN line %d: %w", index+1, parseErr)
			}
			result.profile.Routes = append(result.profile.Routes, route)
		case "dhcp-option":
			if err := applyDHCPOption(&result.profile, args); err != nil {
				return parsedSource{}, fmt.Errorf("OpenVPN line %d: %w", index+1, err)
			}
		case "reneg-sec":
			if len(args) != 1 {
				return parsedSource{}, directiveArity(index, directive)
			}
			seconds, parseErr := strconv.ParseUint(args[0], 10, 32)
			if parseErr != nil {
				return parsedSource{}, fmt.Errorf("OpenVPN line %d: invalid reneg-sec %q", index+1, args[0])
			}
			result.profile.RenegotiateInterval = (time.Duration(seconds) * time.Second).String()
		case "tun-mtu":
			if len(args) != 1 {
				return parsedSource{}, directiveArity(index, directive)
			}
			mtu, parseErr := strconv.ParseUint(args[0], 10, 32)
			if parseErr != nil || mtu < 576 || mtu > 9000 {
				return parsedSource{}, fmt.Errorf("OpenVPN line %d: invalid tun-mtu %q", index+1, args[0])
			}
			result.profile.MTU = uint32(mtu)
		case "tls-auth", "tls-crypt", "tls-crypt-v2":
			if len(args) == 0 {
				return parsedSource{}, fmt.Errorf("OpenVPN line %d: %s requires inline key material", index+1, directive)
			}
			return parsedSource{}, fmt.Errorf("OpenVPN line %d: external %s key paths are not allowed; embed the key in the profile", index+1, directive)
		case "key-direction":
			if len(args) != 1 {
				return parsedSource{}, directiveArity(index, directive)
			}
			if args[0] != "0" && args[0] != "1" {
				return parsedSource{}, fmt.Errorf("OpenVPN line %d: key-direction must be 0 or 1", index+1)
			}
			direction := "server"
			if args[0] == "1" {
				direction = "client"
			}
			if result.profile.ControlWrap == nil {
				result.profile.ControlWrap = &ControlWrap{Direction: direction}
			} else {
				result.profile.ControlWrap.Direction = direction
			}
		case "dev":
			if len(args) != 1 || !strings.HasPrefix(strings.ToLower(args[0]), "tun") {
				return parsedSource{}, fmt.Errorf("OpenVPN line %d: only tun devices are supported", index+1)
			}
		case "resolv-retry", "nobind", "persist-key", "persist-tun", "auth-nocache", "verb", "mute", "max-routes", "connect-retry", "connect-timeout":
			// Safe client-process hints; the embedded endpoint owns their lifecycle.
		case "script-security", "up", "down", "route-up", "route-pre-down", "ipchange", "learn-address", "tls-verify", "auth-user-pass-verify", "client-connect", "client-disconnect", "plugin", "management", "management-client", "management-external-key", "setenv", "setenv-safe":
			return parsedSource{}, fmt.Errorf("OpenVPN line %d: directive %q is forbidden", index+1, directive)
		default:
			return parsedSource{}, fmt.Errorf("OpenVPN line %d: unsupported directive %q", index+1, directive)
		}
	}
	if !clientMode {
		return parsedSource{}, errors.New("OpenVPN profile is not a client profile")
	}
	if len(result.profile.Remotes) == 0 {
		return parsedSource{}, errors.New("OpenVPN profile contains no remote server")
	}
	for blockName, key := range result.controlBlocks {
		wrapType := strings.ReplaceAll(blockName, "-", "_")
		if result.profile.ControlWrap != nil && result.profile.ControlWrap.Type != "" && result.profile.ControlWrap.Type != wrapType {
			return parsedSource{}, errors.New("OpenVPN profile contains multiple control-channel key types")
		}
		direction := ""
		if result.profile.ControlWrap != nil {
			direction = result.profile.ControlWrap.Direction
		}
		result.profile.ControlWrap = &ControlWrap{Type: wrapType, Key: key, Direction: direction}
	}
	if result.profile.ControlWrap != nil && result.profile.ControlWrap.Type == "" {
		return parsedSource{}, errors.New("key-direction is present without an inline tls-auth key")
	}
	result.profile.Routes = unique(result.profile.Routes)
	result.profile.DNSServers = unique(result.profile.DNSServers)
	result.profile.Domains = unique(result.profile.Domains)
	return result, nil
}

func inlineBlockName(raw string) (string, bool) {
	if !strings.HasPrefix(raw, "<") || !strings.HasSuffix(raw, ">") || strings.HasPrefix(raw, "</") {
		return "", false
	}
	name := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(raw, "<"), ">")))
	switch name {
	case "ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2":
		return name, true
	default:
		return "", false
	}
}

func splitDirective(line string) ([]string, error) {
	var fields []string
	var current strings.Builder
	var quote rune
	escaped := false
	flush := func() {
		if current.Len() > 0 {
			fields = append(fields, current.String())
			current.Reset()
		}
	}
	for _, value := range line {
		if escaped {
			current.WriteRune(value)
			escaped = false
			continue
		}
		if value == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if value == quote {
				quote = 0
			} else {
				current.WriteRune(value)
			}
			continue
		}
		if value == '\'' || value == '"' {
			quote = value
			continue
		}
		if unicode.IsSpace(value) {
			flush()
			continue
		}
		current.WriteRune(value)
	}
	if escaped {
		return nil, errors.New("trailing escape")
	}
	if quote != 0 {
		return nil, errors.New("unterminated quote")
	}
	flush()
	return fields, nil
}

func parseIPv4Route(args []string) (string, error) {
	if len(args) < 1 || len(args) > 4 {
		return "", errors.New("route expects network [netmask] [vpn_gateway] [metric]")
	}
	var prefix netip.Prefix
	var err error
	next := 1
	if strings.Contains(args[0], "/") {
		prefix, err = netip.ParsePrefix(args[0])
	} else {
		address, parseErr := netip.ParseAddr(args[0])
		if parseErr != nil || !address.Is4() {
			return "", fmt.Errorf("invalid IPv4 route address %q", args[0])
		}
		bits := 32
		if len(args) > 1 && net.ParseIP(args[1]) != nil {
			maskIP := net.ParseIP(args[1]).To4()
			if maskIP == nil {
				return "", fmt.Errorf("invalid IPv4 route mask %q", args[1])
			}
			var total int
			bits, total = net.IPMask(maskIP).Size()
			if total != 32 {
				return "", fmt.Errorf("non-contiguous IPv4 route mask %q", args[1])
			}
			next = 2
		}
		prefix = netip.PrefixFrom(address, bits)
	}
	if err != nil || !prefix.IsValid() || !prefix.Addr().Is4() {
		return "", fmt.Errorf("invalid IPv4 route %q", args[0])
	}
	if len(args) > next {
		gateway := strings.ToLower(args[next])
		if gateway != "vpn_gateway" {
			if _, metricErr := strconv.Atoi(gateway); metricErr != nil {
				return "", fmt.Errorf("route gateway %q is not supported; only vpn_gateway is allowed", args[next])
			}
		}
	}
	return prefix.Masked().String(), nil
}

func parseIPv6Route(args []string) (string, error) {
	if len(args) < 1 || len(args) > 3 {
		return "", errors.New("route-ipv6 expects prefix [vpn_gateway] [metric]")
	}
	prefix, err := netip.ParsePrefix(args[0])
	if err != nil || !prefix.Addr().Is6() {
		return "", fmt.Errorf("invalid IPv6 route %q", args[0])
	}
	if len(args) > 1 && strings.ToLower(args[1]) != "vpn_gateway" {
		if _, metricErr := strconv.Atoi(args[1]); metricErr != nil {
			return "", fmt.Errorf("route-ipv6 gateway %q is not supported; only vpn_gateway is allowed", args[1])
		}
	}
	return prefix.Masked().String(), nil
}

func applyDHCPOption(profile *Profile, args []string) error {
	if len(args) < 2 {
		return errors.New("dhcp-option requires a name and value")
	}
	name := strings.ToUpper(args[0])
	value := strings.TrimSpace(args[1])
	switch name {
	case "DNS", "DNS6":
		address, err := netip.ParseAddr(strings.Trim(value, "[]"))
		if err != nil || !address.IsValid() {
			return fmt.Errorf("invalid DHCP DNS address %q", value)
		}
		profile.DNSServers = append(profile.DNSServers, address.String())
	case "DOMAIN", "DOMAIN-ROUTE", "DOMAIN-SEARCH", "ADAPTER_DOMAIN_SUFFIX":
		domain := normalizeDomain(value)
		if err := validateDomain(domain); err != nil {
			return err
		}
		profile.Domains = append(profile.Domains, domain)
	default:
		return fmt.Errorf("unsupported dhcp-option %q", name)
	}
	return nil
}

func normalizeNetwork(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "tcp", "tcp-client", "tcp4", "tcp4-client", "tcp6", "tcp6-client":
		return "tcp", nil
	case "udp", "udp4", "udp6":
		return "udp", nil
	default:
		return "", fmt.Errorf("unsupported OpenVPN transport %q", raw)
	}
}

func validateRemote(remote Remote) error {
	server := strings.TrimSpace(remote.Server)
	if server == "" || strings.ContainsAny(server, " /\\\t\r\n") {
		return fmt.Errorf("invalid server %q", remote.Server)
	}
	if net.ParseIP(server) == nil {
		if err := validateDomain(server); err != nil {
			return fmt.Errorf("invalid server domain %q: %w", server, err)
		}
	}
	if remote.Port == 0 {
		return errors.New("server port is zero")
	}
	if remote.Network != "tcp" && remote.Network != "udp" {
		return fmt.Errorf("unsupported network %q", remote.Network)
	}
	return nil
}

func validateDomain(raw string) error {
	domain := normalizeDomain(raw)
	if domain == "" || len(domain) > 253 || strings.Contains(domain, "..") {
		return errors.New("invalid domain")
	}
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("invalid domain label")
		}
		for _, value := range label {
			if !(value >= 'a' && value <= 'z') && !(value >= '0' && value <= '9') && value != '-' {
				return errors.New("domain must use ASCII letters, digits and hyphens")
			}
		}
	}
	return nil
}

func normalizeDomain(raw string) string {
	return strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(raw)), "."), ".")
}

func normalizeCertificatePEM(content []byte) (string, error) {
	remaining := bytes.TrimSpace(content)
	var output bytes.Buffer
	count := 0
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			return "", errors.New("contains non-PEM data")
		}
		if block.Type != "CERTIFICATE" {
			return "", fmt.Errorf("unexpected PEM block %q", block.Type)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return "", err
		}
		if err := pem.Encode(&output, &pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}); err != nil {
			return "", err
		}
		remaining = bytes.TrimSpace(rest)
		count++
	}
	if count == 0 {
		return "", errors.New("contains no certificate")
	}
	return output.String(), nil
}

func normalizePrivateKeyPEM(content []byte) (string, error) {
	block, rest := pem.Decode(bytes.TrimSpace(content))
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return "", errors.New("must contain exactly one PEM private key")
	}
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return "", fmt.Errorf("unsupported PEM block %q", block.Type)
	}
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

func encodeClientIdentity(privateKey any, certificate *x509.Certificate, chain []*x509.Certificate) (string, string, error) {
	if privateKey == nil || certificate == nil {
		return "", "", errors.New("PKCS#12 bundle is missing client identity")
	}
	var certificates bytes.Buffer
	for _, item := range append([]*x509.Certificate{certificate}, chain...) {
		if item == nil {
			continue
		}
		if err := pem.Encode(&certificates, &pem.Block{Type: "CERTIFICATE", Bytes: item.Raw}); err != nil {
			return "", "", err
		}
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("encode PKCS#12 private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if _, err := tls.X509KeyPair(certificates.Bytes(), keyPEM); err != nil {
		return "", "", fmt.Errorf("PKCS#12 certificate and private key do not match: %w", err)
	}
	return certificates.String(), string(keyPEM), nil
}

func sameFirstCertificate(left, right []byte) (bool, error) {
	leftBlock, _ := pem.Decode(left)
	rightBlock, _ := pem.Decode(right)
	if leftBlock == nil || rightBlock == nil {
		return false, errors.New("certificate is not PEM encoded")
	}
	return bytes.Equal(leftBlock.Bytes, rightBlock.Bytes), nil
}

func readRegularFile(path string, limit int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	return os.ReadFile(path)
}

func anyRemoteIsDomain(remotes []Remote) bool {
	for _, remote := range remotes {
		if net.ParseIP(remote.Server) == nil {
			return true
		}
	}
	return false
}

func splitNonEmpty(raw, separator string) []string {
	var values []string
	for _, value := range strings.Split(raw, separator) {
		if value = strings.TrimSpace(value); value != "" {
			values = append(values, strings.ToUpper(value))
		}
	}
	return unique(values)
}

func unique(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

func directiveArity(index int, directive string) error {
	return fmt.Errorf("OpenVPN line %d: invalid arguments for %s", index+1, directive)
}

func expandHome(path string) string {
	path = strings.TrimSpace(path)
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			if path == "~" {
				return home
			}
			return filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return path
}

func nonEmpty(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
