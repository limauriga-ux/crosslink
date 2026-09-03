package core

import (
	"errors"
	"fmt"
	"os"
	"strings"

	appconfig "github.com/limauriga-ux/crosslink/internal/config"
	"github.com/limauriga-ux/crosslink/internal/corpendpoint"
	"github.com/limauriga-ux/crosslink/internal/openvpnprofile"
	"github.com/limauriga-ux/crosslink/internal/profile"

	singjson "github.com/sagernet/sing/common/json"
)

const (
	corpEndpointTag = "corp"
	dnsTransportTag = "crosslink-dns"
	directTag       = "direct"
	mixedInboundTag = "mixed-in"
	tunInboundTag   = "tun-in"
	maxProfileBytes = 8 << 20
)

type compiledProfile struct {
	content      []byte
	defaultRoute string
	outboundTags []string
}

type openVPNRuntimeConfig struct {
	profile  openvpnprofile.Profile
	username string
	password string
}

func compileConfig(cfg *appconfig.Config) (compiledProfile, error) {
	return compileConfigWithOpenVPN(cfg, nil)
}

func compileConfigWithOpenVPN(cfg *appconfig.Config, openVPN *openVPNRuntimeConfig) (compiledProfile, error) {
	profileOutbounds, profileEndpoints, profileRules, profileFinal, err := loadProfile(cfg)
	if err != nil {
		return compiledProfile{}, err
	}

	outbounds := make([]any, 0, len(profileOutbounds)+2)
	outbounds = append(outbounds, map[string]any{"type": "direct", "tag": directTag})
	if openVPN == nil {
		// The tag remains resolvable while disconnected so persisted OPENVPN
		// rules fail closed rather than falling through to the public final.
		outbounds = append(outbounds, map[string]any{"type": "block", "tag": openvpnprofile.EndpointTag})
	}
	outboundTags := []string{directTag}
	for _, outbound := range profileOutbounds {
		tag, _ := outbound["tag"].(string)
		if tag == "" || tag == directTag || tag == corpEndpointTag || tag == openvpnprofile.EndpointTag || tag == corpendpoint.PublicAuthOutboundTag {
			continue
		}
		outbounds = append(outbounds, withBootstrapDomainResolver(outbound))
		outboundTags = append(outboundTags, tag)
	}
	endpoints := []any{map[string]any{"type": corpendpoint.Type, "tag": corpEndpointTag}}
	endpointTags := make([]string, 0, len(profileEndpoints))
	for _, endpoint := range profileEndpoints {
		tag, _ := endpoint["tag"].(string)
		if tag == "" || tag == corpEndpointTag || tag == directTag || tag == openvpnprofile.EndpointTag || containsString(outboundTags, tag) {
			continue
		}
		endpoints = append(endpoints, withBootstrapDomainResolver(endpoint))
		endpointTags = append(endpointTags, tag)
	}
	if openVPN != nil {
		endpoints = append(endpoints, openVPN.profile.Endpoint(openVPN.username, openVPN.password, cfg.DirectOutbound.Interface, bootstrapDNSTag))
		endpointTags = append(endpointTags, openvpnprofile.EndpointTag)
	}
	validTargets := append(append([]string(nil), outboundTags...), endpointTags...)
	// OPENVPN is a fixed local-rule target, implemented by either the active
	// endpoint above or the same-tag block outbound installed while offline.
	// It is intentionally absent from outboundTags so it can never become the
	// implicit public final when a Profile has no usable public node.

	rulePlan, err := loadRulePlan(cfg)
	if err != nil {
		return compiledProfile{}, err
	}
	prependRules, appendRules, err := profile.CompileRulePlan(rulePlan, validTargets)
	if err != nil {
		return compiledProfile{}, fmt.Errorf("compile injected rules: %w", err)
	}

	var routeRuleSets []any
	if cfg.Core.DomesticDirect {
		routeRuleSets, err = ensureDomesticRuleSets(cfg)
		if err != nil {
			return compiledProfile{}, fmt.Errorf("prepare domestic rule-sets: %w", err)
		}
	}

	finalOutbound := profileFinal
	if !containsString(outboundTags, finalOutbound) && !containsString(endpointTags, finalOutbound) {
		if len(outboundTags) > 1 {
			finalOutbound = outboundTags[1]
		} else {
			finalOutbound = directTag
		}
	}
	outbounds = append(outbounds, map[string]any{
		"type":   corpendpoint.PublicAuthOutboundType,
		"tag":    corpendpoint.PublicAuthOutboundTag,
		"detour": finalOutbound,
	})

	rules := []any{
		map[string]any{"action": "sniff"},
		map[string]any{"protocol": "dns", "action": "hijack-dns"},
		map[string]any{"preferred_by": []string{corpEndpointTag}, "action": "route", "outbound": corpEndpointTag},
	}
	rules = append(rules, prependRules...)
	if openVPN != nil {
		// A user-opened browser authentication challenge follows the public
		// final through this dynamic rule. The scope stays empty until the
		// daemon arms it for a trusted live challenge, and it must outrank the
		// static profile rules below: the challenge URL is the only way to
		// authenticate when it lives inside the claimed segments.
		rules = append(rules, map[string]any{
			"preferred_by": []string{corpendpoint.PublicAuthOutboundTag},
			"action":       "route",
			"outbound":     corpendpoint.PublicAuthOutboundTag,
		})
		// The imported OpenVPN profile is explicit user policy, so its static
		// routes and split-DNS domains outrank generic subscription Profile
		// boilerplate (for example a blanket 10.0.0.0/8 => DIRECT rule would
		// otherwise blackhole IP-literal traffic to OpenVPN-owned segments).
		// Deliberate local prepend rules above remain higher priority, and
		// matching traffic fails closed at the unready endpoint instead of
		// leaking into public/domestic fallbacks.
		if len(openVPN.profile.Domains) > 0 {
			rules = append(rules, map[string]any{
				"domain_suffix": append([]string(nil), openVPN.profile.Domains...),
				"action":        "route",
				"outbound":      openvpnprofile.EndpointTag,
			})
		}
		if len(openVPN.profile.Routes) > 0 {
			rules = append(rules, map[string]any{
				"ip_cidr":  append([]string(nil), openVPN.profile.Routes...),
				"action":   "route",
				"outbound": openvpnprofile.EndpointTag,
			})
		}
		// Pushed routes and split-DNS domains are known only after the server
		// configures the tunnel; preferred_by covers those dynamic additions.
		rules = append(rules, map[string]any{
			"preferred_by": []string{openvpnprofile.EndpointTag},
			"action":       "route",
			"outbound":     openvpnprofile.EndpointTag,
		})
	}
	rules = append(rules, profileRules...)
	rules = append(rules, appendRules...)
	if cfg.Core.DomesticDirect {
		rules = append(rules,
			map[string]any{"rule_set": []string{domesticDomainRuleSetTag}, "action": "route", "outbound": directTag},
			map[string]any{"rule_set": []string{domesticIPRuleSetTag}, "action": "route", "outbound": directTag},
		)
	}
	rules = append(rules, map[string]any{"ip_is_private": true, "action": "route", "outbound": directTag})

	inbounds := make([]any, 0, 2)
	if cfg.Core.TUNEnabled {
		tunInbound := map[string]any{
			"type":         "tun",
			"tag":          tunInboundTag,
			"address":      []string{fmt.Sprintf("%s/%d", cfg.TUN.IP, cfg.TUN.Mask)},
			"mtu":          cfg.TUN.MTU,
			"auto_route":   true,
			"strict_route": true,
			"stack":        "mixed",
		}
		if name := strings.TrimSpace(cfg.TUN.Name); name != "" {
			tunInbound["interface_name"] = name
		}
		inbounds = append(inbounds, tunInbound)
	}
	if cfg.Core.MixedPort > 0 {
		inbounds = append(inbounds, map[string]any{
			"type":        "mixed",
			"tag":         mixedInboundTag,
			"listen":      "127.0.0.1",
			"listen_port": cfg.Core.MixedPort,
		})
	}

	dnsServers, err := buildDNSServers(cfg.DNS.Upstream, finalOutbound, cfg.DirectOutbound.Interface)
	if err != nil {
		return compiledProfile{}, fmt.Errorf("compile DNS: %w", err)
	}
	var dnsRules []any
	if openVPN != nil {
		dnsRules = append(dnsRules, map[string]any{
			"preferred_by": []string{dnsTransportTag},
			"action":       "route",
			"server":       dnsTransportTag,
		})
		dnsServers = append(dnsServers, map[string]any{
			"type":                     "openvpn",
			"tag":                      openvpnprofile.PushedDNSTag,
			"endpoint":                 openvpnprofile.EndpointTag,
			"accept_default_resolvers": false,
			"accept_search_domain":     true,
		})
		staticDNSDefault := false
		if len(openVPN.profile.DNSServers) > 0 {
			dnsServers = append(dnsServers, map[string]any{
				"type":     openvpnprofile.StaticDNSType,
				"tag":      openvpnprofile.StaticDNSTag,
				"endpoint": openvpnprofile.EndpointTag,
				"servers":  append([]string(nil), openVPN.profile.DNSServers...),
				"domains":  append([]string(nil), openVPN.profile.Domains...),
			})
			if len(openVPN.profile.Domains) > 0 {
				dnsRules = append(dnsRules, map[string]any{
					"preferred_by": []string{openvpnprofile.StaticDNSTag},
					"action":       "route",
					"server":       openvpnprofile.StaticDNSTag,
				})
			} else {
				staticDNSDefault = true
			}
		}
		dnsRules = append(dnsRules, map[string]any{
			"preferred_by": []string{openvpnprofile.PushedDNSTag},
			"action":       "route",
			"server":       openvpnprofile.PushedDNSTag,
		})
		if staticDNSDefault {
			dnsRules = append(dnsRules, map[string]any{
				"action": "route",
				"server": openvpnprofile.StaticDNSTag,
			})
		}
	}
	routeOptions := map[string]any{
		"rules":                   rules,
		"final":                   finalOutbound,
		"auto_detect_interface":   true,
		"default_domain_resolver": dnsTransportTag,
	}
	if len(routeRuleSets) > 0 {
		routeOptions["rule_set"] = routeRuleSets
	}
	root := map[string]any{
		"log": map[string]any{
			"level":     nonEmpty(cfg.Core.LogLevel, "info"),
			"timestamp": true,
		},
		"dns": map[string]any{
			"servers":  dnsServers,
			"final":    dnsTransportTag,
			"strategy": "ipv4_only",
			"rules":    dnsRules,
		},
		"endpoints": endpoints,
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route":     routeOptions,
	}

	content, err := singjson.Marshal(root)
	if err != nil {
		return compiledProfile{}, fmt.Errorf("encode sing-box configuration: %w", err)
	}
	return compiledProfile{content: content, defaultRoute: finalOutbound, outboundTags: outboundTags}, nil
}

func loadProfile(cfg *appconfig.Config) ([]map[string]any, []map[string]any, []any, string, error) {
	content, err := cfg.ReadCoreProfile(maxProfileBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, nil, "", nil
		}
		return nil, nil, nil, "", fmt.Errorf("read proxy profile: %w", err)
	}
	root, err := singjson.UnmarshalExtended[map[string]any](content)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("parse proxy profile: %w", err)
	}

	var outbounds []map[string]any
	if rawOutbounds, ok := root["outbounds"].([]any); ok {
		for _, raw := range rawOutbounds {
			if outbound, ok := raw.(map[string]any); ok {
				outbounds = append(outbounds, outbound)
			}
		}
	}
	var endpoints []map[string]any
	if rawEndpoints, ok := root["endpoints"].([]any); ok {
		for _, raw := range rawEndpoints {
			if endpoint, ok := raw.(map[string]any); ok {
				endpoints = append(endpoints, endpoint)
			}
		}
	}

	var rules []any
	var final string
	if route, ok := root["route"].(map[string]any); ok {
		if rawRules, ok := route["rules"].([]any); ok {
			rules = append(rules, rawRules...)
		}
		final, _ = route["final"].(string)
	}
	return outbounds, endpoints, rules, final, nil
}

func loadRulePlan(cfg *appconfig.Config) (profile.RulePlan, error) {
	content, err := cfg.ReadRulePlan(profile.MaxRulePlanBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return profile.RulePlan{Version: profile.RulePlanVersion}, nil
		}
		return profile.RulePlan{}, err
	}
	return profile.ParseRulePlan(content)
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func nonEmpty(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
