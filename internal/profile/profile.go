package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	singjson "github.com/sagernet/sing/common/json"
	"github.com/xmdhs/clash2singbox/convert"
	"github.com/xmdhs/clash2singbox/model"
	"github.com/xmdhs/clash2singbox/model/clash"
	"gopkg.in/yaml.v3"
)

const MaxBytes = 8 << 20

type Report struct {
	Format    string   `json:"format"`
	Nodes     int      `json:"nodes"`
	Endpoints int      `json:"endpoints"`
	Warnings  []string `json:"warnings,omitempty"`
}

var supportedOutboundTypes = map[string]bool{
	"direct": true, "block": true, "selector": true, "urltest": true,
	"socks": true, "http": true, "shadowsocks": true, "vmess": true,
	"vless": true, "trojan": true, "anytls": true, "hysteria": true,
	"hysteria2": true, "tuic": true,
}

var supportedEndpointTypes = map[string]bool{"wireguard": true}

// Normalize converts either a constrained sing-box JSON profile or a Clash
// YAML profile into the fragment consumed by CrossLink. System TUN, DNS,
// services, and control APIs are never imported from remote content.
func Normalize(content []byte) ([]byte, Report, error) {
	if len(bytes.TrimSpace(content)) == 0 {
		return nil, Report{}, errors.New("profile is empty")
	}
	if len(content) > MaxBytes {
		return nil, Report{}, fmt.Errorf("profile exceeds %d bytes", MaxBytes)
	}
	if normalized, report, err := normalizeSingBox(content); err == nil {
		return normalized, report, nil
	}
	return normalizeClash(content)
}

func normalizeSingBox(content []byte) ([]byte, Report, error) {
	root, err := singjson.UnmarshalExtended[map[string]any](content)
	if err != nil {
		return nil, Report{}, err
	}
	rawOutbounds, _ := root["outbounds"].([]any)
	rawEndpoints, _ := root["endpoints"].([]any)
	if len(rawOutbounds) == 0 && len(rawEndpoints) == 0 {
		return nil, Report{}, errors.New("sing-box profile contains no outbounds or endpoints")
	}

	outbounds, outboundTags := sanitizeEntries(rawOutbounds, supportedOutboundTypes)
	endpoints, endpointTags := sanitizeEntries(rawEndpoints, supportedEndpointTypes)
	allTags := append(append([]string(nil), outboundTags...), endpointTags...)
	if len(allTags) == 0 {
		return nil, Report{}, errors.New("sing-box profile contains no usable tagged entries")
	}

	var routeRules []any
	final := ""
	if route, ok := root["route"].(map[string]any); ok {
		if rules, ok := route["rules"].([]any); ok {
			routeRules = sanitizeRules(rules)
		}
		if candidate, ok := route["final"].(string); ok && contains(allTags, candidate) {
			final = candidate
		}
	}
	if final == "" {
		final = allTags[0]
	}

	normalized := map[string]any{
		"outbounds": outbounds,
		"endpoints": endpoints,
		"route": map[string]any{
			"rules": routeRules,
			"final": final,
		},
	}
	encoded, err := singjson.Marshal(normalized)
	if err != nil {
		return nil, Report{}, err
	}
	return encoded, Report{Format: "sing-box", Nodes: len(outbounds), Endpoints: len(endpoints)}, nil
}

type clashRuleDocument struct {
	Rules []string `yaml:"rules"`
}

func normalizeClash(content []byte) ([]byte, Report, error) {
	var source clash.Clash
	if err := yaml.Unmarshal(content, &source); err != nil {
		return nil, Report{}, fmt.Errorf("parse profile as sing-box JSON or Clash YAML: %w", err)
	}
	var ruleDocument clashRuleDocument
	if err := yaml.Unmarshal(content, &ruleDocument); err != nil {
		return nil, Report{}, fmt.Errorf("parse Clash rules: %w", err)
	}

	removedCorporateProxies := make(map[string]bool)
	filteredProxies := make([]clash.Proxies, 0, len(source.Proxies))
	for _, proxy := range source.Proxies {
		if isLegacyCorporateProxy(proxy) {
			removedCorporateProxies[proxy.Name] = true
			continue
		}
		filteredProxies = append(filteredProxies, proxy)
	}
	source.Proxies = filteredProxies

	outbounds, endpoints, conversionErr := convert.Clash2sing(source, model.SINGLATEST)
	if len(outbounds) == 0 && len(endpoints) == 0 {
		if conversionErr != nil {
			return nil, Report{}, fmt.Errorf("convert Clash profile: %w", conversionErr)
		}
		return nil, Report{}, errors.New("Clash profile contains no supported nodes")
	}

	validTargets := map[string]string{
		"DIRECT": "direct", "direct": "direct",
		"REJECT": "block", "REJECT-DROP": "block", "block": "block",
		"ECorpLink": "corp", "CrossLink": "corp", "corp": "corp",
	}
	nodeTags := make([]string, 0, len(outbounds)+len(endpoints))
	for _, outbound := range outbounds {
		if outbound.Tag != "" {
			nodeTags = append(nodeTags, outbound.Tag)
			validTargets[outbound.Tag] = outbound.Tag
		}
	}
	for _, endpoint := range endpoints {
		if endpoint != nil && endpoint.Tag != "" {
			nodeTags = append(nodeTags, endpoint.Tag)
			validTargets[endpoint.Tag] = endpoint.Tag
		}
	}
	if len(nodeTags) == 0 {
		return nil, Report{}, errors.New("converted Clash profile has no tagged nodes")
	}

	convertedOutbounds := make([]any, 0, len(outbounds)+len(source.ProxyGroup)+3)
	for index := range outbounds {
		convertedOutbounds = append(convertedOutbounds, outbounds[index])
	}
	convertedOutbounds = append(convertedOutbounds, map[string]any{"type": "block", "tag": "block"})

	warnings := make([]string, 0, 4)
	if conversionErr != nil {
		warnings = append(warnings, conversionErr.Error())
	}
	groupTags := make(map[string]bool)
	for _, group := range source.ProxyGroup {
		members, containsCorporate := mapClashGroupMembers(group.Proxies, removedCorporateProxies, validTargets)
		if containsCorporate && len(members) == 1 && members[0] == "direct" {
			validTargets[group.Name] = "corp"
			continue
		}
		if len(members) == 0 || group.Name == "" || groupTags[group.Name] {
			continue
		}
		groupType := strings.ToLower(strings.ReplaceAll(group.Type, "-", ""))
		var converted map[string]any
		switch groupType {
		case "select", "selector":
			converted = map[string]any{"type": "selector", "tag": group.Name, "outbounds": members, "default": members[0]}
		case "urltest":
			converted = map[string]any{
				"type": "urltest", "tag": group.Name, "outbounds": members,
				"url": "https://www.gstatic.com/generate_204", "interval": "10m", "tolerance": 50,
			}
		default:
			warnings = append(warnings, fmt.Sprintf("ignored unsupported Clash proxy group %s (%s)", group.Name, group.Type))
			continue
		}
		convertedOutbounds = append(convertedOutbounds, converted)
		groupTags[group.Name] = true
		validTargets[group.Name] = group.Name
	}

	defaultTarget := ""
	if len(groupTags) == 0 {
		autoMembers := append([]string(nil), nodeTags...)
		selectorMembers := append([]string{"Auto"}, autoMembers...)
		selectorMembers = append(selectorMembers, "direct")
		convertedOutbounds = append(convertedOutbounds,
			map[string]any{
				"type": "urltest", "tag": "Auto", "outbounds": autoMembers,
				"url": "https://www.gstatic.com/generate_204", "interval": "10m", "tolerance": 50,
			},
			map[string]any{"type": "selector", "tag": "Proxy", "outbounds": selectorMembers, "default": "Auto"},
		)
		validTargets["Auto"] = "Auto"
		validTargets["Proxy"] = "Proxy"
		defaultTarget = "Proxy"
	}

	routeRules, finalTarget, ruleWarnings := convertClashRules(ruleDocument.Rules, validTargets)
	warnings = append(warnings, ruleWarnings...)
	if finalTarget != "" {
		defaultTarget = finalTarget
	}
	if defaultTarget == "" {
		for tag := range groupTags {
			defaultTarget = tag
			break
		}
	}
	if defaultTarget == "" {
		defaultTarget = nodeTags[0]
	}

	normalized := map[string]any{
		"outbounds": convertedOutbounds,
		"endpoints": endpoints,
		"route": map[string]any{
			"rules": routeRules,
			"final": defaultTarget,
		},
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return nil, Report{}, fmt.Errorf("encode converted profile: %w", err)
	}
	return encoded, Report{
		Format: "clash", Nodes: len(outbounds), Endpoints: len(endpoints), Warnings: uniqueStrings(warnings),
	}, nil
}

func isLegacyCorporateProxy(proxy clash.Proxies) bool {
	name := strings.ToLower(strings.TrimSpace(proxy.Name))
	server := strings.Trim(strings.ToLower(strings.TrimSpace(proxy.Server)), "[]")
	return (strings.Contains(name, "ecorplink") || strings.Contains(name, "crosslink")) &&
		(strings.EqualFold(proxy.Type, "socks5") || strings.EqualFold(proxy.Type, "socks")) &&
		(server == "127.0.0.1" || server == "localhost" || server == "::1")
}

func mapClashGroupMembers(members []string, removed map[string]bool, targets map[string]string) ([]string, bool) {
	mapped := make([]string, 0, len(members))
	seen := make(map[string]bool, len(members))
	containsCorporate := false
	for _, member := range members {
		if removed[member] {
			containsCorporate = true
			continue
		}
		target, found := targets[member]
		if !found || seen[target] || target == "corp" {
			continue
		}
		seen[target] = true
		mapped = append(mapped, target)
	}
	return mapped, containsCorporate
}

func convertClashRules(rules []string, targets map[string]string) ([]any, string, []string) {
	converted := make([]any, 0, len(rules))
	finalTarget := ""
	droppedTypes := make(map[string]int)
	droppedTargets := make(map[string]int)
	for _, raw := range rules {
		fields := strings.Split(raw, ",")
		if len(fields) < 2 {
			continue
		}
		ruleType := strings.ToUpper(strings.TrimSpace(fields[0]))
		if ruleType == "MATCH" {
			target, found := targets[strings.TrimSpace(fields[1])]
			if found {
				finalTarget = target
			} else {
				droppedTargets[strings.TrimSpace(fields[1])]++
			}
			continue
		}
		if len(fields) < 3 {
			continue
		}
		value := strings.TrimSpace(fields[1])
		target, found := targets[strings.TrimSpace(fields[2])]
		if !found {
			droppedTargets[strings.TrimSpace(fields[2])]++
			continue
		}
		if ruleType == "PROCESS-NAME" && strings.Contains(strings.ToLower(value), "ecorplink") {
			continue
		}
		rule := map[string]any{"action": "route", "outbound": target}
		switch ruleType {
		case "DOMAIN":
			rule["domain"] = []string{value}
		case "DOMAIN-SUFFIX":
			rule["domain_suffix"] = []string{"." + strings.TrimPrefix(strings.TrimPrefix(value, "+."), ".")}
		case "DOMAIN-KEYWORD":
			rule["domain_keyword"] = []string{value}
		case "DOMAIN-REGEX":
			rule["domain_regex"] = []string{value}
		case "IP-CIDR", "IP-CIDR6":
			rule["ip_cidr"] = []string{value}
		case "SRC-IP-CIDR":
			rule["source_ip_cidr"] = []string{value}
		case "PROCESS-NAME":
			rule["process_name"] = []string{value}
		case "PROCESS-PATH":
			rule["process_path"] = []string{value}
		case "DST-PORT", "SRC-PORT":
			port, err := strconv.Atoi(value)
			if err != nil || port < 1 || port > 65535 {
				droppedTypes[ruleType]++
				continue
			}
			if ruleType == "DST-PORT" {
				rule["port"] = []int{port}
			} else {
				rule["source_port"] = []int{port}
			}
		case "NETWORK":
			rule["network"] = []string{strings.ToLower(value)}
		default:
			droppedTypes[ruleType]++
			continue
		}
		converted = append(converted, rule)
	}
	warnings := make([]string, 0, len(droppedTypes)+len(droppedTargets))
	for ruleType, count := range droppedTypes {
		warnings = append(warnings, fmt.Sprintf("ignored %d unsupported Clash %s rule(s)", count, ruleType))
	}
	for target, count := range droppedTargets {
		warnings = append(warnings, fmt.Sprintf("ignored %d Clash rule(s) targeting unavailable %s", count, target))
	}
	return converted, finalTarget, warnings
}

func uniqueStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func sanitizeEntries(entries []any, supportedTypes map[string]bool) ([]any, []string) {
	clean := make([]any, 0, len(entries))
	tags := make([]string, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	for _, raw := range entries {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		tag, _ := entry["tag"].(string)
		entryType, _ := entry["type"].(string)
		if tag == "" || entryType == "" || seen[tag] || !supportedTypes[entryType] {
			continue
		}
		seen[tag] = true
		clean = append(clean, entry)
		tags = append(tags, tag)
	}
	return clean, tags
}

func sanitizeRules(rules []any) []any {
	clean := make([]any, 0, len(rules))
	for _, raw := range rules {
		rule, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		// Remote profiles may route traffic but may not run arbitrary actions
		// that mutate DNS, sniff state, or process execution.
		action, _ := rule["action"].(string)
		if action != "" && action != "route" && action != "reject" {
			continue
		}
		clean = append(clean, rule)
	}
	return clean
}

func SaveAtomic(path string, content []byte) error {
	path = expandHome(path)
	if path == "" {
		return errors.New("profile path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".profile-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func Read(path string) ([]byte, error) {
	content, err := os.ReadFile(expandHome(path))
	if err != nil {
		return nil, err
	}
	if len(content) > MaxBytes {
		return nil, fmt.Errorf("profile exceeds %d bytes", MaxBytes)
	}
	return content, nil
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

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
