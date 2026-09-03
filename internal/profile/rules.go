package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

const (
	RulePlanVersion  = 1
	MaxRulePlanBytes = 256 << 10
	maxInjectedRules = 512
	maxRuleLineBytes = 2048

	// OpenVPNTargetTag is owned by CrossLink, not by imported proxy Profiles.
	// The core always reserves it: a disconnected session maps it to a block
	// outbound so persisted enterprise rules fail closed instead of leaking to
	// the public fallback.
	OpenVPNTargetTag = "openvpn-enterprise"
)

// RulePlan is stored independently from the imported subscription so profile
// refreshes cannot overwrite local routing policy. Prepend rules run before
// subscription rules; Append rules run after them.
type RulePlan struct {
	Version int      `json:"version"`
	Prepend []string `json:"prepend"`
	Append  []string `json:"append"`
}

// RuleContext describes the sanitized subscription fields needed by the rule
// editor and compiler. Targets are concrete outbound/endpoint tags in profile
// order; built-in DIRECT, REJECT and CORP targets are always available and are
// therefore not repeated here.
type RuleContext struct {
	Targets          []string
	ProfileRuleCount int
	Final            string
}

func LoadRulePlan(path string) (RulePlan, error) {
	path = expandHome(path)
	if strings.TrimSpace(path) == "" {
		return RulePlan{Version: RulePlanVersion}, nil
	}
	content, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return RulePlan{Version: RulePlanVersion}, nil
		}
		return RulePlan{}, fmt.Errorf("read rule plan: %w", err)
	}
	return ParseRulePlan(content)
}

// ParseRulePlan decodes a bounded rule plan already read through the caller's
// filesystem trust boundary.
func ParseRulePlan(content []byte) (RulePlan, error) {
	if len(content) > MaxRulePlanBytes {
		return RulePlan{}, fmt.Errorf("rule plan exceeds %d bytes", MaxRulePlanBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var plan RulePlan
	if err := decoder.Decode(&plan); err != nil {
		return RulePlan{}, fmt.Errorf("parse rule plan: %w", err)
	}
	return NormalizeRulePlan(plan)
}

func NormalizeRulePlan(plan RulePlan) (RulePlan, error) {
	if plan.Version != 0 && plan.Version != RulePlanVersion {
		return RulePlan{}, fmt.Errorf("unsupported rule plan version %d", plan.Version)
	}
	prepend, err := normalizeRuleLines("prepend", plan.Prepend)
	if err != nil {
		return RulePlan{}, err
	}
	appendRules, err := normalizeRuleLines("append", plan.Append)
	if err != nil {
		return RulePlan{}, err
	}
	if len(prepend)+len(appendRules) > maxInjectedRules {
		return RulePlan{}, fmt.Errorf("rule plan contains more than %d rules", maxInjectedRules)
	}
	return RulePlan{Version: RulePlanVersion, Prepend: prepend, Append: appendRules}, nil
}

func SaveRulePlanAtomic(path string, plan RulePlan) error {
	normalized, err := NormalizeRulePlan(plan)
	if err != nil {
		return err
	}
	content, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return fmt.Errorf("encode rule plan: %w", err)
	}
	if len(content) > MaxRulePlanBytes {
		return fmt.Errorf("rule plan exceeds %d bytes", MaxRulePlanBytes)
	}
	return SaveAtomic(path, append(content, '\n'))
}

// InspectRuleContext reads targets and route metadata from an already
// normalized proxy profile. Reserved CrossLink targets are excluded because
// the core owns their definitions.
func InspectRuleContext(content []byte) (RuleContext, error) {
	root, err := jsonObject(content)
	if err != nil {
		return RuleContext{}, fmt.Errorf("parse proxy profile for rules: %w", err)
	}
	context := RuleContext{Final: "direct"}
	seen := make(map[string]bool)
	for _, field := range []string{"outbounds", "endpoints"} {
		entries, _ := root[field].([]any)
		for _, raw := range entries {
			entry, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			tag, _ := entry["tag"].(string)
			tag = strings.TrimSpace(tag)
			if tag == "" || isReservedInjectedTarget(tag) || seen[tag] {
				continue
			}
			seen[tag] = true
			context.Targets = append(context.Targets, tag)
		}
	}
	if route, ok := root["route"].(map[string]any); ok {
		if rules, ok := route["rules"].([]any); ok {
			context.ProfileRuleCount = len(rules)
		}
		if final, ok := route["final"].(string); ok && strings.TrimSpace(final) != "" {
			context.Final = final
		}
	}
	return context, nil
}

// CompileRulePlan validates and converts Clash-style local rules into sing-box
// route rules. It is strict by design: a local typo must fail the save/reload,
// never disappear silently as unsupported subscription syntax does.
func CompileRulePlan(plan RulePlan, targets []string) (prepend, appendRules []any, err error) {
	normalized, err := NormalizeRulePlan(plan)
	if err != nil {
		return nil, nil, err
	}
	targetMap := buildInjectedTargetMap(targets)
	prepend, err = compileInjectedStage("prepend", normalized.Prepend, targetMap)
	if err != nil {
		return nil, nil, err
	}
	appendRules, err = compileInjectedStage("append", normalized.Append, targetMap)
	if err != nil {
		return nil, nil, err
	}
	return prepend, appendRules, nil
}

func normalizeRuleLines(stage string, lines []string) ([]string, error) {
	clean := make([]string, 0, len(lines))
	for index, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) > maxRuleLineBytes {
			return nil, fmt.Errorf("%s rule %d exceeds %d bytes", stage, index+1, maxRuleLineBytes)
		}
		clean = append(clean, line)
	}
	return clean, nil
}

type injectedTarget struct {
	outbound string
	reject   bool
}

func buildInjectedTargetMap(targets []string) map[string]injectedTarget {
	result := map[string]injectedTarget{
		"DIRECT":         {outbound: "direct"},
		"direct":         {outbound: "direct"},
		"REJECT":         {reject: true},
		"REJECT-DROP":    {reject: true},
		"BLOCK":          {reject: true},
		"block":          {reject: true},
		"CORP":           {outbound: "corp"},
		"corp":           {outbound: "corp"},
		"ECorpLink":      {outbound: "corp"},
		"CrossLink":      {outbound: "corp"},
		"OPENVPN":        {outbound: OpenVPNTargetTag},
		"OpenVPN":        {outbound: OpenVPNTargetTag},
		OpenVPNTargetTag: {outbound: OpenVPNTargetTag},
	}
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" || isReservedInjectedTarget(target) {
			continue
		}
		result[target] = injectedTarget{outbound: target}
	}
	return result
}

func isReservedInjectedTarget(target string) bool {
	switch strings.ToUpper(strings.TrimSpace(target)) {
	case "DIRECT", "REJECT", "REJECT-DROP", "BLOCK", "CORP", "ECORPLINK", "CROSSLINK", "OPENVPN", "OPENVPN-ENTERPRISE":
		return true
	default:
		return false
	}
}

func compileInjectedStage(stage string, lines []string, targets map[string]injectedTarget) ([]any, error) {
	compiled := make([]any, 0, len(lines))
	for index, raw := range lines {
		rule, err := compileInjectedRule(raw, targets)
		if err != nil {
			return nil, fmt.Errorf("%s rule %d (%q): %w", stage, index+1, raw, err)
		}
		compiled = append(compiled, rule)
	}
	return compiled, nil
}

func compileInjectedRule(raw string, targets map[string]injectedTarget) (map[string]any, error) {
	fields := strings.Split(raw, ",")
	if len(fields) < 2 {
		return nil, errors.New("expected Clash syntax TYPE,VALUE,TARGET")
	}
	ruleType := strings.ToUpper(strings.TrimSpace(fields[0]))
	if ruleType == "MATCH" {
		return nil, errors.New("MATCH is not injectable; change the profile final outbound instead")
	}
	if len(fields) < 3 {
		return nil, errors.New("expected Clash syntax TYPE,VALUE,TARGET")
	}
	targetIndex := len(fields) - 1
	if strings.EqualFold(strings.TrimSpace(fields[targetIndex]), "no-resolve") {
		targetIndex--
	}
	if targetIndex < 2 {
		return nil, errors.New("missing rule target")
	}
	value := strings.TrimSpace(strings.Join(fields[1:targetIndex], ","))
	if value == "" {
		return nil, errors.New("rule value is empty")
	}
	targetName := strings.TrimSpace(fields[targetIndex])
	target, ok := targets[targetName]
	if !ok {
		return nil, fmt.Errorf("target %q is unavailable in the current profile", targetName)
	}

	rule := map[string]any{"action": "route", "outbound": target.outbound}
	if target.reject {
		rule = map[string]any{"action": "reject"}
	}
	switch ruleType {
	case "DOMAIN":
		rule["domain"] = []string{value}
	case "DOMAIN-SUFFIX":
		suffix := strings.TrimPrefix(strings.TrimPrefix(value, "+."), ".")
		if suffix == "" {
			return nil, errors.New("domain suffix is empty")
		}
		rule["domain_suffix"] = []string{"." + suffix}
	case "DOMAIN-KEYWORD":
		rule["domain_keyword"] = []string{value}
	case "DOMAIN-REGEX":
		rule["domain_regex"] = []string{value}
	case "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR":
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR: %w", err)
		}
		if ruleType == "IP-CIDR" && !prefix.Addr().Is4() {
			return nil, errors.New("IP-CIDR requires an IPv4 prefix")
		}
		if ruleType == "IP-CIDR6" && !prefix.Addr().Is6() {
			return nil, errors.New("IP-CIDR6 requires an IPv6 prefix")
		}
		field := "ip_cidr"
		if ruleType == "SRC-IP-CIDR" {
			field = "source_ip_cidr"
		}
		rule[field] = []string{prefix.String()}
	case "PROCESS-NAME":
		rule["process_name"] = []string{value}
	case "PROCESS-PATH":
		rule["process_path"] = []string{value}
	case "DST-PORT", "SRC-PORT":
		port, err := strconv.Atoi(value)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port %q", value)
		}
		field := "port"
		if ruleType == "SRC-PORT" {
			field = "source_port"
		}
		rule[field] = []int{port}
	case "NETWORK":
		network := strings.ToLower(value)
		if network != "tcp" && network != "udp" {
			return nil, errors.New("NETWORK must be tcp or udp")
		}
		rule["network"] = []string{network}
	default:
		return nil, fmt.Errorf("unsupported rule type %s", ruleType)
	}
	return rule, nil
}

func jsonObject(content []byte) (map[string]any, error) {
	if len(bytes.TrimSpace(content)) == 0 {
		return map[string]any{}, nil
	}
	var root map[string]any
	if err := json.Unmarshal(content, &root); err != nil {
		return nil, err
	}
	return root, nil
}
