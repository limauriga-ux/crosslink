package profile

import (
	"fmt"

	singjson "github.com/sagernet/sing/common/json"
)

type PreviewItem struct {
	Tag      string `json:"tag"`
	Type     string `json:"type"`
	DelayMs  int    `json:"delay_ms"`
	Selected bool   `json:"selected,omitempty"`
}

type PreviewGroup struct {
	Tag      string        `json:"tag"`
	Type     string        `json:"type"`
	Selected string        `json:"selected,omitempty"`
	Items    []PreviewItem `json:"items"`
}

func PreviewGroups(content []byte) ([]PreviewGroup, error) {
	root, err := singjson.UnmarshalExtended[map[string]any](content)
	if err != nil {
		return nil, fmt.Errorf("parse profile preview: %w", err)
	}
	rawOutbounds, _ := root["outbounds"].([]any)
	entries := make(map[string]map[string]any, len(rawOutbounds))
	for _, raw := range rawOutbounds {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		tag, _ := entry["tag"].(string)
		if tag != "" {
			entries[tag] = entry
		}
	}
	groups := make([]PreviewGroup, 0)
	for _, raw := range rawOutbounds {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		groupType, _ := entry["type"].(string)
		if groupType != "selector" && groupType != "urltest" {
			continue
		}
		tag, _ := entry["tag"].(string)
		members := stringSlice(entry["outbounds"])
		selected, _ := entry["default"].(string)
		if selected == "" && len(members) > 0 {
			selected = members[0]
		}
		items := make([]PreviewItem, 0, len(members))
		for _, member := range members {
			child := entries[member]
			childType, _ := child["type"].(string)
			items = append(items, PreviewItem{
				Tag: member, Type: childType, DelayMs: -1, Selected: member == selected,
			})
		}
		groups = append(groups, PreviewGroup{Tag: tag, Type: groupType, Selected: selected, Items: items})
	}
	return groups, nil
}

func stringSlice(value any) []string {
	values, _ := value.([]any)
	result := make([]string, 0, len(values))
	for _, raw := range values {
		if item, ok := raw.(string); ok && item != "" {
			result = append(result, item)
		}
	}
	return result
}
