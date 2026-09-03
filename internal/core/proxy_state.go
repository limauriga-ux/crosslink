package core

import (
	"encoding/json"

	appconfig "github.com/limauriga-ux/crosslink/internal/config"
)

const maxProxyStateBytes = 256 << 10

func loadProxySelections(cfg *appconfig.Config) map[string]string {
	selections := make(map[string]string)
	if cfg == nil {
		return selections
	}
	content, err := cfg.ReadProxyState(maxProxyStateBytes)
	if err != nil {
		return selections
	}
	if json.Unmarshal(content, &selections) != nil {
		return make(map[string]string)
	}
	return selections
}

func saveProxySelections(cfg *appconfig.Config, selections map[string]string) error {
	if cfg == nil {
		return nil
	}
	content, err := json.Marshal(selections)
	if err != nil {
		return err
	}
	return cfg.WriteProxyState(content)
}
