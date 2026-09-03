package core

import (
	"net"
	"strings"
	"testing"

	appconfig "github.com/limauriga-ux/crosslink/internal/config"
)

func TestValidateConfiguredTUNAvailabilityAllowsAutomaticAndFreeNames(t *testing.T) {
	cfg := appconfig.DefaultConfig()
	cfg.TUN.Name = ""
	if err := validateConfiguredTUNAvailabilityFrom(cfg, "", []net.Interface{{Name: "utun7"}}); err != nil {
		t.Fatalf("automatic allocation = %v", err)
	}

	cfg.TUN.Name = "utun12"
	if err := validateConfiguredTUNAvailabilityFrom(cfg, "", []net.Interface{{Name: "utun7"}, {Name: "utun9"}}); err != nil {
		t.Fatalf("free explicit name = %v", err)
	}
}

func TestValidateConfiguredTUNAvailabilityRejectsOccupiedName(t *testing.T) {
	cfg := appconfig.DefaultConfig()
	cfg.TUN.Name = "utun7"
	err := validateConfiguredTUNAvailabilityFrom(cfg, "", []net.Interface{{Name: "utun7"}, {Name: "utun9"}})
	if err == nil || !strings.Contains(err.Error(), "already in use") || !strings.Contains(err.Error(), "automatic") {
		t.Fatalf("occupied name error = %v", err)
	}
}

func TestValidateConfiguredTUNAvailabilityAllowsCurrentInterfaceDuringReload(t *testing.T) {
	cfg := appconfig.DefaultConfig()
	cfg.TUN.Name = "utun9"
	if err := validateConfiguredTUNAvailabilityFrom(cfg, "utun9", []net.Interface{{Name: "utun7"}, {Name: "utun9"}}); err != nil {
		t.Fatalf("current interface reload = %v", err)
	}
}

func TestValidateConfiguredTUNAvailabilityIgnoredWhenTUNDisabled(t *testing.T) {
	cfg := appconfig.DefaultConfig()
	cfg.Core.TUNEnabled = false
	cfg.TUN.Name = "utun7"
	if err := validateConfiguredTUNAvailabilityFrom(cfg, "", []net.Interface{{Name: "utun7"}}); err != nil {
		t.Fatalf("disabled TUN = %v", err)
	}
}
