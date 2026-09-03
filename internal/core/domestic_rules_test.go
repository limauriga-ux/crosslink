package core

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	appconfig "github.com/limauriga-ux/crosslink/internal/config"
)

func TestEnsureDomesticRuleSetsInstallsBundledBinaryFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".crosslink", "rulesets")
	cfg := domesticRuleSetTestConfig(t, dir)
	ruleSets, err := ensureDomesticRuleSets(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(ruleSets) != 2 {
		t.Fatalf("rule sets = %#v", ruleSets)
	}
	for index, item := range domesticRuleSetFiles {
		path := filepath.Join(dir, item.name)
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		bundled, err := bundledDomesticRuleSets.ReadFile(item.source)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(content, bundled) {
			t.Fatalf("%s content differs from bundle", item.name)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s permissions = %o", item.name, info.Mode().Perm())
		}
		definition := ruleSets[index].(map[string]any)
		if definition["tag"] != item.tag || definition["format"] != "binary" || definition["path"] != path {
			t.Fatalf("definition = %#v", definition)
		}
	}
}

func TestEnsureDomesticRuleSetsRepairsInsecureDirectoryPermissions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".crosslink", "rulesets")
	cfg := domesticRuleSetTestConfig(t, dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureDomesticRuleSets(cfg); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("rule-set directory permissions = %o", info.Mode().Perm())
	}
}

func TestEnsureDomesticRuleSetsRepairsCorruptBundledCache(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".crosslink", "rulesets")
	cfg := domesticRuleSetTestConfig(t, dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, item := range domesticRuleSetFiles {
		if err := os.WriteFile(filepath.Join(dir, item.name), []byte("corrupt"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ensureDomesticRuleSets(cfg); err != nil {
		t.Fatal(err)
	}
	for _, item := range domesticRuleSetFiles {
		cached, err := os.ReadFile(filepath.Join(dir, item.name))
		if err != nil {
			t.Fatal(err)
		}
		bundled, err := bundledDomesticRuleSets.ReadFile(item.source)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(cached, bundled) {
			t.Fatalf("%s corrupt cache survived repair", item.name)
		}
		info, err := os.Stat(filepath.Join(dir, item.name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s permissions = %o", item.name, info.Mode().Perm())
		}
	}
}

func TestEnsureDomesticRuleSetsRejectsCrossLinkDataSymlink(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(home, ".crosslink")); err != nil {
		t.Fatal(err)
	}
	cfg := domesticRuleSetTestConfig(t, filepath.Join(home, ".crosslink", "rulesets"))
	if _, err := ensureDomesticRuleSets(cfg); err == nil {
		t.Fatal("CrossLink data symlink was accepted")
	}
	if _, err := os.Stat(filepath.Join(outside, "rulesets")); !os.IsNotExist(err) {
		t.Fatalf("outside directory was modified: %v", err)
	}
}

func TestEnsureDomesticRuleSetsRejectsEscapingNestedSymlink(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dataDir := filepath.Join(home, ".crosslink")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := domesticRuleSetTestConfig(t, filepath.Join(dataDir, "rulesets"))
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dataDir, "rulesets")); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureDomesticRuleSets(cfg); err == nil {
		t.Fatal("escaping nested symlink was accepted")
	}
	if _, err := os.Stat(filepath.Join(outside, "geosite-cn.srs")); !os.IsNotExist(err) {
		t.Fatalf("outside directory was modified: %v", err)
	}
}

func TestWriteRuleSetIfChangedRepairsStaleCache(t *testing.T) {
	dir := t.TempDir()
	root := openTestRuleSetRoot(t, dir)
	path := filepath.Join(dir, "geoip-cn.srs")
	if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeRuleSetIfChanged(root, filepath.Base(path), []byte("fresh")); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "fresh" {
		t.Fatalf("cache = %q", content)
	}
}

func TestWriteRuleSetIfChangedRepairsInsecurePermissions(t *testing.T) {
	dir := t.TempDir()
	root := openTestRuleSetRoot(t, dir)
	path := filepath.Join(dir, "geosite-cn.srs")
	content := []byte("same-content")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeRuleSetIfChanged(root, filepath.Base(path), content); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("repaired cache mode = %v", info.Mode())
	}
}

func TestWriteRuleSetIfChangedReplacesSymlinkWithoutTouchingTarget(t *testing.T) {
	dir := t.TempDir()
	root := openTestRuleSetRoot(t, dir)
	target := filepath.Join(dir, "target")
	path := filepath.Join(dir, "geoip-cn.srs")
	if err := os.WriteFile(target, []byte("target-content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(target), path); err != nil {
		t.Fatal(err)
	}
	if err := writeRuleSetIfChanged(root, filepath.Base(path), []byte("bundled-content")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("replacement mode = %v", info.Mode())
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "bundled-content" {
		t.Fatalf("cache = %q", content)
	}
	targetContent, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(targetContent) != "target-content" {
		t.Fatalf("symlink target was modified: %q", targetContent)
	}
}

func TestWriteRuleSetIfChangedReplacesDirectoryEntry(t *testing.T) {
	dir := t.TempDir()
	root := openTestRuleSetRoot(t, dir)
	path := filepath.Join(dir, "geoip-cn.srs")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	err := writeRuleSetIfChanged(root, filepath.Base(path), []byte("bundled-content"))
	if err == nil {
		t.Fatal("directory cache entry was unexpectedly replaced")
	}
	info, statErr := os.Stat(path)
	if statErr != nil || !info.IsDir() {
		t.Fatalf("directory cache entry changed: info=%v err=%v", info, statErr)
	}
}

func openTestRuleSetRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}

func domesticRuleSetTestConfig(t *testing.T, ruleSetDir string) *appconfig.Config {
	t.Helper()
	cfg := appconfig.DefaultConfig()
	if err := cfg.BindConfigPath(filepath.Join(filepath.Dir(ruleSetDir), "config.json")); err != nil {
		t.Fatal(err)
	}
	cfg.Core.RuleSetDir = ruleSetDir
	return cfg
}
