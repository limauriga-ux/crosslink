package core

import (
	"bytes"
	"crypto/rand"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	appconfig "github.com/limauriga-ux/crosslink/internal/config"
)

const (
	domesticDomainRuleSetTag = "crosslink-geosite-cn"
	domesticIPRuleSetTag     = "crosslink-geoip-cn"
)

//go:embed rulesets/geosite-cn.srs rulesets/geoip-cn.srs
var bundledDomesticRuleSets embed.FS

type bundledRuleSet struct {
	source string
	name   string
	tag    string
}

var domesticRuleSetFiles = []bundledRuleSet{
	{source: "rulesets/geosite-cn.srs", name: "geosite-cn.srs", tag: domesticDomainRuleSetTag},
	{source: "rulesets/geoip-cn.srs", name: "geoip-cn.srs", tag: domesticIPRuleSetTag},
}

func ensureDomesticRuleSets(cfg *appconfig.Config) ([]any, error) {
	allowedRoot, dir, err := cfg.DomesticRuleSetPaths()
	if err != nil {
		return nil, err
	}
	rootParent := filepath.Dir(allowedRoot)
	rootName := filepath.Base(allowedRoot)
	if err := os.MkdirAll(rootParent, 0o700); err != nil {
		return nil, fmt.Errorf("create CrossLink data parent: %w", err)
	}
	parentRoot, err := os.OpenRoot(rootParent)
	if err != nil {
		return nil, fmt.Errorf("open CrossLink data parent: %w", err)
	}
	defer parentRoot.Close()
	dataInfo, err := parentRoot.Lstat(rootName)
	if errors.Is(err, fs.ErrNotExist) {
		if err := parentRoot.Mkdir(rootName, 0o700); err != nil {
			return nil, fmt.Errorf("create CrossLink data directory: %w", err)
		}
		dataInfo, err = parentRoot.Lstat(rootName)
	}
	if err != nil {
		return nil, fmt.Errorf("inspect CrossLink data directory: %w", err)
	}
	if !dataInfo.IsDir() || dataInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("CrossLink data directory must be a real directory")
	}
	root, err := parentRoot.OpenRoot(rootName)
	if err != nil {
		return nil, fmt.Errorf("open CrossLink data directory: %w", err)
	}
	defer root.Close()
	if err := secureRootDirectory(root); err != nil {
		return nil, fmt.Errorf("secure CrossLink data directory: %w", err)
	}
	relativeDir, err := filepath.Rel(allowedRoot, dir)
	if err != nil {
		return nil, fmt.Errorf("resolve domestic rule-set directory: %w", err)
	}
	if err := root.MkdirAll(relativeDir, 0o700); err != nil {
		return nil, fmt.Errorf("create domestic rule-set directory: %w", err)
	}
	ruleSetRoot, err := root.OpenRoot(relativeDir)
	if err != nil {
		return nil, fmt.Errorf("open domestic rule-set directory: %w", err)
	}
	defer ruleSetRoot.Close()
	if err := secureRootDirectory(ruleSetRoot); err != nil {
		return nil, fmt.Errorf("secure domestic rule-set directory: %w", err)
	}

	ruleSets := make([]any, 0, len(domesticRuleSetFiles))
	for _, item := range domesticRuleSetFiles {
		content, err := fs.ReadFile(bundledDomesticRuleSets, item.source)
		if err != nil {
			return nil, fmt.Errorf("read bundled %s: %w", item.name, err)
		}
		if err := writeRuleSetIfChanged(ruleSetRoot, item.name, content); err != nil {
			return nil, fmt.Errorf("install bundled %s: %w", item.name, err)
		}
		ruleSets = append(ruleSets, map[string]any{
			"type":   "local",
			"tag":    item.tag,
			"format": "binary",
			"path":   filepath.Join(dir, item.name),
		})
	}
	return ruleSets, nil
}

func secureRootDirectory(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Chmod(0o700)
}

func writeRuleSetIfChanged(root *os.Root, name string, content []byte) error {
	if filepath.Base(name) != name || name == "." {
		return fmt.Errorf("invalid rule-set file name %q", name)
	}
	info, statErr := root.Lstat(name)
	if statErr == nil && info.Mode().IsRegular() && info.Mode().Perm() == 0o600 && info.Size() == int64(len(content)) {
		current, openErr := root.Open(name)
		if openErr == nil {
			currentInfo, infoErr := current.Stat()
			currentContent, readErr := io.ReadAll(current)
			closeErr := current.Close()
			if infoErr == nil && readErr == nil && closeErr == nil && os.SameFile(info, currentInfo) && bytes.Equal(currentContent, content) {
				return nil
			}
		}
	} else if statErr != nil && !errors.Is(statErr, fs.ErrNotExist) {
		return statErr
	}

	temporary, temporaryName, err := createRuleSetTemp(root)
	if err != nil {
		return err
	}
	defer root.Remove(temporaryName)
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
	return root.Rename(temporaryName, name)
}

func createRuleSetTemp(root *os.Root) (*os.File, string, error) {
	for range 10 {
		var random [8]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", err
		}
		name := fmt.Sprintf(".ruleset-%x.tmp", random)
		file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return file, name, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, "", err
		}
	}
	return nil, "", errors.New("create temporary rule-set: exhausted unique names")
}
