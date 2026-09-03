package openvpnprofile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagedStorageUsesSecurePermissionsAndRoundTrips(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), ".crosslink")
	path := filepath.Join(dataDir, "openvpn", "profile.json")
	profile := openVPNTestProfile(t)
	if err := SaveManaged(dataDir, path, profile); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		path string
		perm os.FileMode
	}{
		{dataDir, 0o700},
		{filepath.Dir(path), 0o700},
		{path, 0o600},
	} {
		info, err := os.Stat(item.path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != item.perm {
			t.Fatalf("%s permissions = %o, want %o", item.path, info.Mode().Perm(), item.perm)
		}
	}
	loaded, err := LoadManaged(dataDir, path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Name != profile.Name || loaded.ClientKey != profile.ClientKey {
		t.Fatalf("loaded profile mismatch: %+v", loaded)
	}
	if err := RemoveManaged(dataDir, path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("profile still exists: %v", err)
	}
}

func TestManagedStorageRejectsCrossLinkAndNestedSymlinks(t *testing.T) {
	profile := openVPNTestProfile(t)
	t.Run("data directory", func(t *testing.T) {
		parent := t.TempDir()
		outside := t.TempDir()
		dataDir := filepath.Join(parent, ".crosslink")
		if err := os.Symlink(outside, dataDir); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dataDir, "openvpn", "profile.json")
		if err := SaveManaged(dataDir, path, profile); err == nil || !strings.Contains(err.Error(), "real directory") {
			t.Fatalf("data symlink error = %v", err)
		}
		if _, err := os.Stat(filepath.Join(outside, "openvpn", "profile.json")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("outside path modified: %v", err)
		}
	})
	t.Run("nested directory", func(t *testing.T) {
		dataDir := filepath.Join(t.TempDir(), ".crosslink")
		outside := t.TempDir()
		if err := os.MkdirAll(dataDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(dataDir, "openvpn")); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dataDir, "openvpn", "profile.json")
		if err := SaveManaged(dataDir, path, profile); err == nil || !strings.Contains(err.Error(), "real directory") {
			t.Fatalf("nested symlink error = %v", err)
		}
		if _, err := os.Stat(filepath.Join(outside, "profile.json")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("outside path modified: %v", err)
		}
	})
}

func TestManagedStorageReplacesLeafSymlinkWithoutTouchingTarget(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), ".crosslink")
	dir := filepath.Join(dataDir, "openvpn")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target")
	path := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(target, []byte("do-not-touch"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(target), path); err != nil {
		t.Fatal(err)
	}
	if err := SaveManaged(dataDir, path, openVPNTestProfile(t)); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "do-not-touch" {
		t.Fatalf("symlink target modified: %q", content)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("managed path mode = %s", info.Mode())
	}
}

func TestLoadManagedRejectsInsecurePermissions(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), ".crosslink")
	path := filepath.Join(dataDir, "openvpn", "profile.json")
	if err := SaveManaged(dataDir, path, openVPNTestProfile(t)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManaged(dataDir, path); err == nil || !strings.Contains(err.Error(), "expose private key") {
		t.Fatalf("insecure permission error = %v", err)
	}
}

func openVPNTestProfile(t *testing.T) Profile {
	t.Helper()
	caPEM, p12 := openVPNTestIdentity(t, "password")
	dir := t.TempDir()
	ovpnPath := filepath.Join(dir, "profile.ovpn")
	caPath := filepath.Join(dir, "ca.crt")
	p12Path := filepath.Join(dir, "client.p12")
	if err := os.WriteFile(ovpnPath, []byte("client\nremote 192.0.2.1 1194\nca ca.crt\npkcs12 client.p12\nroute-nopull\nroute 10.20.0.0 255.255.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p12Path, p12, 0o600); err != nil {
		t.Fatal(err)
	}
	profile, _, err := Import(ImportOptions{OVPNPath: ovpnPath, CAPath: caPath, PKCS12Path: p12Path, PKCS12Password: "password"})
	if err != nil {
		t.Fatal(err)
	}
	return profile
}
