package managedfs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRootAtomicRoundTripAndPermissions(t *testing.T) {
	rootPath := filepath.Join(t.TempDir(), ".crosslink")
	root, err := Open(rootPath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	path := filepath.Join(rootPath, "state", "proxy.json")
	if err := root.WriteFileAtomic(path, []byte("value"), 0o600); err != nil {
		t.Fatal(err)
	}
	content, err := root.ReadFile(path, 32)
	if err != nil || string(content) != "value" {
		t.Fatalf("read = %q, %v", content, err)
	}
	for _, item := range []struct {
		path string
		perm os.FileMode
	}{
		{rootPath, 0o700},
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
	if err := root.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := root.Remove(path); err != nil {
		t.Fatalf("idempotent remove: %v", err)
	}
}

func TestRootRejectsSymlinkEscapes(t *testing.T) {
	parent := t.TempDir()
	outside := t.TempDir()
	rootPath := filepath.Join(parent, ".crosslink")
	if err := os.Symlink(outside, rootPath); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(rootPath, false); err == nil || !strings.Contains(err.Error(), "real directory") {
		t.Fatalf("root symlink error = %v", err)
	}

	if err := os.Remove(rootPath); err != nil {
		t.Fatal(err)
	}
	root, err := Open(rootPath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Symlink(outside, filepath.Join(rootPath, "state")); err != nil {
		t.Fatal(err)
	}
	outsideFile := filepath.Join(outside, "proxy.json")
	if err := os.WriteFile(outsideFile, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	managedPath := filepath.Join(rootPath, "state", "proxy.json")
	if _, err := root.ReadFile(managedPath, 32); err == nil || !strings.Contains(err.Error(), "real directory") {
		t.Fatalf("nested symlink read error = %v", err)
	}
	if err := root.WriteFileAtomic(managedPath, []byte("owned"), 0o600); err == nil || !strings.Contains(err.Error(), "real directory") {
		t.Fatalf("nested symlink write error = %v", err)
	}
	content, err := os.ReadFile(outsideFile)
	if err != nil || string(content) != "untouched" {
		t.Fatalf("outside file = %q, %v", content, err)
	}
}

func TestRootReplacesLeafSymlinkWithoutTouchingTarget(t *testing.T) {
	rootPath := filepath.Join(t.TempDir(), ".crosslink")
	root, err := Open(rootPath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	target := filepath.Join(rootPath, "target")
	leaf := filepath.Join(rootPath, "state.json")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(target), leaf); err != nil {
		t.Fatal(err)
	}
	if _, err := root.ReadFile(leaf, 32); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("leaf symlink read error = %v", err)
	}
	if err := root.WriteFileAtomic(leaf, []byte("managed"), 0o600); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(target)
	if err != nil || string(content) != "target" {
		t.Fatalf("target = %q, %v", content, err)
	}
	info, err := os.Lstat(leaf)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("managed leaf = %v, %v", info, err)
	}
}

func TestRootEnsureRegularFileRejectsSymlinkAndTightensMode(t *testing.T) {
	rootPath := filepath.Join(t.TempDir(), ".crosslink")
	root, err := Open(rootPath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	path := filepath.Join(rootPath, "crosslink.log")
	if err := os.WriteFile(path, []byte("existing"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := root.EnsureRegularFile(path, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("secured log = %v, %v", info, err)
	}

	target := filepath.Join(rootPath, "target.log")
	if err := os.WriteFile(target, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(target), path); err != nil {
		t.Fatal(err)
	}
	if err := root.EnsureRegularFile(path, 0o600); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("log symlink error = %v", err)
	}
	content, err := os.ReadFile(target)
	if err != nil || string(content) != "untouched" {
		t.Fatalf("symlink target = %q, %v", content, err)
	}
}

func TestRootRejectsTraversalAndOversize(t *testing.T) {
	parent := t.TempDir()
	rootPath := filepath.Join(parent, ".crosslink")
	root, err := Open(rootPath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.WriteFileAtomic(filepath.Join(parent, "outside"), []byte("x"), 0o600); err == nil {
		t.Fatal("outside write was accepted")
	}
	path := filepath.Join(rootPath, "large")
	if err := root.WriteFileAtomic(path, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := root.ReadFile(path, 4); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversize error = %v", err)
	}
	if err := root.Remove(filepath.Join(rootPath, "missing", "leaf")); !errors.Is(err, os.ErrNotExist) && err != nil {
		t.Fatalf("remove missing parent = %v", err)
	}
}
