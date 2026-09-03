package embeddeddaemon

import (
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
)

func TestEnsureWritesEmbeddedDaemonAndSkipsMatchingFile(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "crosslink-daemon")
	src := Source{
		FS:     fstest.MapFS{"crosslink-daemon": {Data: []byte("daemon-v1")}},
		Path:   "crosslink-daemon",
		SHA256: "d4375538e8bc2b9b78c2c780d9028d761f7ec9527dd0040153a107d348033f5e",
	}
	path, replaced, err := Ensure(src, dst)
	if err != nil {
		t.Fatal(err)
	}
	if path != dst {
		t.Fatalf("path = %q, want %q", path, dst)
	}
	if !replaced {
		t.Fatalf("replaced = false on first install, want true")
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0111 == 0 {
		t.Fatalf("installed daemon is not executable: %v", info.Mode())
	}
	path, replaced, err = Ensure(src, dst)
	if err != nil {
		t.Fatal(err)
	}
	if path != dst {
		t.Fatalf("path = %q, want %q", path, dst)
	}
	if replaced {
		t.Fatalf("replaced = true on no-op rerun, want false")
	}
}

func TestEnsureReportsReplacedWhenContentChanges(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "crosslink-daemon")
	v1 := Source{
		FS:   fstest.MapFS{"crosslink-daemon": {Data: []byte("daemon-v1")}},
		Path: "crosslink-daemon",
	}
	if _, replaced, err := Ensure(v1, dst); err != nil || !replaced {
		t.Fatalf("v1 install: replaced=%v err=%v", replaced, err)
	}
	v2 := Source{
		FS:   fstest.MapFS{"crosslink-daemon": {Data: []byte("daemon-v2")}},
		Path: "crosslink-daemon",
	}
	_, replaced, err := Ensure(v2, dst)
	if err != nil {
		t.Fatal(err)
	}
	if !replaced {
		t.Fatalf("replaced = false when content changed, want true")
	}
}

func TestEnsureRejectsSHA256Mismatch(t *testing.T) {
	_, _, err := Ensure(Source{
		FS:     fstest.MapFS{"crosslink-daemon": {Data: []byte("daemon-v1")}},
		Path:   "crosslink-daemon",
		SHA256: "bad",
	}, filepath.Join(t.TempDir(), "crosslink-daemon"))
	if err == nil {
		t.Fatal("expected sha mismatch error")
	}
}
