package daemonipc

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestServerSocketIsOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets are not used on Windows")
	}
	path := filepath.Join(t.TempDir(), "daemon.sock")
	srv := NewServer(path, func(cmd Cmd) Response { return Response{OK: true} })
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("socket mode = %#o, want 0600", got)
	}
}

func TestServerRefusesNonSocketAndSymlinkLeaves(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets are not used on Windows")
	}
	for _, test := range []struct {
		name  string
		setup func(path string) error
		want  string
	}{
		{name: "regular file", setup: func(path string) error { return os.WriteFile(path, []byte("keep"), 0o600) }, want: "non-socket"},
		{name: "directory", setup: func(path string) error { return os.Mkdir(path, 0o700) }, want: "non-socket"},
		{name: "symlink", setup: func(path string) error {
			target := filepath.Join(filepath.Dir(path), "target")
			if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
				return err
			}
			return os.Symlink(filepath.Base(target), path)
		}, want: "symlink"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "daemon.sock")
			if err := test.setup(path); err != nil {
				t.Fatal(err)
			}
			srv := NewServer(path, func(cmd Cmd) Response { return Response{OK: true} })
			err := srv.Start()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Start error = %v, want %q", err, test.want)
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("pre-existing leaf was removed: %v", err)
			}
		})
	}
}
