package embeddeddaemon

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

type Source struct {
	FS     fs.FS
	Path   string
	SHA256 string
}

func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", "crosslink-daemon")
	}
	name := "crosslink-daemon"
	if runtime.GOOS == "windows" {
		name = "crosslink-daemon.exe"
	}
	return filepath.Join(home, ".crosslink", "bin", name)
}

// Ensure makes the bundled daemon binary present at dst. It returns the final
// path, a boolean replaced flag that is true whenever this call wrote new
// bytes (file did not exist, or its contents differed from src), and any
// error.
//
// The replaced flag lets callers detect that a freshly-extracted daemon may
// not match what is currently running under launchd: the on-disk file changed
// in this GUI session, but a launchd-managed daemon already exec'd the old
// bytes is still serving requests from memory. Callers can use it to trigger
// `launchctl kickstart -k` so the running process is restarted from the new
// file.
func Ensure(src Source, dst string) (string, bool, error) {
	if dst == "" {
		dst = DefaultPath()
	}
	data, err := fs.ReadFile(src.FS, src.Path)
	if err != nil {
		return "", false, fmt.Errorf("read embedded daemon: %w", err)
	}
	sum := sha256Hex(data)
	if src.SHA256 != "" && sum != src.SHA256 {
		return "", false, fmt.Errorf("embedded daemon sha256 mismatch: got %s want %s", sum, src.SHA256)
	}
	current, err := os.ReadFile(dst)
	if err == nil && bytes.Equal(current, data) && sha256Hex(current) == sum {
		return dst, false, nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return "", false, fmt.Errorf("create daemon dir: %w", err)
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, data, 0755); err != nil {
		return "", false, fmt.Errorf("write daemon: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp) //nolint:errcheck
		return "", false, fmt.Errorf("install daemon: %w", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(dst, 0755); err != nil {
			return "", false, fmt.Errorf("chmod daemon: %w", err)
		}
	}
	return dst, true, nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
