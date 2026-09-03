package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/limauriga-ux/crosslink/internal/managedfs"
)

// WritePidFile writes the PID to a file owned by the current process.
func WritePidFile(path string, pid int) error {
	return WritePidFileOwned(path, pid, -1, -1)
}

// WritePidFileOwned writes a PID atomically and, when owner IDs are supplied,
// assigns the temporary inode before it becomes visible.
func WritePidFileOwned(path string, pid, uid, gid int) error {
	root, err := managedfs.Open(filepath.Dir(path), true)
	if err != nil {
		return err
	}
	defer root.Close()
	content := []byte(strconv.Itoa(pid) + "\n")
	if uid >= 0 && gid >= 0 {
		return root.WriteFileAtomicOwned(path, content, 0o600, uid, gid)
	}
	return root.WriteFileAtomic(path, content, 0o600)
}

// ReadPidFile reads the PID from a file.
func ReadPidFile(path string) (int, error) {
	root, err := managedfs.Open(filepath.Dir(path), false)
	if err != nil {
		return 0, err
	}
	defer root.Close()
	data, err := root.ReadFile(path, 64)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, err
	}
	return pid, nil
}

// RemovePidFile removes the PID file.
func RemovePidFile(path string) error {
	root, err := managedfs.Open(filepath.Dir(path), false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	return root.Remove(path)
}

// PidFilePath returns the default PID file path.
func PidFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".crosslink.pid"
	}
	return filepath.Join(home, ".crosslink", "crosslink.pid")
}
