//go:build darwin || linux

package daemonipc

import (
	"fmt"
	"net"
	"os"
)

func defaultAuthorizedOwner() (uid, gid int) {
	return os.Getuid(), os.Getgid()
}

func authorizePeerUID(uid uint32, authorizedUID int) error {
	if authorizedUID < 0 {
		return fmt.Errorf("authorized uid is invalid")
	}
	// Root remains an administrative peer; the desktop identity is explicit.
	if uid == 0 || uint32(authorizedUID) == uid {
		return nil
	}
	return fmt.Errorf("unauthorized uid %d", uid)
}

func configureSocketOwner(listener net.Listener, uid, gid int) error {
	if uid < 0 || gid < 0 {
		return fmt.Errorf("socket owner is invalid")
	}
	if os.Getuid() != 0 && os.Getuid() != uid {
		return fmt.Errorf("cannot assign socket to uid %d from uid %d", uid, os.Getuid())
	}
	path := listenerPath(listener)
	if path == "" {
		return fmt.Errorf("listener socket path is unavailable")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("daemon socket was replaced before securing")
	}
	if os.Getuid() == 0 {
		if err := os.Chown(path, uid, gid); err != nil {
			return err
		}
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	finalInfo, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if finalInfo.Mode()&os.ModeSymlink != 0 || finalInfo.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("daemon socket changed while securing")
	}
	return nil
}

func listenerPath(listener net.Listener) string {
	if unixListener, ok := listener.(*net.UnixListener); ok {
		return unixListener.Addr().String()
	}
	return ""
}
