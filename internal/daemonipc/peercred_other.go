//go:build !darwin && !linux

package daemonipc

import (
	"fmt"
	"net"
	"runtime"
)

func defaultAuthorizedOwner() (uid, gid int) { return -1, -1 }

func validatePeer(conn net.Conn, authorizedUID int) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	return fmt.Errorf("peer credentials are not implemented on %s", runtime.GOOS)
}

func configureSocketOwner(net.Listener, int, int) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	return fmt.Errorf("socket ownership is not implemented on %s", runtime.GOOS)
}
