//go:build darwin

package daemonipc

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func validatePeer(conn net.Conn, authorizedUID int) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("unexpected connection type %T", conn)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var peerUID uint32
	var peerErr error
	if err := raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			peerErr = err
			return
		}
		peerUID = cred.Uid
	}); err != nil {
		return err
	}
	if peerErr != nil {
		return peerErr
	}
	return authorizePeerUID(peerUID, authorizedUID)
}
