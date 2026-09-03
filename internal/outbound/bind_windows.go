//go:build windows

package outbound

import (
	"syscall"

	"golang.org/x/sys/windows"
)

const ipUnicastIf = 31 // IP_UNICAST_IF

func bindToInterface(ifIndex int, ifName string) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var innerErr error
		idx := uint32(ifIndex)
		err := c.Control(func(fd uintptr) {
			innerErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIf, int(idx))
		})
		if err != nil {
			return err
		}
		return innerErr
	}
}
