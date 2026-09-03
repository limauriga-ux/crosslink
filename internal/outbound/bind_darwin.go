//go:build darwin

package outbound

import "syscall"

const ipBoundIf = 25 // IP_BOUND_IF on macOS

func bindToInterface(ifIndex int, ifName string) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var innerErr error
		err := c.Control(func(fd uintptr) {
			innerErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipBoundIf, ifIndex)
		})
		if err != nil {
			return err
		}
		return innerErr
	}
}
