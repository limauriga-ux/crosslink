//go:build linux

package outbound

import "syscall"

func bindToInterface(ifIndex int, ifName string) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var innerErr error
		err := c.Control(func(fd uintptr) {
			innerErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifName)
		})
		if err != nil {
			return err
		}
		return innerErr
	}
}
