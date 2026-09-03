//go:build linux

package routetable

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func startWatcher(onChange func()) (stop func(), err error) {
	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	sa := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV6_ROUTE,
	}
	if err := unix.Bind(sock, sa); err != nil {
		unix.Close(sock)
		return nil, err
	}
	done := make(chan struct{})
	go func() {
		defer unix.Close(sock)
		buf := make([]byte, 4096)
		for {
			select {
			case <-done:
				return
			default:
			}
			n, err := unix.Read(sock, buf)
			if err != nil {
				return
			}
			msgs, _ := syscall.ParseNetlinkMessage(buf[:n])
			for _, msg := range msgs {
				if msg.Header.Type == uint16(unix.RTM_NEWROUTE) || msg.Header.Type == uint16(unix.RTM_DELROUTE) {
					onChange()
					break
				}
			}
		}
	}()
	return func() {
		close(done)
		unix.Close(sock)
	}, nil
}
