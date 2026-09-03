//go:build linux || openbsd || freebsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"net"
	"runtime"

	"golang.org/x/sys/unix"
)

var fwmarkIoctl int

func init() {
	switch runtime.GOOS {
	case "linux", "android":
		fwmarkIoctl = 36 /* unix.SO_MARK */
	case "freebsd":
		fwmarkIoctl = 0x1015 /* unix.SO_USER_COOKIE */
	case "openbsd":
		fwmarkIoctl = 0x1021 /* unix.SO_RTABLE */
	}
}

func (s *StdNetBind) SetMark(mark uint32) error {
	var operr error
	if fwmarkIoctl == 0 {
		return nil
	}
	if s.ipv4 != nil {
		fd, err := s.ipv4.SyscallConn()
		if err != nil {
			return err
		}
		err = fd.Control(func(fd uintptr) {
			operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, fwmarkIoctl, int(mark))
		})
		if err == nil {
			err = operr
		}
		if err != nil {
			return err
		}
	}
	if s.ipv6 != nil {
		fd, err := s.ipv6.SyscallConn()
		if err != nil {
			return err
		}
		err = fd.Control(func(fd uintptr) {
			operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, fwmarkIoctl, int(mark))
		})
		if err == nil {
			err = operr
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (t *TcpBind) SetMark(mark uint32) error {
	if fwmarkIoctl == 0 {
		return nil
	}
	t.mu.Lock()
	t.fwmark = mark
	conns := make([]*tcpConn, 0, len(t.tcpConnMap))
	for _, conn := range t.tcpConnMap {
		conns = append(conns, conn)
	}
	t.mu.Unlock()

	var err error
	for _, conn := range conns {
		fd, e := conn.conn.SyscallConn()
		if e != nil {
			return e
		}
		e = fd.Control(func(fd uintptr) {
			err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, fwmarkIoctl, int(mark))
		})
		if e != nil {
			return e
		}
		if err != nil {
			return err
		}
	}
	return err
}

func (t *TcpBind) applyMark(conn *net.TCPConn) error {
	if fwmarkIoctl == 0 {
		return nil
	}
	t.mu.Lock()
	mark := t.fwmark
	t.mu.Unlock()
	if mark == 0 {
		return nil
	}
	fd, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var operr error
	err = fd.Control(func(fd uintptr) {
		operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, fwmarkIoctl, int(mark))
	})
	if err != nil {
		return err
	}
	return operr
}
