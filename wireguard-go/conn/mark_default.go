//go:build !linux && !openbsd && !freebsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import "net"

func (s *StdNetBind) SetMark(mark uint32) error {
	return nil
}

func (t *TcpBind) SetMark(mark uint32) error {
	t.mu.Lock()
	t.fwmark = mark
	t.mu.Unlock()
	return nil
}

func (t *TcpBind) applyMark(conn *net.TCPConn) error {
	return nil
}
