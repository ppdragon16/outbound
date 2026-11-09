//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
 */

package netproxy

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// TfoControl sets TCP_FASTOPEN_CONNECT on a TCP socket before connect(2).
// The kernel then defers the connection establishment to the first write(2),
// which sends the SYN carrying that data (when a TFO cookie for the peer is
// available; otherwise the handshake proceeds without payload and no data is
// lost). Callers must write promptly after dialing: a dial+close probe with
// TFO enabled never establishes a connection at all.
func TfoControl(c syscall.RawConn) error {
	var sockOptErr error
	controlErr := c.Control(func(fd uintptr) {
		err := unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN_CONNECT, 1)
		if err != nil {
			sockOptErr = fmt.Errorf("error setting TCP_FASTOPEN_CONNECT socket option: %w", err)
		}
	})
	if controlErr != nil {
		return fmt.Errorf("error invoking socket control function: %w", controlErr)
	}
	return sockOptErr
}
