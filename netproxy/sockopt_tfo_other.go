//go:build !linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
 */

package netproxy

import (
	"errors"
	"syscall"
)

// TfoControl reports the platform as unsupported: TCP_FASTOPEN_CONNECT is a
// Linux 4.11+ socket option. Dialers that request TFO surface this error only
// when the option is actually enabled in their configuration.
func TfoControl(c syscall.RawConn) error {
	return errors.New("tcp fast open is only supported on linux")
}
