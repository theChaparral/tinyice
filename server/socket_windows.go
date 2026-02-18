// consume: build windows
//go:build windows
// +build windows

package server

import (
	"syscall"
)

func setReusePort(fd uintptr) error {
	// On Windows, syscall.SetsockoptInt takes syscall.Handle
	// SO_REUSEPORT is not supported on Windows, so we only set SO_REUSEADDR
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
}
