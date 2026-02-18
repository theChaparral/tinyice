// consume: build linux darwin freebsd
// +build linux darwin freebsd

package server

import (
	"syscall"
)

func setReusePort(fd uintptr) error {
	err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	if err != nil {
		return err
	}
	// 0x0f is SO_REUSEPORT on most Unix systems
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 0x0f, 1)
}
