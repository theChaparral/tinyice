// consume: build linux darwin freebsd
// +build linux darwin freebsd

package server

import (
	"syscall"
	"golang.org/x/sys/unix"
)

func setReusePort(fd uintptr) error {
	err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	if err != nil {
		return err
	}
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1)
}
