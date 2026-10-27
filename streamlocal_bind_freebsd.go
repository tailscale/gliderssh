// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build freebsd

package ssh

import (
	"context"
	"fmt"
	"net"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

func bindStagedUnixSocket(ctx context.Context, stageFD int, _, finalPath string) (net.Listener, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "unix-listener")
	defer f.Close()

	var addr unix.RawSockaddrUnix
	// x/sys/unix does not provide a Bindat wrapper. Match its BSD
	// SockaddrUnix encoding: two header bytes, "s", and its terminating NUL.
	addr.Len = 4
	addr.Family = unix.AF_UNIX
	addr.Path[0] = 's'
	_, _, errno := unix.Syscall6(unix.SYS_BINDAT, uintptr(stageFD), uintptr(fd), uintptr(unsafe.Pointer(&addr)), uintptr(addr.Len), 0, 0)
	if errno != 0 {
		return nil, fmt.Errorf("bindat unix socket %q: %w", finalPath, errno)
	}
	if err := unix.Listen(fd, unix.SOMAXCONN); err != nil {
		return nil, err
	}
	return net.FileListener(f)
}
