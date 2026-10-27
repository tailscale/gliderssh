// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build android || (!linux && !darwin && !freebsd && !openbsd)

package ssh

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
)

func listenUnixSocket(ctx context.Context, path string, mode os.FileMode, opts UnixForwardingOptions) (net.Listener, error) {
	if opts.BindUnlink {
		if info, err := os.Lstat(path); err == nil && info.Mode().Type() == os.ModeSocket {
			if err := unlink(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return nil, fmt.Errorf("failed to unlink existing socket %q: %w", path, err)
			}
		}
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on unix socket %q: %w", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("failed to set permissions on socket %q: %w", path, err)
	}
	if opts.BindOwner != nil {
		if err := os.Lchown(path, opts.BindOwner.UID, opts.BindOwner.GID); err != nil {
			_ = ln.Close()
			return nil, fmt.Errorf("failed to set owner on socket %q: %w", path, err)
		}
	}
	return ln, nil
}
