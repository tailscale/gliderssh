// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package ssh

import (
	"context"
	"fmt"
	"net"
)

func bindStagedUnixSocket(ctx context.Context, stageFD int, stagePath, finalPath string) (net.Listener, error) {
	// Binding through procfs makes the sockaddr independent of the length of
	// the destination directory while stageFD keeps that directory pinned.
	procPath := fmt.Sprintf("/proc/self/fd/%d/s", stageFD)
	ln, err := (&net.ListenConfig{}).Listen(ctx, "unix", procPath)
	if err == nil {
		return ln, nil
	}
	// Some systems do not mount procfs. Retain support when the ordinary
	// staging pathname still fits.
	if len(stagePath) >= maxSunPathLen {
		return nil, fmt.Errorf("unix socket path %q leaves insufficient room for secure staging and procfs binding failed: %w", finalPath, err)
	}
	return (&net.ListenConfig{}).Listen(ctx, "unix", stagePath)
}
