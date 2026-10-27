// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin || openbsd

package ssh

import (
	"context"
	"fmt"
	"net"
)

func bindStagedUnixSocket(ctx context.Context, _ int, stagePath, finalPath string) (net.Listener, error) {
	// Darwin and OpenBSD have neither bindat nor a procfs descriptor path.
	// Their secure staging path must therefore fit in sockaddr_un in addition
	// to the final path validated by the caller.
	if len(stagePath) >= maxSunPathLen {
		return nil, fmt.Errorf("unix socket path %q leaves insufficient room for secure staging (%d-byte staged path >= %d-byte limit)", finalPath, len(stagePath), maxSunPathLen)
	}
	return (&net.ListenConfig{}).Listen(ctx, "unix", stagePath)
}
