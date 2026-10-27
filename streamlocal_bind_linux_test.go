// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package ssh

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestReverseUnixForwardingFullLengthPath(t *testing.T) {
	dir := tempDirUnixSocket(t)
	baseLen := maxSunPathLen - len(dir) - 2 // slash plus one byte below the limit
	if baseLen < 1 {
		t.Skip("temporary directory is too long for a full-length socket path")
	}
	path := filepath.Join(dir, strings.Repeat("s", baseLen))
	if len(path) != maxSunPathLen-1 {
		t.Fatalf("test socket path length = %d, want %d", len(path), maxSunPathLen-1)
	}

	ctx, cancel := newContext(nil)
	defer cancel()
	ln, err := NewReverseUnixForwardingCallback(UnixForwardingOptions{AllowAll: true})(ctx, path)
	if err != nil {
		t.Fatalf("failed to listen at maximum-length path: %v", err)
	}
	defer ln.Close() //nolint:errcheck
}
