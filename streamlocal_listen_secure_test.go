// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || darwin || freebsd || openbsd

package ssh

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMakeStageDirUsesShortName(t *testing.T) {
	dir := tempDirUnixSocket(t)
	resolvedDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := openDirNoSymlinks(resolvedDir)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)

	name, err := makeStageDir(fd)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Unlinkat(fd, name, unix.AT_REMOVEDIR)
	const maxStagingOverhead = 13
	stagedPath := filepath.Join(resolvedDir, name, "s")
	if overhead := len(stagedPath) - len(resolvedDir); overhead > maxStagingOverhead {
		t.Errorf("staging path adds %d bytes, want at most %d", overhead, maxStagingOverhead)
	}
}

func TestConfigureStagedSocketPinsDirectory(t *testing.T) {
	dir := tempDirUnixSocket(t)
	resolvedDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	parentFD, err := openDirNoSymlinks(resolvedDir)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(parentFD)

	stageName, err := makeStageDir(parentFD)
	if err != nil {
		t.Fatal(err)
	}
	stageFD, err := unix.Openat(parentFD, stageName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(stageFD)

	stagePath := filepath.Join(resolvedDir, stageName, "s")
	ln, err := net.Listen("unix", stagePath)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	defer ln.Close() //nolint:errcheck

	// Move the private directory after it has been opened, then replace its
	// old pathname with an attacker-controlled directory and regular file.
	// Descriptor-relative configuration must still affect the original socket.
	movedName := stageName + "-moved"
	if err := unix.Renameat(parentFD, stageName, parentFD, movedName); err != nil {
		t.Fatal(err)
	}
	defer unix.Unlinkat(parentFD, movedName, unix.AT_REMOVEDIR)
	if err := unix.Mkdirat(parentFD, stageName, 0o700); err != nil {
		t.Fatal(err)
	}
	defer unix.Unlinkat(parentFD, stageName, unix.AT_REMOVEDIR)
	replacement := filepath.Join(resolvedDir, stageName, "s")
	if err := os.WriteFile(replacement, []byte("do not modify"), 0o600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(replacement)

	if err := configureStagedSocket(stageFD, "test socket", 0o666, nil); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(replacement); err != nil {
		t.Fatal(err)
	} else if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("replacement file mode = %04o, want 0600 unchanged", got)
	}
	original := filepath.Join(resolvedDir, movedName, "s")
	if fi, err := os.Stat(original); err != nil {
		t.Fatal(err)
	} else if got := fi.Mode().Perm(); got != 0o666 {
		t.Errorf("pinned socket mode = %04o, want 0666", got)
	}
	if err := unix.Unlinkat(stageFD, "s", 0); err != nil {
		t.Fatal(err)
	}
}
