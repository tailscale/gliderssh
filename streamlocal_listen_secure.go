// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || darwin || freebsd || openbsd

package ssh

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// listenUnixSocket creates and configures the socket in a private staging
// directory, then atomically moves it to path. Directory descriptors keep both
// the staging and destination directories pinned while names are manipulated.
func listenUnixSocket(ctx context.Context, path string, mode os.FileMode, opts UnixForwardingOptions) (net.Listener, error) {
	parentPath, base := filepath.Dir(path), filepath.Base(path)
	parentFD, err := openDirNoSymlinks(parentPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open socket directory %q: %w", parentPath, err)
	}
	keepParentFD := false
	defer func() {
		if !keepParentFD {
			_ = unix.Close(parentFD)
		}
	}()

	stageName, err := makeStageDir(parentFD)
	if err != nil {
		return nil, fmt.Errorf("failed to create socket staging directory: %w", err)
	}
	stageFD, err := unix.Openat(parentFD, stageName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Unlinkat(parentFD, stageName, unix.AT_REMOVEDIR)
		return nil, fmt.Errorf("failed to open socket staging directory: %w", err)
	}
	defer unix.Close(stageFD)
	defer unix.Unlinkat(parentFD, stageName, unix.AT_REMOVEDIR)

	var stageStat unix.Stat_t
	if err := unix.Fstat(stageFD, &stageStat); err != nil {
		return nil, fmt.Errorf("failed to inspect socket staging directory: %w", err)
	}
	if stageStat.Mode&unix.S_IFMT != unix.S_IFDIR || stageStat.Mode&0o777 != 0o700 || int(stageStat.Uid) != os.Geteuid() {
		return nil, errors.New("socket staging directory has unexpected type, mode, or owner")
	}

	stagePath := filepath.Join(parentPath, stageName, "s")
	ln, err := bindStagedUnixSocket(ctx, stageFD, stagePath, path)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on unix socket %q: %w", path, err)
	}
	uln, ok := ln.(*net.UnixListener)
	if !ok {
		_ = ln.Close()
		return nil, errors.New("unix listen returned a non-Unix listener")
	}
	uln.SetUnlinkOnClose(false)
	cleanupListener := true
	defer func() {
		if cleanupListener {
			_ = ln.Close()
			_ = unix.Unlinkat(stageFD, "s", 0)
		}
	}()

	if err := configureStagedSocket(stageFD, path, mode, opts.BindOwner); err != nil {
		return nil, err
	}

	if err := prepareDestination(parentFD, base, opts.BindUnlink); err != nil {
		return nil, err
	}
	if err := unix.Renameat(stageFD, "s", parentFD, base); err != nil {
		return nil, fmt.Errorf("failed to install unix socket %q: %w", path, err)
	}

	cleanupListener = false
	keepParentFD = true
	return &renamedUnixListener{Listener: ln, dirFD: parentFD, name: base, addr: &net.UnixAddr{Name: path, Net: "unix"}}, nil
}

func configureStagedSocket(stageFD int, finalPath string, mode os.FileMode, owner *UnixSocketOwner) error {
	var socketStat unix.Stat_t
	if err := unix.Fstatat(stageFD, "s", &socketStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("failed to inspect staged socket: %w", err)
	}
	if socketStat.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return errors.New("staged socket path is not a socket")
	}
	if err := unix.Fchmodat(stageFD, "s", uint32(mode.Perm()), 0); err != nil {
		return fmt.Errorf("failed to set permissions on socket %q: %w", finalPath, err)
	}
	if owner != nil {
		if err := unix.Fchownat(stageFD, "s", owner.UID, owner.GID, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fmt.Errorf("failed to set owner on socket %q: %w", finalPath, err)
		}
	}
	return nil
}

func openDirNoSymlinks(path string) (int, error) {
	if !filepath.IsAbs(path) {
		return -1, errors.New("directory path is not absolute")
	}
	fd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if err != nil {
			return -1, err
		}
		fd = next
	}
	return fd, nil
}

func makeStageDir(parentFD int) (string, error) {
	for range 100 {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		// Randomness only avoids collisions; the directory's ownership and
		// mode provide the security boundary. Keep this name short because it
		// counts against sockaddr_un's path limit on Darwin and OpenBSD.
		name := ".s" + hex.EncodeToString(b[:])
		if err := unix.Mkdirat(parentFD, name, 0o700); err == nil {
			return name, nil
		} else if !errors.Is(err, unix.EEXIST) {
			return "", err
		}
	}
	return "", errors.New("could not allocate a unique staging directory")
}

func prepareDestination(dirFD int, name string, bindUnlink bool) error {
	var st unix.Stat_t
	err := unix.Fstatat(dirFD, name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to inspect existing socket %q: %w", name, err)
	}
	if !bindUnlink || st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return fmt.Errorf("socket path %q already exists", name)
	}
	if err := unix.Unlinkat(dirFD, name, 0); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("failed to unlink existing socket %q: %w", name, err)
	}
	return nil
}

type renamedUnixListener struct {
	net.Listener
	dirFD int
	name  string
	addr  net.Addr
	once  sync.Once
}

func (l *renamedUnixListener) Addr() net.Addr { return l.addr }

func (l *renamedUnixListener) Close() error {
	err := l.Listener.Close()
	l.once.Do(func() {
		_ = unix.Unlinkat(l.dirFD, l.name, 0)
		_ = unix.Close(l.dirFD)
	})
	return err
}
