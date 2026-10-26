//go:build unix

package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
)

func ownIdentity(_ Context) (int, int, []int, error) {
	return os.Geteuid(), os.Getegid(), nil, nil
}

func TestSessionUserResolveErrorFailsForward(t *testing.T) {
	t.Parallel()

	ctx, cancel := newContext(nil)
	defer cancel()

	// A SessionUser error must fail the forward rather than fall back to
	// in-process execution.
	opts := UnixForwardingOptions{
		AllowAll: true,
		SessionUser: func(_ Context) (int, int, []int, error) {
			return 0, 0, nil, errors.New("no session user")
		},
	}
	if _, err := NewLocalUnixForwardingCallback(opts)(ctx, "/tmp/unused.sock"); err == nil {
		t.Fatal("dial with failing SessionUser succeeded; want error")
	}
	dir := tempDirUnixSocket(t)
	if _, err := NewReverseUnixForwardingCallback(opts)(ctx, filepath.Join(dir, "x.sock")); err == nil {
		t.Fatal("listen with failing SessionUser succeeded; want error")
	}
	if v := ctx.Value(forwardingPrivsepKey); v != nil {
		t.Fatalf("failed resolution stored %v in ctx", v)
	}
}

func TestSessionUserInProcessForwarding(t *testing.T) {
	t.Parallel()

	ctx, cancel := newContext(nil)
	defer cancel()

	// A matching SessionUser identity must keep forwarding in-process and
	// preserve existing dial behavior.
	l := sampleUnixSocketServer(t)
	cb := NewLocalUnixForwardingCallback(UnixForwardingOptions{
		AllowAll:    true,
		SessionUser: ownIdentity,
	})
	conn, err := cb(ctx, l.Addr().String())
	if err != nil {
		t.Fatalf("dial via in-process identity: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	result, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, sampleServerResponse) {
		t.Fatalf("result = %#v; want %#v", result, sampleServerResponse)
	}

	if _, ok := ctx.Value(forwardingPrivsepKey).(*privsepChild); ok {
		t.Fatal("matching identity spawned a privsep child")
	}
}

func TestSessionUserInProcessReverseForwarding(t *testing.T) {
	t.Parallel()

	ctx, cancel := newContext(nil)
	t.Cleanup(cancel)

	dir := tempDirUnixSocket(t)
	sockPath := filepath.Join(dir, "reverse.sock")
	cb := NewReverseUnixForwardingCallback(UnixForwardingOptions{
		AllowAll:    true,
		BindUnlink:  true,
		SessionUser: ownIdentity,
	})
	ln, err := cb(ctx, sockPath)
	if err != nil {
		t.Fatalf("listen via in-process identity: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	info, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("stat bound socket: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("socket permissions = %04o; want 0600", perm)
	}

	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		_, _ = c.Write(sampleServerResponse)
		_ = c.Close()
	}()

	c, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial bound socket: %v", err)
	}
	result, err := io.ReadAll(c)
	_ = c.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, sampleServerResponse) {
		t.Fatalf("result = %#v; want %#v", result, sampleServerResponse)
	}

	if _, ok := ctx.Value(forwardingPrivsepKey).(*privsepChild); ok {
		t.Fatal("matching identity spawned a privsep child")
	}
}

func TestPrivsepChildDialAndListen(t *testing.T) {
	t.Parallel()

	// spawnPrivsepChild re-executes the test binary, whose ssh package init
	// enters privsep child mode via envPrivsep before any test code runs.
	h, err := spawnPrivsepChild(os.Geteuid(), os.Getegid(), nil)
	if err != nil {
		t.Skipf("cannot spawn privsep child on this platform: %v", err)
	}

	// Close must be idempotent and reap the process.
	h.Close()
	h.Close()

	h2, err := spawnPrivsepChild(os.Geteuid(), os.Getegid(), nil)
	if err != nil {
		t.Fatalf("respawn privsep child: %v", err)
	}
	t.Cleanup(h2.Close)

	// Dial round trip through the privsep child process
	l := sampleUnixSocketServer(t)
	conn, err := h2.dialConn(l.Addr().String())
	if err != nil {
		t.Fatalf("privsep child dial: %v", err)
	}
	result, err := io.ReadAll(conn)
	_ = conn.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, sampleServerResponse) {
		t.Fatalf("result = %#v; want %#v", result, sampleServerResponse)
	}

	// Listen round trip: bind via privsep child, connect locally
	dir := tempDirUnixSocket(t)
	sockPath := filepath.Join(dir, "privsep.sock")
	ln, err := h2.listenConn(sockPath, 0o600, true)
	if err != nil {
		t.Fatalf("privsep child listen: %v", err)
	}
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		_, _ = c.Write(sampleServerResponse)
		_ = c.Close()
	}()

	info, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("stat privsep child socket: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("socket permissions = %04o; want 0600", perm)
	}

	c, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial privsep child socket: %v", err)
	}
	result, err = io.ReadAll(c)
	_ = c.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, sampleServerResponse) {
		t.Fatalf("result = %#v; want %#v", result, sampleServerResponse)
	}

	// The parent-side listener removes the path on close
	if err := ln.Close(); err != nil {
		t.Fatalf("close privsep child listener: %v", err)
	}
	if _, err := os.Stat(sockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket path not removed after close: %v", err)
	}
}

func TestPrivsepRequestErrorPropagates(t *testing.T) {
	t.Parallel()

	h, err := spawnPrivsepChild(os.Geteuid(), os.Getegid(), nil)
	if err != nil {
		t.Skipf("cannot spawn privsep child on this platform: %v", err)
	}
	t.Cleanup(h.Close)

	dir := tempDirUnixSocket(t)

	// Dialing a path that does not exist surfaces the child's error with
	// its syscall identity intact across the child boundary
	missing := filepath.Join(dir, "missing.sock")
	conn, err := h.dialConn(missing)
	if err == nil {
		_ = conn.Close()
		t.Fatal("dial missing socket succeeded; want error")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("dial missing socket error = %v; want fs.ErrNotExist", err)
	}

	// Unknown request kinds report a descriptive error
	want := `unknown request kind "bogus"`
	if _, err := h.call(privsepRequest{Kind: "bogus", Path: missing}); err == nil || err.Error() != want {
		t.Fatalf("bogus kind error = %v; want %q", err, want)
	}

	// A dead child's transport failures carry ErrPrivsepChild
	h.Close()
	_, err = h.call(privsepRequest{Kind: kindDial, Path: missing})
	if !errors.Is(err, ErrPrivsepChild) {
		t.Fatalf("call on closed child error = %v; want ErrPrivsepChild", err)
	}
}

func TestPrivsepChildConcurrentCalls(t *testing.T) {
	t.Parallel()

	// One child serves many forwards; requests are serialized by the
	// parent's mutex so replies never interleave.
	h, err := spawnPrivsepChild(os.Geteuid(), os.Getegid(), nil)
	if err != nil {
		t.Skipf("cannot spawn privsep child on this platform: %v", err)
	}
	t.Cleanup(h.Close)

	const n = 8
	l := newLocalUnixListener(t)
	go func() {
		for i := 0; i < n; i++ {
			conn, aerr := l.Accept()
			if aerr != nil {
				return
			}
			go func() {
				_, _ = conn.Write(sampleServerResponse)
				_ = conn.Close()
			}()
		}
	}()
	errCh := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			conn, err := h.dialConn(l.Addr().String())
			if err != nil {
				errCh <- fmt.Errorf("privsep child dial: %w", err)
				return
			}
			result, err := io.ReadAll(conn)
			_ = conn.Close()
			if err != nil {
				errCh <- err
				return
			}
			if !bytes.Equal(result, sampleServerResponse) {
				errCh <- fmt.Errorf("result = %#v", result)
				return
			}
			errCh <- nil
		}()
	}
	for i := 0; i < n; i++ {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
	_ = l.Close()
}

func TestPrivsepUnlinkRunsInChild(t *testing.T) {
	t.Parallel()

	dir := tempDirUnixSocket(t)
	sockPath := filepath.Join(dir, "cleanup.sock")

	// Bind with a live child, then kill it before closing the
	// listener. The parent-side close must not unlink on its own.
	h1, err := spawnPrivsepChild(os.Geteuid(), os.Getegid(), nil)
	if err != nil {
		t.Skipf("cannot spawn privsep child on this platform: %v", err)
	}
	ln1, err := h1.listenConn(sockPath, 0o600, true)
	if err != nil {
		t.Fatalf("privsep child listen: %v", err)
	}
	if _, ok := ln1.(*privsepListener); !ok {
		t.Fatal("listenConn did not return a privsepListener")
	}

	h1.Close() // child dies; the wrapper's unlink request will fail
	if err := ln1.Close(); err != nil {
		t.Fatalf("close listener without child: %v", err)
	}
	if _, err := os.Stat(sockPath); err != nil {
		t.Fatalf("parent unlinked socket path on close: %v", err)
	}

	// A live child removes the path when its wrapper listener closes
	h2, err := spawnPrivsepChild(os.Geteuid(), os.Getegid(), nil)
	if err != nil {
		t.Fatalf("respawn privsep child: %v", err)
	}
	t.Cleanup(h2.Close)

	ln2, err := h2.listenConn(sockPath, 0o600, true) // unlink leftover socket
	if err != nil {
		t.Fatalf("rebind socket: %v", err)
	}
	if _, err := os.Stat(sockPath); err != nil {
		t.Fatalf("stat rebound socket: %v", err)
	}
	if err := ln2.Close(); err != nil {
		t.Fatalf("close listener with child: %v", err)
	}
	if _, err := os.Stat(sockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket path not removed after close: %v", err)
	}
}

func TestPrivsepChildRespawnAfterDeath(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to run the privsep child as another user")
	}
	u, err := user.Lookup("nobody")
	if err != nil {
		t.Skipf("cannot resolve nobody: %v", err)
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		t.Skipf("cannot parse nobody ids: %v %v", err1, err2)
	}

	ctx, cancel := newContext(nil)
	t.Cleanup(cancel)
	opts := UnixForwardingOptions{
		AllowAll: true,
		SessionUser: func(_ Context) (int, int, []int, error) {
			return uid, gid, nil, nil
		},
	}

	h1, err := sessionPrivsepChild(ctx, opts)
	if err != nil {
		t.Skipf("cannot spawn privsep child on this platform: %v", err)
	}
	if h1 == nil {
		t.Fatal("differing identity did not spawn a privsep child")
	}

	// Simulate the child dying mid-session, then verify the next lookup
	// replaces it instead of returning the dead instance.
	h1.Close()
	if _, err := h1.call(privsepRequest{Kind: kindUnlink, Path: "/nonexistent"}); err == nil {
		t.Fatal("call on closed child succeeded")
	}

	h2, err := sessionPrivsepChild(ctx, opts)
	if err != nil {
		t.Fatalf("respawn after death: %v", err)
	}
	t.Cleanup(h2.Close)
	if h2 == nil || h2 == h1 {
		t.Fatal("dead privsep child was not replaced")
	}
}
