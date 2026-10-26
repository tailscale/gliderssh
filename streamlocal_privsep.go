package ssh

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// envPrivsep activates privsep child mode in a re-executed process.
	// It is for internal use and must not be set by embedders.
	envPrivsep = "_GLIDERSSH_PRIVSEP_CHILD"

	kindDial   = "dial"
	kindListen = "listen"
	kindUnlink = "unlink"
)

// ErrPrivsepChild reports that a forward failed because the session's privsep
// child could not run or stopped responding. It is transient: the next forward
// request on the connection retries with a fresh child.
var ErrPrivsepChild = errors.New("privsep child failed")

// childError wraps spawn and transport failures so that embedders can identify
// them with errors.Is(err, ErrPrivsepChild).
type childError struct{ err error }

func (e *childError) Error() string   { return "privsep child: " + e.err.Error() }
func (e *childError) Unwrap() []error { return []error{ErrPrivsepChild, e.err} }

// privsepRequest is one forwarding operation sent from parent to child. Replies
// arrive as a single privsepResponse datagram carrying any resulting file
// descriptor as SCM_RIGHTS out-of-band data.
type privsepRequest struct {
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	Unlink bool   `json:"unlink,omitempty"` // remove existing socket before bind
	Mode   uint32 `json:"mode,omitempty"`   // listen permission bits, applied via umask
}

// privsepResponse is one reply from the child. File descriptors arrive as
// SCM_RIGHTS on the same datagram.
type privsepResponse struct {
	Err string `json:"err,omitempty"`

	// ErrCode carries the underlying syscall errno when the child's error
	// is a syscall.Errno, so callers can errors.Is against fs.ErrNotExist,
	// fs.ErrPermission, and similar sentinels.
	ErrCode int `json:"errCode,omitempty"`

	// Token is set only in the child's hello, echoing the spawn secret
	// for the parent to verify.
	Token string `json:"token,omitempty"`
}

// privsepErr translates a child error back into a parent-side error. On
// platforms with an errno model the syscall error is reconstructed so
// errors.Is keeps working across the child boundary.
func privsepErr(resp privsepResponse) error {
	if err := errnoFromCode(resp.ErrCode); err != nil {
		return fmt.Errorf("privsep child: %w", err)
	}
	return errors.New(resp.Err)
}

const privsepMaxMsgLen = 4096

// privsepChild is a per-connection process running as the session user.
// Dial, listen, and unlink calls execute in it via the methods below,
// keeping privileged path syscalls out of the parent (privilege separation).
type privsepChild struct {
	mu        sync.Mutex // serializes request/reply pairs
	conn      *net.UnixConn
	cmd       *exec.Cmd
	closeOnce sync.Once
	dead      atomic.Bool
}

var (
	// forwardingPrivsepKey is the ctx value key for a session's child.
	forwardingPrivsepKey = &contextKey{"forwarding-privsep-child"}

	// inProcessIdentity marks that SessionUser resolved to the process
	// identity, so syscalls run in-process without re-resolving.
	inProcessIdentity = &struct{}{}

	// reapWait is how long Close waits for the child to exit on its own
	// before killing it.
	reapWait = 2 * time.Second
)

// sessionPrivsepChild returns the privsep child for ctx, spawning it on first
// use. It returns a nil child when SessionUser is unset or the resolved
// identity matches the process identity and syscalls can run in-process.
func sessionPrivsepChild(ctx Context, opts UnixForwardingOptions) (*privsepChild, error) {
	if opts.SessionUser == nil {
		return nil, nil
	}
	// The in-process sentinel survives for the session. A matching
	// identity never needs the resolver to run again.
	if ctxInProcess(ctx) {
		return nil, nil
	}
	if h := cachedPrivsepChild(ctx); h != nil {
		return h, nil
	}

	uid, gid, groups, err := opts.SessionUser(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve session user: %w", err)
	}

	ctx.Lock()
	defer ctx.Unlock()

	if ctxInProcess(ctx) {
		return nil, nil
	}
	if h := cachedPrivsepChild(ctx); h != nil {
		return h, nil
	}
	if uid == os.Geteuid() && gid == os.Getegid() {
		ctx.SetValue(forwardingPrivsepKey, inProcessIdentity)
		return nil, nil
	}

	h, err := spawnPrivsepChild(uid, gid, groups)
	if err != nil {
		return nil, &childError{err}
	}
	ctx.SetValue(forwardingPrivsepKey, h)
	go func() {
		<-ctx.Done()
		h.Close()
	}()
	return h, nil
}

// ctxInProcess reports whether the sentinel marks in-process execution.
func ctxInProcess(ctx Context) bool {
	return ctx.Value(forwardingPrivsepKey) == inProcessIdentity
}

// cachedPrivsepChild returns the live child stored in ctx, or nil when no
// child is cached, the sentinel marks in-process execution, or the cached
// child died and should be replaced. A dead child is reaped so repeated
// kills by the session user cannot accumulate zombies.
func cachedPrivsepChild(ctx Context) *privsepChild {
	switch c := ctx.Value(forwardingPrivsepKey).(type) {
	case *privsepChild:
		if c.dead.Load() {
			go c.Close() // reap, respawn on next use
			return nil
		}
		return c
	default:
		// inProcessIdentity sentinel or unset value.
		return nil
	}
}

// dialConn connects to path inside the child and returns the resulting connection.
func (c *privsepChild) dialConn(path string) (net.Conn, error) {
	file, err := c.call(privsepRequest{Kind: kindDial, Path: path})
	if err != nil {
		return nil, err
	} else if file == nil {
		return nil, errors.New("privsep child returned no connection")
	}
	defer func() { _ = file.Close() }() // conn holds the dup
	conn, err := net.FileConn(file)
	if err != nil {
		return nil, fmt.Errorf("wrap privsep child fd: %w", err)
	}
	return conn, nil
}

// listenConn binds path inside the child with permission bits mode,
// optionally removing an existing socket first. The returned listener removes
// the socket path on close by asking the child to unlink it, matching
// in-process forwarding without running any path syscall as the parent.
func (c *privsepChild) listenConn(path string, mode os.FileMode, unlink bool) (net.Listener, error) {
	req := privsepRequest{Kind: kindListen, Path: path, Unlink: unlink, Mode: uint32(mode)}
	file, err := c.call(req)
	if err != nil {
		return nil, err
	}
	if file == nil {
		return nil, errors.New("privsep child returned no listener")
	}
	defer func() { _ = file.Close() }() // listener holds the dup
	ln, err := net.FileListener(file)
	if err != nil {
		return nil, fmt.Errorf("wrap privsep child fd: %w", err)
	}
	if ul, ok := ln.(*net.UnixListener); ok {
		disableParentUnlink(ul)
	}
	return &privsepListener{Listener: ln, c: c, path: path}, nil
}

// privsepListener wraps a listener bound inside the child and delegates socket
// file removal to that child on close.
type privsepListener struct {
	net.Listener
	c    *privsepChild
	path string
}

func (l *privsepListener) Close() error {
	err := l.Listener.Close()
	// Best-effort cleanup as the session user. A dead child leaves the
	// socket file in place rather than unlinking with parent privileges.
	_, _ = l.c.call(privsepRequest{Kind: kindUnlink, Path: l.path})
	return err
}

// call sends one request and waits for its reply, returning any received file descriptor.
func (c *privsepChild) call(req privsepRequest) (*os.File, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, _, err := c.conn.WriteMsgUnix(payload, nil, nil); err != nil {
		c.dead.Store(true)
		go c.Close() // reap, respawn on next use
		return nil, &childError{fmt.Errorf("write request: %w", err)}
	}

	var oob [256]byte // room for one SCM_RIGHTS message
	buf := make([]byte, privsepMaxMsgLen)
	n, oobn, _, _, err := c.conn.ReadMsgUnix(buf, oob[:])
	if err != nil {
		c.dead.Store(true)
		go c.Close() // reap, respawn on next use
		return nil, &childError{fmt.Errorf("read reply: %w", err)}
	}

	file := fileFromOOB(oob[:oobn])
	var resp privsepResponse
	if err := json.Unmarshal(buf[:n], &resp); err != nil {
		if file != nil {
			_ = file.Close()
		}
		return nil, fmt.Errorf("privsep child reply: %w", err)
	}
	if resp.Err != "" {
		if file != nil {
			_ = file.Close()
		}
		return nil, privsepErr(resp)
	}
	return file, nil
}

// Close shuts down the child connection and process. Safe for concurrent use.
// It never blocks on request serialization so a hung child or stuck dial
// cannot wedge session cleanup; closing the conn unblocks any pending call.
func (c *privsepChild) Close() {
	c.closeOnce.Do(func() {
		c.dead.Store(true)
		_ = c.conn.Close()
		done := make(chan error, 1)
		go func() { done <- c.cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(reapWait):
			_ = c.cmd.Process.Kill()
			<-done
		}
	})
}

// handshake reads the child's hello and verifies it echoes the spawn token,
// failing fast if fd 3 was not wired to the process we spawned.
func (c *privsepChild) handshake(token string) error {
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = c.conn.SetReadDeadline(time.Time{}) }()

	buf := make([]byte, privsepMaxMsgLen)
	n, _, _, _, err := c.conn.ReadMsgUnix(buf, nil)
	if err != nil {
		return fmt.Errorf("read hello: %w", err)
	}
	var resp privsepResponse
	if err := json.Unmarshal(buf[:n], &resp); err != nil {
		return fmt.Errorf("hello: %w", err)
	} else if subtle.ConstantTimeCompare([]byte(resp.Token), []byte(token)) != 1 {
		return errors.New("token mismatch")
	}
	return nil
}
