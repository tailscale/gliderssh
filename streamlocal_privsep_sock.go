//go:build unix

package ssh

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"syscall"
)

const privsepFD = 3 // ExtraFiles index -> fd number in the child

// errnoFromCode reconstructs a syscall.Errno from a child-supplied code.
// Non-positive codes map to nil so no errno identity is invented for
// successful or unspecified replies.
func errnoFromCode(code int) error {
	if code <= 0 {
		return nil
	}
	return syscall.Errno(code)
}

func init() {
	// Any non-empty value enables child mode; the token is verified over
	// the socketpair, not from the environment.
	if token := os.Getenv(envPrivsep); token != "" {
		runPrivsepChild(token)
	}
}

// runPrivsepChild serves forwarding requests until the parent disconnects, then exits
// without running main. This keeps embedder logic from executing as the session user.
func runPrivsepChild(token string) {
	f := os.NewFile(privsepFD, envPrivsep)
	pc, err := net.FilePacketConn(f)
	_ = f.Close()
	if err != nil {
		os.Exit(1)
	}
	uc, ok := pc.(*net.UnixConn)
	if !ok {
		os.Exit(1)
	}
	servePrivsepChild(uc, token)
	os.Exit(0)
}

// servePrivsepChild handles one request at a time because umask is process-global.
func servePrivsepChild(c *net.UnixConn, token string) {
	hello, _ := json.Marshal(privsepResponse{Token: token})
	if _, _, err := c.WriteMsgUnix(hello, nil, nil); err != nil {
		return
	}

	buf := make([]byte, privsepMaxMsgLen)
	for {
		n, _, _, _, err := c.ReadMsgUnix(buf, nil)
		if err != nil || n == 0 {
			return
		}
		var req privsepRequest
		if err := json.Unmarshal(buf[:n], &req); err != nil {
			continue // malformed datagram, drop it
		}

		file, rerr := handlePrivsepRequest(req)
		resp := privsepResponse{}
		if rerr != nil {
			resp.Err = rerr.Error()
			resp.ErrCode = errnoCode(rerr)
		}
		payload, _ := json.Marshal(resp)

		var oob []byte
		if file != nil {
			oob = syscall.UnixRights(int(file.Fd()))
		}
		_, _, werr := c.WriteMsgUnix(payload, oob, nil)
		if file != nil {
			_ = file.Close() // parent holds the dup
		}
		if werr != nil {
			return
		}
	}
}

func handlePrivsepRequest(req privsepRequest) (*os.File, error) {
	switch req.Kind {
	case kindDial:
		return serveDial(req.Path)
	case kindListen:
		return serveListen(req)
	case kindUnlink:
		return nil, serveUnlink(req.Path)
	default:
		return nil, fmt.Errorf("unknown request kind %q", req.Kind)
	}
}

// serveDial connects to path with the session user's credentials.
func serveDial(path string) (*os.File, error) {
	uc, err := net.DialUnix("unix", nil, &net.UnixAddr{Net: "unix", Name: path})
	if err != nil {
		return nil, err
	}
	file, err := uc.File()
	if err != nil {
		_ = uc.Close()
		return nil, err
	}
	_ = uc.Close() // file holds a dup
	return file, nil
}

// serveListen binds path with permission bits mode. The umask at bind time
// yields the final mode, avoiding a racy chmod of the bound path.
func serveListen(req privsepRequest) (*os.File, error) {
	mode := os.FileMode(req.Mode) & 0o777

	oldUmask := syscall.Umask(int(0o777 &^ uint32(mode)))
	defer syscall.Umask(oldUmask)

	if req.Unlink {
		// Only remove socket files; regular files fail the bind with
		// EADDRINUSE instead of being deleted.
		if info, serr := os.Lstat(req.Path); serr == nil && info.Mode().Type() == os.ModeSocket {
			if uerr := os.Remove(req.Path); uerr != nil && !errors.Is(uerr, fs.ErrNotExist) {
				return nil, fmt.Errorf("unlink %q: %w", req.Path, uerr)
			}
		}
	}

	ln, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: req.Path})
	if err != nil {
		return nil, err
	}
	file, err := ln.File()
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	// Keep the socket file; the parent listener owns path removal.
	ln.SetUnlinkOnClose(false)
	_ = ln.Close() // file holds a dup
	return file, nil
}

// serveUnlink removes path as the session user. This keeps socket cleanup out of the
// privileged parent, whose unlink would otherwise re-resolve the path with root privileges.
func serveUnlink(path string) error {
	err := os.Remove(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// disableParentUnlink ensures the parent-side listener never removes its own
// socket path: Close would re-resolve it with the process's privileges.
// Cleanup is delegated to the child via privsepListener instead.
func disableParentUnlink(ln *net.UnixListener) {
	ln.SetUnlinkOnClose(false)
}

// spawnPrivsepChild starts the per-session child process running as uid/gid
// with supplementary groups.
func spawnPrivsepChild(uid, gid int, groups []int) (*privsepChild, error) {
	token, err := newPrivsepToken()
	if err != nil {
		return nil, fmt.Errorf("generate privsep token: %w", err)
	}

	// SOCK_DGRAM on a socketpair is message-oriented and supports
	// SCM_RIGHTS everywhere we can build. Darwin lacks unix SOCK_SEQPACKET.
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, fmt.Errorf("privsep child socketpair: %w", err)
	}
	syscall.CloseOnExec(pair[0])
	syscall.CloseOnExec(pair[1])

	exe, err := os.Executable()
	if err != nil {
		_ = syscall.Close(pair[0])
		_ = syscall.Close(pair[1])
		return nil, fmt.Errorf("resolve privsep child executable: %w", err)
	}

	parent := os.NewFile(uintptr(pair[0]), "gliderssh privsep parent")
	child := os.NewFile(uintptr(pair[1]), "gliderssh privsep child")

	cmd := exec.Command(exe)
	cmd.Env = privsepEnv(token)
	cmd.ExtraFiles = []*os.File{child}
	attr := &syscall.SysProcAttr{}
	if uid != os.Geteuid() || gid != os.Getegid() {
		attr.Credential = &syscall.Credential{
			Uid:    uint32(uid),
			Gid:    uint32(gid),
			Groups: u32ids(groups),
		}
	}
	cmd.SysProcAttr = attr

	c := &privsepChild{cmd: cmd}
	if err := cmd.Start(); err != nil {
		_ = parent.Close()
		_ = child.Close()
		return nil, fmt.Errorf("start forwarding privsep child: %w", err)
	}

	pc, perr := net.FilePacketConn(parent)
	_ = parent.Close()
	_ = child.Close() // exec made its dup during Start
	if perr != nil {
		_ = c.cmd.Process.Kill()
		_ = c.cmd.Wait()
		return nil, fmt.Errorf("privsep child socket: %w", perr)
	}
	uc, ok := pc.(*net.UnixConn)
	if !ok {
		_ = c.cmd.Process.Kill()
		_ = c.cmd.Wait()
		return nil, errors.New("privsep child socket: not a unix conn")
	}
	c.conn = uc

	if err := c.handshake(token); err != nil {
		c.Close()
		return nil, fmt.Errorf("privsep child handshake: %w", err)
	}
	return c, nil
}

// privsepEnv returns a minimal environment for the child. It runs as the
// session user, and its /proc environ is readable by that user after exec,
// so nothing from the embedder's environment may leak into it.
func privsepEnv(token string) []string {
	env := []string{envPrivsep + "=" + token}
	for _, key := range []string{"GODEBUG", "GOMAXPROCS", "GOGC", "GOMEMLIMIT"} {
		if v, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+v)
		}
	}
	return env
}

// newPrivsepToken returns a random one-time token the child must echo back
// in its hello, so fd 3 cannot be pre-seeded with a foreign socket.
func newPrivsepToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// u32ids converts group ids for syscall.Credential.
func u32ids(ids []int) []uint32 {
	out := make([]uint32, len(ids))
	for i, id := range ids {
		out[i] = uint32(id)
	}
	return out
}

// fileFromOOB extracts the first file descriptor from out-of-band data.
func fileFromOOB(oob []byte) *os.File {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil
	}
	for _, m := range msgs {
		fds, err := syscall.ParseUnixRights(&m)
		if err != nil {
			continue
		}
		if len(fds) > 0 {
			return os.NewFile(uintptr(fds[0]), "gliderssh privsep child socket")
		}
	}
	return nil
}

// errnoCode returns the syscall errno underlying err, or 0 when err is not
// a syscall error. The value crosses the child boundary as a plain int and
// is turned back into a syscall.Errno by errnoFromCode on the parent.
func errnoCode(err error) int {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return int(errno)
	}
	return 0
}
