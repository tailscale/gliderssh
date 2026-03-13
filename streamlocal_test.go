package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

// tempDirUnixSocket returns a temporary directory that can safely hold unix
// sockets.
//
// On all platforms other than darwin this just returns t.TempDir(). On darwin
// we manually make a temporary directory in /tmp because t.TempDir() returns a
// very long directory name, and the path length limit for Unix sockets on
// darwin is 104 characters.
func tempDirUnixSocket(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "darwin" {
		testName := strings.ReplaceAll(t.Name(), "/", "_")
		dir, err := os.MkdirTemp("/tmp", fmt.Sprintf("gliderlabs-ssh-test-%s-", testName))
		if err != nil {
			t.Fatalf("create temp dir for test: %v", err)
		}

		t.Cleanup(func() {
			err := os.RemoveAll(dir)
			if err != nil {
				t.Errorf("remove temp dir %s: %v", dir, err)
			}
		})
		return dir
	}

	return t.TempDir()
}

func newLocalUnixListener(t *testing.T) net.Listener {
	path := filepath.Join(tempDirUnixSocket(t), "socket.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("failed to listen on a unix socket %q: %v", path, err)
	}
	return l
}

func sampleUnixSocketServer(t *testing.T) net.Listener {
	l := newLocalUnixListener(t)

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		conn.Write(sampleServerResponse)
		conn.Close()
	}()

	return l
}

func newTestSessionWithUnixForwarding(t *testing.T, forwardingEnabled bool) (net.Listener, *gossh.Client, func()) {
	l := sampleUnixSocketServer(t)

	allowAllCb := NewLocalUnixForwardingCallback(UnixForwardingOptions{AllowAll: true})
	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {},
		LocalUnixForwardingCallback: func(ctx Context, socketPath string) (net.Conn, error) {
			if socketPath != l.Addr().String() {
				panic("unexpected socket path: " + socketPath)
			}
			if !forwardingEnabled {
				return nil, ErrRejected
			}
			return allowAllCb(ctx, socketPath)
		},
	}, nil)

	return l, client, func() {
		cleanup()
		l.Close()
	}
}

func TestLocalUnixForwardingWorks(t *testing.T) {
	t.Parallel()

	l, client, cleanup := newTestSessionWithUnixForwarding(t, true)
	defer cleanup()

	conn, err := client.Dial("unix", l.Addr().String())
	if err != nil {
		t.Fatalf("Error connecting to %v: %v", l.Addr().String(), err)
	}
	result, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, sampleServerResponse) {
		t.Fatalf("result = %#v; want %#v", result, sampleServerResponse)
	}
}

func TestLocalUnixForwardingRespectsCallback(t *testing.T) {
	t.Parallel()

	l, client, cleanup := newTestSessionWithUnixForwarding(t, false)
	defer cleanup()

	_, err := client.Dial("unix", l.Addr().String())
	if err == nil {
		t.Fatalf("Expected error connecting to %v but it succeeded", l.Addr().String())
	}
	if !strings.Contains(err.Error(), "unix forwarding is disabled") {
		t.Fatalf("Expected permission error but got %#v", err)
	}
}

func TestReverseUnixForwardingWorks(t *testing.T) {
	t.Parallel()

	remoteSocketPath := filepath.Join(tempDirUnixSocket(t), "remote.sock")

	allowAllCb := NewReverseUnixForwardingCallback(UnixForwardingOptions{
		AllowAll:   true,
		BindUnlink: true,
	})
	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {},
		ReverseUnixForwardingCallback: func(ctx Context, socketPath string) (net.Listener, error) {
			if socketPath != remoteSocketPath {
				panic("unexpected socket path: " + socketPath)
			}
			return allowAllCb(ctx, socketPath)
		},
	}, nil)
	defer cleanup()

	l, err := client.ListenUnix(remoteSocketPath)
	if err != nil {
		t.Fatalf("failed to listen on a unix socket over SSH %q: %v", remoteSocketPath, err)
	}
	defer l.Close()
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		conn.Write(sampleServerResponse)
		conn.Close()
	}()

	// Dial the listener that should've been created by the server.
	conn, err := net.Dial("unix", remoteSocketPath)
	if err != nil {
		t.Fatalf("Error connecting to %v: %v", remoteSocketPath, err)
	}
	result, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, sampleServerResponse) {
		t.Fatalf("result = %#v; want %#v", result, sampleServerResponse)
	}

	// Close the listener and make sure that the Unix socket is gone.
	err = l.Close()
	if err != nil {
		t.Fatalf("failed to close remote listener: %v", err)
	}
	_, err = os.Stat(remoteSocketPath)
	if err == nil {
		t.Fatal("expected remote socket to be removed after close")
	}
}

func TestValidateSocketPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		path      string
		opts      UnixForwardingOptions
		wantErr   bool
		wantClean string    // expected cleaned path on success
		errSubstr string    // substring expected in error message
		wantType  error     // expected error type (ErrRejected)
	}{
		// Basic validation (applies to all modes).
		{
			name:      "absolute path accepted with AllowAll",
			path:      "/tmp/test.sock",
			opts:      UnixForwardingOptions{AllowAll: true},
			wantClean: "/tmp/test.sock",
		},
		{
			name:      "relative path rejected",
			path:      "relative/path.sock",
			opts:      UnixForwardingOptions{AllowAll: true},
			wantErr:   true,
			errSubstr: "must be absolute",
			wantType:  ErrRejected,
		},
		{
			name:      "dot-relative path rejected",
			path:      "./local.sock",
			opts:      UnixForwardingOptions{AllowAll: true},
			wantErr:   true,
			errSubstr: "must be absolute",
			wantType:  ErrRejected,
		},
		{
			name:      "empty path rejected",
			path:      "",
			opts:      UnixForwardingOptions{AllowAll: true},
			wantErr:   true,
			errSubstr: "must be absolute",
			wantType:  ErrRejected,
		},
		{
			name:      "path with dot-dot cleaned and accepted",
			path:      "/tmp/foo/../bar/test.sock",
			opts:      UnixForwardingOptions{AllowAll: true},
			wantClean: "/tmp/bar/test.sock",
		},
		{
			name:      "path with double slashes cleaned",
			path:      "/tmp//foo//test.sock",
			opts:      UnixForwardingOptions{AllowAll: true},
			wantClean: "/tmp/foo/test.sock",
		},
		{
			name:      "path with trailing slash cleaned",
			path:      "/tmp/test.sock/",
			opts:      UnixForwardingOptions{AllowAll: true},
			wantClean: "/tmp/test.sock",
		},
		{
			name:      "path at sun_path limit rejected",
			path:      "/" + strings.Repeat("a", maxSunPathLen-1),
			opts:      UnixForwardingOptions{AllowAll: true},
			wantErr:   true,
			errSubstr: "too long",
			wantType:  ErrRejected,
		},
		{
			name:      "path just under sun_path limit accepted",
			path:      "/" + strings.Repeat("a", maxSunPathLen-3),
			opts:      UnixForwardingOptions{AllowAll: true},
			wantClean: "/" + strings.Repeat("a", maxSunPathLen-3),
		},

		// AllowedDirectories tests.
		{
			name:      "path in allowed directory accepted",
			path:      "/tmp/ssh/agent.sock",
			opts:      UnixForwardingOptions{AllowedDirectories: []string{"/tmp"}},
			wantClean: "/tmp/ssh/agent.sock",
		},
		{
			name:      "path in second allowed directory accepted",
			path:      "/home/user/.ssh/agent.sock",
			opts:      UnixForwardingOptions{AllowedDirectories: []string{"/tmp", "/home/user"}},
			wantClean: "/home/user/.ssh/agent.sock",
		},
		{
			name:      "path outside allowed directories rejected",
			path:      "/var/run/docker.sock",
			opts:      UnixForwardingOptions{AllowedDirectories: []string{"/tmp", "/home/user"}},
			wantErr:   true,
			errSubstr: "not in an allowed directory",
			wantType:  ErrRejected,
		},
		{
			name:      "empty allowed directories rejects all",
			path:      "/tmp/test.sock",
			opts:      UnixForwardingOptions{AllowedDirectories: []string{}},
			wantErr:   true,
			errSubstr: "not in an allowed directory",
			wantType:  ErrRejected,
		},
		{
			name:      "nil allowed directories rejects all",
			path:      "/tmp/test.sock",
			opts:      UnixForwardingOptions{},
			wantErr:   true,
			errSubstr: "not in an allowed directory",
			wantType:  ErrRejected,
		},
		{
			name:      "allowed directory itself is not a valid socket path",
			path:      "/tmp",
			opts:      UnixForwardingOptions{AllowedDirectories: []string{"/tmp"}},
			wantErr:   true,
			errSubstr: "not in an allowed directory",
			wantType:  ErrRejected,
		},
		{
			name:      "allowed directory with trailing slash works",
			path:      "/tmp/test.sock",
			opts:      UnixForwardingOptions{AllowedDirectories: []string{"/tmp/"}},
			wantClean: "/tmp/test.sock",
		},
		{
			name:      "dot-dot traversal out of allowed directory rejected",
			path:      "/tmp/../var/run/docker.sock",
			opts:      UnixForwardingOptions{AllowedDirectories: []string{"/tmp"}},
			wantErr:   true,
			errSubstr: "not in an allowed directory",
			wantType:  ErrRejected,
		},
		{
			name:      "dot-dot traversal staying in allowed directory accepted",
			path:      "/tmp/foo/../bar/test.sock",
			opts:      UnixForwardingOptions{AllowedDirectories: []string{"/tmp"}},
			wantClean: "/tmp/bar/test.sock",
		},
		{
			name:      "allowed directory prefix attack rejected",
			path:      "/tmpevil/test.sock",
			opts:      UnixForwardingOptions{AllowedDirectories: []string{"/tmp"}},
			wantErr:   true,
			errSubstr: "not in an allowed directory",
			wantType:  ErrRejected,
		},

		// DeniedPrefixes tests.
		{
			name:      "path in denied prefix rejected",
			path:      "/run/user/1000/systemd/private.sock",
			opts:      UnixForwardingOptions{AllowedDirectories: []string{"/run/user/1000"}, DeniedPrefixes: []string{"/run/user/1000/systemd"}},
			wantErr:   true,
			errSubstr: "is denied",
			wantType:  ErrRejected,
		},
		{
			name:      "exact denied path rejected",
			path:      "/var/run/docker.sock",
			opts:      UnixForwardingOptions{AllowedDirectories: []string{"/var/run"}, DeniedPrefixes: []string{"/var/run/docker.sock"}},
			wantErr:   true,
			errSubstr: "is denied",
			wantType:  ErrRejected,
		},
		{
			name:      "path not matching denied prefix accepted",
			path:      "/run/user/1000/podman/podman.sock",
			opts:      UnixForwardingOptions{AllowedDirectories: []string{"/run/user/1000"}, DeniedPrefixes: []string{"/run/user/1000/systemd"}},
			wantClean: "/run/user/1000/podman/podman.sock",
		},
		{
			name:      "denied prefix does not match partial directory names",
			path:      "/run/user/1000/systemd-resolved/test.sock",
			opts:      UnixForwardingOptions{AllowedDirectories: []string{"/run/user/1000"}, DeniedPrefixes: []string{"/run/user/1000/systemd"}},
			wantClean: "/run/user/1000/systemd-resolved/test.sock",
		},

		// AllowAll overrides AllowedDirectories/DeniedPrefixes.
		{
			name:      "AllowAll ignores AllowedDirectories",
			path:      "/var/run/docker.sock",
			opts:      UnixForwardingOptions{AllowAll: true, AllowedDirectories: []string{"/tmp"}},
			wantClean: "/var/run/docker.sock",
		},
		{
			name:      "AllowAll ignores DeniedPrefixes",
			path:      "/run/user/1000/systemd/private.sock",
			opts:      UnixForwardingOptions{AllowAll: true, DeniedPrefixes: []string{"/run/user/1000/systemd"}},
			wantClean: "/run/user/1000/systemd/private.sock",
		},

		// Real-world socket paths.
		{
			name:      "podman socket path",
			path:      "/run/user/1000/podman/podman.sock",
			opts:      UnixForwardingOptions{AllowedDirectories: []string{"/run/user/1000"}},
			wantClean: "/run/user/1000/podman/podman.sock",
		},
		{
			name:      "gpg agent socket",
			path:      "/home/user/.gnupg/S.gpg-agent",
			opts:      UnixForwardingOptions{AllowedDirectories: []string{"/home/user"}},
			wantClean: "/home/user/.gnupg/S.gpg-agent",
		},
		{
			name:      "gpg agent socket systemd path",
			path:      "/run/user/1000/gnupg/S.gpg-agent",
			opts:      UnixForwardingOptions{AllowedDirectories: []string{"/run/user/1000"}},
			wantClean: "/run/user/1000/gnupg/S.gpg-agent",
		},
		{
			name:      "vscode remote socket",
			path:      "/tmp/code-d0fd2e91-ed82-46dd-8394-87ac5cde31c3.sock",
			opts:      UnixForwardingOptions{AllowedDirectories: []string{"/tmp"}},
			wantClean: "/tmp/code-d0fd2e91-ed82-46dd-8394-87ac5cde31c3.sock",
		},
		{
			name:      "ssh agent socket",
			path:      "/tmp/ssh-XXXXXXXXXX/agent.12345",
			opts:      UnixForwardingOptions{AllowedDirectories: []string{"/tmp"}},
			wantClean: "/tmp/ssh-XXXXXXXXXX/agent.12345",
		},
		{
			name:      "docker socket denied even when /var/run allowed",
			path:      "/var/run/docker.sock",
			opts:      UnixForwardingOptions{AllowedDirectories: []string{"/var/run"}, DeniedPrefixes: []string{"/var/run/docker.sock"}},
			wantErr:   true,
			errSubstr: "is denied",
			wantType:  ErrRejected,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cleaned, err := validateSocketPath(tt.path, tt.opts)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("validateSocketPath(%q) = %q, nil; want error containing %q", tt.path, cleaned, tt.errSubstr)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("validateSocketPath(%q) error = %q; want substring %q", tt.path, err.Error(), tt.errSubstr)
				}
				if tt.wantType != nil && !errors.Is(err, tt.wantType) {
					t.Fatalf("validateSocketPath(%q) error type = %T; want errors.Is(%v)", tt.path, err, tt.wantType)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateSocketPath(%q) = error %q; want %q", tt.path, err, tt.wantClean)
			}
			if cleaned != tt.wantClean {
				t.Fatalf("validateSocketPath(%q) = %q; want %q", tt.path, cleaned, tt.wantClean)
			}
		})
	}
}

func TestRejectedMessage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "bare ErrRejected gives generic message",
			err:  ErrRejected,
			want: "unix forwarding is disabled",
		},
		{
			name: "rejectionError gives descriptive message",
			err:  &rejectionError{reason: "socket path must be absolute"},
			want: "socket path must be absolute",
		},
		{
			name: "wrapped ErrRejected gives wrapper message",
			err:  fmt.Errorf("custom reason: %w", ErrRejected),
			want: "custom reason: ssh: rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := rejectedMessage(tt.err)
			if got != tt.want {
				t.Fatalf("rejectedMessage(%v) = %q; want %q", tt.err, got, tt.want)
			}
		})
	}
}

func TestUserSocketDirectories(t *testing.T) {
	t.Parallel()

	dirs := UserSocketDirectories("/home/testuser", "1000")
	want := []string{"/home/testuser", "/tmp", "/run/user/1000"}

	if len(dirs) != len(want) {
		t.Fatalf("UserSocketDirectories returned %d dirs; want %d", len(dirs), len(want))
	}
	for i, d := range dirs {
		if d != want[i] {
			t.Fatalf("UserSocketDirectories()[%d] = %q; want %q", i, d, want[i])
		}
	}
}

func TestNewLocalUnixForwardingCallbackValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		opts      UnixForwardingOptions
		path      string
		wantErr   bool
		errSubstr string
	}{
		{
			name: "AllowAll accepts any absolute path",
			opts: UnixForwardingOptions{AllowAll: true},
			path: "/var/run/docker.sock",
		},
		{
			name:      "AllowAll rejects relative path",
			opts:      UnixForwardingOptions{AllowAll: true},
			path:      "relative.sock",
			wantErr:   true,
			errSubstr: "must be absolute",
		},
		{
			name:      "restricted rejects path outside allowed dirs",
			opts:      UnixForwardingOptions{AllowedDirectories: []string{"/tmp"}},
			path:      "/var/run/docker.sock",
			wantErr:   true,
			errSubstr: "not in an allowed directory",
		},
		{
			name: "restricted accepts path in allowed dir",
			opts: UnixForwardingOptions{AllowedDirectories: []string{"/tmp"}},
			path: "/tmp/test.sock",
		},
		{
			name: "PathValidator is called and can reject",
			opts: UnixForwardingOptions{
				AllowAll: true,
				PathValidator: func(_ Context, _ string) error {
					return &rejectionError{reason: "custom validator rejected"}
				},
			},
			path:      "/tmp/test.sock",
			wantErr:   true,
			errSubstr: "custom validator rejected",
		},
		{
			name: "PathValidator receives cleaned path",
			opts: UnixForwardingOptions{
				AllowAll: true,
				PathValidator: func(_ Context, path string) error {
					if path != "/tmp/test.sock" {
						return fmt.Errorf("expected /tmp/test.sock, got %s", path)
					}
					return nil
				},
			},
			path: "/tmp/foo/../test.sock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := newContext(nil)
			defer cancel()

			cb := NewLocalUnixForwardingCallback(tt.opts)
			// The callback tries to dial the socket, which will fail for
			// non-existent paths. We only care about the validation errors
			// (which wrap ErrRejected), not dial errors.
			_, err := cb(ctx, tt.path)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("error = %q; want substring %q", err.Error(), tt.errSubstr)
				}
				if !errors.Is(err, ErrRejected) {
					t.Fatalf("expected ErrRejected, got %T: %v", err, err)
				}
				return
			}
			// For valid paths, the error should either be nil (socket
			// exists) or a dial error (socket doesn't exist), but NOT
			// a validation/rejection error.
			if err != nil && errors.Is(err, ErrRejected) {
				t.Fatalf("unexpected rejection error: %v", err)
			}
		})
	}
}

func TestNewReverseUnixForwardingCallbackValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		opts      UnixForwardingOptions
		path      string
		wantErr   bool
		errSubstr string
	}{
		{
			name:      "rejects relative path",
			opts:      UnixForwardingOptions{AllowAll: true},
			path:      "relative.sock",
			wantErr:   true,
			errSubstr: "must be absolute",
		},
		{
			name:      "rejects path outside allowed dirs",
			opts:      UnixForwardingOptions{AllowedDirectories: []string{"/tmp"}},
			path:      "/var/run/test.sock",
			wantErr:   true,
			errSubstr: "not in an allowed directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := newContext(nil)
			defer cancel()

			cb := NewReverseUnixForwardingCallback(tt.opts)
			_, err := cb(ctx, tt.path)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("error = %q; want substring %q", err.Error(), tt.errSubstr)
				}
				if !errors.Is(err, ErrRejected) {
					t.Fatalf("expected ErrRejected, got %T: %v", err, err)
				}
				return
			}
			if err != nil && errors.Is(err, ErrRejected) {
				t.Fatalf("unexpected rejection error: %v", err)
			}
		})
	}
}

func TestNewReverseUnixForwardingCallbackBindUnlink(t *testing.T) {
	t.Parallel()

	dir := tempDirUnixSocket(t)
	sockPath := filepath.Join(dir, "test.sock")

	// Create an existing socket. Keep the listener open so the socket
	// file persists (Go's UnixListener.Close removes the file).
	oldLn, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to create socket: %v", err)
	}
	defer oldLn.Close() //nolint:errcheck

	// Without BindUnlink, listening should fail because socket exists.
	cbNoUnlink := NewReverseUnixForwardingCallback(UnixForwardingOptions{
		AllowAll: true,
	})
	_, err = cbNoUnlink(nil, sockPath)
	if err == nil {
		t.Fatal("expected listen to fail on existing socket without BindUnlink")
	}

	// With BindUnlink, the old socket is removed and we can listen.
	cbUnlink := NewReverseUnixForwardingCallback(UnixForwardingOptions{
		AllowAll:   true,
		BindUnlink: true,
	})
	newLn, err := cbUnlink(nil, sockPath)
	if err != nil {
		t.Fatalf("expected listen to succeed with BindUnlink, got: %v", err)
	}
	_ = newLn.Close()
}

func TestNewReverseUnixForwardingCallbackBindUnlinkSkipsNonSocket(t *testing.T) {
	t.Parallel()

	dir := tempDirUnixSocket(t)
	filePath := filepath.Join(dir, "regular.file")

	// Create a regular file at the path.
	if err := os.WriteFile(filePath, []byte("data"), 0600); err != nil {
		t.Fatalf("failed to create regular file: %v", err)
	}

	// BindUnlink should NOT remove regular files. Listen should fail.
	cb := NewReverseUnixForwardingCallback(UnixForwardingOptions{
		AllowAll:   true,
		BindUnlink: true,
	})
	_, err := cb(nil, filePath)
	if err == nil {
		t.Fatal("expected listen to fail on regular file even with BindUnlink")
	}

	// Regular file should still exist.
	if _, err := os.Stat(filePath); err != nil {
		t.Fatalf("regular file should not have been deleted: %v", err)
	}
}

func TestNewReverseUnixForwardingCallbackSocketPermissions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		mask     *os.FileMode
		wantPerm os.FileMode
	}{
		{name: "default mask 0177 gives mode 0600", mask: nil, wantPerm: 0600},
		{name: "custom mask 0117 gives mode 0660", mask: fileMode(0117), wantPerm: 0660},
		{name: "zero mask gives mode 0666", mask: fileMode(0), wantPerm: 0666},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Use a short /tmp path to stay under sun_path limits
			// even when the test framework creates long temp paths.
			dir, err := os.MkdirTemp("/tmp", "ssh-perm-")
			if err != nil {
				t.Fatalf("create temp dir: %v", err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			sockPath := filepath.Join(dir, fmt.Sprintf("p%d.s", i))

			cb := NewReverseUnixForwardingCallback(UnixForwardingOptions{
				AllowAll: true,
				BindMask: tt.mask,
			})
			ln, err := cb(nil, sockPath)
			if err != nil {
				t.Fatalf("failed to listen: %v", err)
			}
			defer ln.Close() //nolint:errcheck

			info, err := os.Stat(sockPath)
			if err != nil {
				t.Fatalf("failed to stat socket: %v", err)
			}
			perm := info.Mode().Perm()
			if perm != tt.wantPerm {
				t.Fatalf("socket permissions = %04o; want %04o", perm, tt.wantPerm)
			}
		})
	}
}

func fileMode(m os.FileMode) *os.FileMode { return &m }

func TestReverseUnixForwardingRespectsCallback(t *testing.T) {
	t.Parallel()

	remoteSocketPath := filepath.Join(tempDirUnixSocket(t), "remote.sock")

	var called int64
	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {},
		ReverseUnixForwardingCallback: func(ctx Context, socketPath string) (net.Listener, error) {
			atomic.AddInt64(&called, 1)
			if socketPath != remoteSocketPath {
				panic("unexpected socket path: " + socketPath)
			}
			return nil, ErrRejected
		},
	}, nil)
	defer cleanup()

	_, err := client.ListenUnix(remoteSocketPath)
	if err == nil {
		t.Fatalf("Expected error listening on %q but it succeeded", remoteSocketPath)
	}

	if atomic.LoadInt64(&called) != 1 {
		t.Fatalf("Expected callback to be called once but it was called %d times", called)
	}
}
