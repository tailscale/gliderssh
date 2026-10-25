package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

func (srv *Server) serveOnce(l net.Listener) error {
	srv.ensureHandlers()
	if err := srv.ensureHostSigner(); err != nil {
		return err
	}
	conn, e := l.Accept()
	if e != nil {
		return e
	}
	srv.ChannelHandlers = map[string]ChannelHandler{
		"session":                        DefaultSessionHandler,
		"direct-tcpip":                   DirectTCPIPHandler,
		"direct-streamlocal@openssh.com": DirectStreamLocalHandler,
	}

	forwardedTCPHandler := &ForwardedTCPHandler{}
	forwardedUnixHandler := &ForwardedUnixHandler{}
	srv.RequestHandlers = map[string]RequestHandler{
		"tcpip-forward":                          forwardedTCPHandler.HandleSSHRequest,
		"cancel-tcpip-forward":                   forwardedTCPHandler.HandleSSHRequest,
		"streamlocal-forward@openssh.com":        forwardedUnixHandler.HandleSSHRequest,
		"cancel-streamlocal-forward@openssh.com": forwardedUnixHandler.HandleSSHRequest,
	}

	srv.HandleConn(conn)
	return nil
}

func newLocalTCPListener() net.Listener {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if l, err = net.Listen("tcp6", "[::1]:0"); err != nil {
			panic(fmt.Sprintf("failed to listen on a port: %v", err))
		}
	}
	return l
}

func newClientSession(t *testing.T, addr string, config *gossh.ClientConfig) (*gossh.Session, *gossh.Client, func()) {
	if config == nil {
		config = &gossh.ClientConfig{
			User: "testuser",
			Auth: []gossh.AuthMethod{
				gossh.Password("testpass"),
			},
		}
	}
	if config.HostKeyCallback == nil {
		config.HostKeyCallback = gossh.InsecureIgnoreHostKey()
	}
	client, err := gossh.Dial("tcp", addr, config)
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	return session, client, func() {
		session.Close()
		client.Close()
	}
}

func newTestSession(t *testing.T, srv *Server, cfg *gossh.ClientConfig) (*gossh.Session, *gossh.Client, func()) {
	l := newLocalTCPListener()
	go srv.serveOnce(l)
	return newClientSession(t, l.Addr().String(), cfg)
}

func TestStdout(t *testing.T) {
	t.Parallel()
	testBytes := []byte("Hello world\n")
	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {
			s.Write(testBytes)
		},
	}, nil)
	defer cleanup()
	var stdout bytes.Buffer
	session.Stdout = &stdout
	if err := session.Run(""); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stdout.Bytes(), testBytes) {
		t.Fatalf("stdout = %#v; want %#v", stdout.Bytes(), testBytes)
	}
}

func TestStderr(t *testing.T) {
	t.Parallel()
	testBytes := []byte("Hello world\n")
	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {
			s.Stderr().Write(testBytes)
		},
	}, nil)
	defer cleanup()
	var stderr bytes.Buffer
	session.Stderr = &stderr
	if err := session.Run(""); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stderr.Bytes(), testBytes) {
		t.Fatalf("stderr = %#v; want %#v", stderr.Bytes(), testBytes)
	}
}

func TestStdin(t *testing.T) {
	t.Parallel()
	testBytes := []byte("Hello world\n")
	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {
			io.Copy(s, s) // stdin back into stdout
		},
	}, nil)
	defer cleanup()
	var stdout bytes.Buffer
	session.Stdout = &stdout
	session.Stdin = bytes.NewBuffer(testBytes)
	if err := session.Run(""); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stdout.Bytes(), testBytes) {
		t.Fatalf("stdout = %#v; want %#v given stdin = %#v", stdout.Bytes(), testBytes, testBytes)
	}
}

func TestUser(t *testing.T) {
	t.Parallel()
	testUser := []byte("progrium")
	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {
			io.WriteString(s, s.User())
		},
	}, &gossh.ClientConfig{
		User: string(testUser),
	})
	defer cleanup()
	var stdout bytes.Buffer
	session.Stdout = &stdout
	if err := session.Run(""); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stdout.Bytes(), testUser) {
		t.Fatalf("stdout = %#v; want %#v given user = %#v", stdout.Bytes(), testUser, string(testUser))
	}
}

func TestDefaultExitStatusZero(t *testing.T) {
	t.Parallel()
	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {
			// noop
		},
	}, nil)
	defer cleanup()
	err := session.Run("")
	if err != nil {
		t.Fatalf("expected nil but got %v", err)
	}
}

func TestExplicitExitStatusZero(t *testing.T) {
	t.Parallel()
	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {
			s.Exit(0)
		},
	}, nil)
	defer cleanup()
	err := session.Run("")
	if err != nil {
		t.Fatalf("expected nil but got %v", err)
	}
}

func TestExitStatusNonZero(t *testing.T) {
	t.Parallel()
	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {
			s.Exit(1)
		},
	}, nil)
	defer cleanup()
	err := session.Run("")
	e, ok := err.(*gossh.ExitError)
	if !ok {
		t.Fatalf("expected ExitError but got %T", err)
	}
	if e.ExitStatus() != 1 {
		t.Fatalf("exit-status = %#v; want %#v", e.ExitStatus(), 1)
	}
}

func TestPty(t *testing.T) {
	t.Parallel()
	term := "xterm"
	winWidth := 40
	winHeight := 80
	done := make(chan bool)
	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {
			ptyReq, _, isPty := s.Pty()
			if !isPty {
				t.Fatalf("expected pty but none requested")
			}
			if ptyReq.Term != term {
				t.Fatalf("expected term %#v but got %#v", term, ptyReq.Term)
			}
			if ptyReq.Window.Width != winWidth {
				t.Fatalf("expected window width %#v but got %#v", winWidth, ptyReq.Window.Width)
			}
			if ptyReq.Window.Height != winHeight {
				t.Fatalf("expected window height %#v but got %#v", winHeight, ptyReq.Window.Height)
			}
			close(done)
		},
	}, nil)
	defer cleanup()
	if err := session.RequestPty(term, winHeight, winWidth, gossh.TerminalModes{}); err != nil {
		t.Fatalf("expected nil but got %v", err)
	}
	if err := session.Shell(); err != nil {
		t.Fatalf("expected nil but got %v", err)
	}
	<-done
}

func TestPtyResize(t *testing.T) {
	t.Parallel()
	winch0 := Window{Width: 40, Height: 80}
	winch1 := Window{Width: 80, Height: 160, WidthPixels: 640, HeightPixels: 1280}
	winch2 := Window{Width: 20, Height: 40, WidthPixels: 160, HeightPixels: 320}
	winches := make(chan Window)
	done := make(chan bool)
	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {
			ptyReq, winCh, isPty := s.Pty()
			if !isPty {
				t.Fatalf("expected pty but none requested")
			}
			// RequestPty computes pixel dimensions from char dimensions,
			// so we only check Width/Height for the initial pty request.
			if ptyReq.Window.Width != winch0.Width || ptyReq.Window.Height != winch0.Height {
				t.Fatalf("expected window size %dx%d but got %dx%d",
					winch0.Width, winch0.Height,
					ptyReq.Window.Width, ptyReq.Window.Height)
			}
			if ptyReq.Window.WidthPixels == 0 || ptyReq.Window.HeightPixels == 0 {
				t.Fatalf("expected non-zero pixel dimensions in pty request, got %#v", ptyReq.Window)
			}
			for win := range winCh {
				winches <- win
			}
			close(done)
		},
	}, nil)
	defer cleanup()
	// winch0
	if err := session.RequestPty("xterm", winch0.Height, winch0.Width, gossh.TerminalModes{}); err != nil {
		t.Fatalf("expected nil but got %v", err)
	}
	if err := session.Shell(); err != nil {
		t.Fatalf("expected nil but got %v", err)
	}
	gotWinch := <-winches
	if gotWinch.Width != winch0.Width || gotWinch.Height != winch0.Height {
		t.Fatalf("expected window size %dx%d but got %dx%d",
			winch0.Width, winch0.Height,
			gotWinch.Width, gotWinch.Height)
	}
	if gotWinch.WidthPixels == 0 || gotWinch.HeightPixels == 0 {
		t.Fatalf("expected non-zero pixel dimensions, got %#v", gotWinch)
	}
	// winch1 — window-change sends all 4 fields per RFC 4254 section 6.7
	winchMsg := struct{ W, H, Wpx, Hpx uint32 }{
		uint32(winch1.Width), uint32(winch1.Height),
		uint32(winch1.WidthPixels), uint32(winch1.HeightPixels),
	}
	ok, err := session.SendRequest("window-change", true, gossh.Marshal(&winchMsg))
	if err == nil && !ok {
		t.Fatalf("unexpected error or bad reply on send request")
	}
	gotWinch = <-winches
	if gotWinch != winch1 {
		t.Fatalf("expected window %#v but got %#v", winch1, gotWinch)
	}
	// winch2
	winchMsg = struct{ W, H, Wpx, Hpx uint32 }{
		uint32(winch2.Width), uint32(winch2.Height),
		uint32(winch2.WidthPixels), uint32(winch2.HeightPixels),
	}
	ok, err = session.SendRequest("window-change", true, gossh.Marshal(&winchMsg))
	if err == nil && !ok {
		t.Fatalf("unexpected error or bad reply on send request")
	}
	gotWinch = <-winches
	if gotWinch != winch2 {
		t.Fatalf("expected window %#v but got %#v", winch2, gotWinch)
	}
	session.Close()
	<-done
}

func TestSignals(t *testing.T) {
	t.Parallel()

	// errChan lets us get errors back from the session
	errChan := make(chan error, 5)

	// doneChan lets us specify that we should exit.
	doneChan := make(chan any)

	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {
			// We need to use a buffered channel here, otherwise it's possible for the
			// second call to Signal to get discarded.
			signals := make(chan Signal, 2)
			s.Signals(signals)

			select {
			case sig := <-signals:
				if sig != SIGINT {
					errChan <- fmt.Errorf("expected signal %v but got %v", SIGINT, sig)
					return
				}
			case <-doneChan:
				errChan <- errors.New("unexpected done")
				return
			}

			select {
			case sig := <-signals:
				if sig != SIGKILL {
					errChan <- fmt.Errorf("expected signal %v but got %v", SIGKILL, sig)
					return
				}
			case <-doneChan:
				errChan <- errors.New("unexpected done")
				return
			}
		},
	}, nil)
	defer cleanup()

	go func() {
		session.Signal(gossh.SIGINT)
		session.Signal(gossh.SIGKILL)
	}()

	go func() {
		errChan <- session.Run("")
	}()

	err := <-errChan
	close(doneChan)

	if err != nil {
		t.Fatalf("expected nil but got %v", err)
	}
}

func TestBreakWithChanRegistered(t *testing.T) {
	t.Parallel()

	// errChan lets us get errors back from the session
	errChan := make(chan error, 5)

	// doneChan lets us specify that we should exit.
	doneChan := make(chan any)

	breakChan := make(chan bool)

	readyToReceiveBreak := make(chan bool)

	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {
			s.Break(breakChan) // register a break channel with the session
			readyToReceiveBreak <- true

			select {
			case <-breakChan:
				io.WriteString(s, "break")
			case <-doneChan:
				errChan <- errors.New("unexpected done")
				return
			}
		},
	}, nil)
	defer cleanup()
	var stdout bytes.Buffer
	session.Stdout = &stdout
	go func() {
		errChan <- session.Run("")
	}()

	<-readyToReceiveBreak
	ok, err := session.SendRequest("break", true, nil)
	if err != nil {
		t.Fatalf("expected nil but got %v", err)
	}
	if ok != true {
		t.Fatalf("expected true but got %v", ok)
	}

	err = <-errChan
	close(doneChan)

	if err != nil {
		t.Fatalf("expected nil but got %v", err)
	}
	if !bytes.Equal(stdout.Bytes(), []byte("break")) {
		t.Fatalf("stdout = %#v, expected 'break'", stdout.Bytes())
	}
}

func TestBreakWithoutChanRegistered(t *testing.T) {
	t.Parallel()

	// errChan lets us get errors back from the session
	errChan := make(chan error, 5)

	// doneChan lets us specify that we should exit.
	doneChan := make(chan any)

	waitUntilAfterBreakSent := make(chan bool)

	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {
			<-waitUntilAfterBreakSent
		},
	}, nil)
	defer cleanup()
	var stdout bytes.Buffer
	session.Stdout = &stdout
	go func() {
		errChan <- session.Run("")
	}()

	ok, err := session.SendRequest("break", true, nil)
	if err != nil {
		t.Fatalf("expected nil but got %v", err)
	}
	if ok != false {
		t.Fatalf("expected false but got %v", ok)
	}
	waitUntilAfterBreakSent <- true

	err = <-errChan
	close(doneChan)
	if err != nil {
		t.Fatalf("expected nil but got %v", err)
	}
}

// sendRequestWithTimeout sends a global-free session request and waits
// for its reply, failing the test if the server does not answer in
// time. It guards against regressions that park the session request
// loop, which would otherwise hang the test until the global timeout.
func sendRequestWithTimeout(t *testing.T, session *gossh.Session, name string, payload []byte, timeout time.Duration) (bool, error) {
	t.Helper()
	type result struct {
		ok  bool
		err error
	}
	ch := make(chan result, 1)
	go func() {
		ok, err := session.SendRequest(name, true, payload)
		ch <- result{ok, err}
	}()
	select {
	case r := <-ch:
		return r.ok, r.err
	case <-time.After(timeout):
		return false, fmt.Errorf("timed out waiting for %q reply", name)
	}
}

// TestWindowChangeWhenConsumerNotDraining verifies that window-change
// requests never park the session request loop, even when the session
// handler never reads the window size channel. Parking the loop would
// leak one goroutine and its session state per session channel, even
// after the client disconnects.
func TestWindowChangeWhenConsumerNotDraining(t *testing.T) {
	t.Parallel()

	handlerDone := make(chan bool)
	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {
			s.Pty() // accept the pty, but never drain the window channel
			<-handlerDone
		},
	}, nil)
	defer cleanup()

	if err := session.RequestPty("xterm", 80, 40, gossh.TerminalModes{}); err != nil {
		t.Fatalf("expected nil but got %v", err)
	}
	if err := session.Shell(); err != nil {
		t.Fatalf("expected nil but got %v", err)
	}

	// The window channel is buffered with capacity one and already
	// holds the initial pty window size, so this first request must be
	// answered even though no consumer is reading anything.
	winchMsg := struct{ W, H, Wpx, Hpx uint32 }{800, 600, 6400, 4800}
	ok, err := sendRequestWithTimeout(t, session, "window-change", gossh.Marshal(&winchMsg), 10*time.Second)
	if err != nil {
		t.Fatalf("expected nil but got %v", err)
	}
	if !ok {
		t.Fatalf("expected true but got %v", ok)
	}

	// A burst of window-changes must not wedge the request loop either.
	for i := 0; i < 50; i++ {
		winchMsg = struct{ W, H, Wpx, Hpx uint32 }{uint32(100 + i), 200, 0, 0}
		if _, err := session.SendRequest("window-change", false, gossh.Marshal(&winchMsg)); err != nil {
			t.Fatalf("expected nil but got %v", err)
		}
	}

	// The request loop must still be able to process further requests.
	winchMsg = struct{ W, H, Wpx, Hpx uint32 }{900, 700, 7200, 5600}
	ok, err = sendRequestWithTimeout(t, session, "window-change", gossh.Marshal(&winchMsg), 10*time.Second)
	if err != nil {
		t.Fatalf("expected nil but got %v", err)
	}
	if !ok {
		t.Fatalf("expected true but got %v", ok)
	}

	close(handlerDone)
}

// TestBreakWhenConsumerNotDraining verifies that break requests do not
// park the session request loop when the registered break channel is
// never drained; the request is answered with a failure reply instead.
func TestBreakWhenConsumerNotDraining(t *testing.T) {
	t.Parallel()

	breakChan := make(chan bool) // unbuffered, never read
	readyToRegisterBreak := make(chan bool)
	handlerDone := make(chan bool)

	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {
			s.Break(breakChan)
			readyToRegisterBreak <- true
			<-handlerDone
		},
	}, nil)
	defer cleanup()

	var stdout bytes.Buffer
	session.Stdout = &stdout
	errChan := make(chan error, 1)
	go func() {
		errChan <- session.Run("")
	}()

	<-readyToRegisterBreak
	// Break requests must be answered (with ok=false, since the
	// consumer is not reading) instead of parking the request loop.
	for i := 0; i < 5; i++ {
		ok, err := sendRequestWithTimeout(t, session, "break", nil, 10*time.Second)
		if err != nil {
			t.Fatalf("expected nil but got %v", err)
		}
		if ok {
			t.Fatalf("expected false but got %v", ok)
		}
	}

	close(handlerDone)
	if err := <-errChan; err != nil {
		t.Fatalf("expected nil but got %v", err)
	}
}

// TestEnvironBounded verifies that a client cannot force unbounded
// memory growth by sending an endless stream of env requests: only the
// first maxEnvs variables are accepted, the rest are rejected.
func TestEnvironBounded(t *testing.T) {
	t.Parallel()

	envCh := make(chan []string, 1)
	handlerDone := make(chan bool)

	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {
			envCh <- s.Environ()
			<-handlerDone
		},
	}, nil)
	defer cleanup()

	for i := 0; i < maxEnvs+10; i++ {
		payload := gossh.Marshal(struct{ Key, Value string }{"KEY", fmt.Sprint(i)})
		ok, err := sendRequestWithTimeout(t, session, "env", payload, 10*time.Second)
		if err != nil {
			t.Fatalf("env %d: expected nil but got %v", i, err)
		}
		if i < maxEnvs && !ok {
			t.Fatalf("env %d: expected true but got %v", i, ok)
		}
		if i >= maxEnvs && ok {
			t.Fatalf("env %d: expected false but got %v", i, ok)
		}
	}

	if err := session.Shell(); err != nil {
		t.Fatalf("expected nil but got %v", err)
	}
	env := <-envCh
	if len(env) != maxEnvs {
		t.Fatalf("expected %d environment entries but got %d", maxEnvs, len(env))
	}

	close(handlerDone)
}
