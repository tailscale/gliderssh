package ssh

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestAddHostKey(t *testing.T) {
	s := Server{}
	signer, err := generateSigner()
	if err != nil {
		t.Fatal(err)
	}
	s.AddHostKey(signer)
	if len(s.HostSigners) != 1 {
		t.Fatal("Key was not properly added")
	}
	signer, err = generateSigner()
	if err != nil {
		t.Fatal(err)
	}
	s.AddHostKey(signer)
	if len(s.HostSigners) != 1 {
		t.Fatal("Key was not properly replaced")
	}
}

func TestServerShutdown(t *testing.T) {
	l := newLocalTCPListener()
	testBytes := []byte("Hello world\n")
	s := &Server{
		Handler: func(s Session) {
			s.Write(testBytes)
			time.Sleep(50 * time.Millisecond)
		},
	}
	go func() {
		err := s.Serve(l)
		if err != nil && err != ErrServerClosed {
			t.Error(err)
		}
	}()
	sessDone := make(chan struct{})
	sess, _, cleanup := newClientSession(t, l.Addr().String(), nil)
	go func() {
		defer cleanup()
		defer close(sessDone)
		var stdout bytes.Buffer
		sess.Stdout = &stdout
		if err := sess.Run(""); err != nil {
			t.Error(err)
			return
		}
		if !bytes.Equal(stdout.Bytes(), testBytes) {
			t.Errorf("expected = %s; got %s", testBytes, stdout.Bytes())
		}
	}()

	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		err := s.Shutdown(context.Background())
		if err != nil {
			t.Error(err)
		}
	}()

	timeout := time.After(2 * time.Second)
	select {
	case <-timeout:
		t.Fatal("timeout")
		return
	case <-srvDone:
		// TODO: add timeout for sessDone
		<-sessDone
		return
	}
}

func TestServerClose(t *testing.T) {
	l := newLocalTCPListener()
	s := &Server{
		Handler: func(s Session) {
			time.Sleep(5 * time.Second)
		},
	}
	go func() {
		err := s.Serve(l)
		if err != nil && err != ErrServerClosed {
			t.Error(err)
		}
	}()

	clientDoneChan := make(chan struct{})
	closeDoneChan := make(chan struct{})

	sess, _, cleanup := newClientSession(t, l.Addr().String(), nil)
	go func() {
		defer cleanup()
		defer close(clientDoneChan)
		<-closeDoneChan
		if err := sess.Run(""); err != nil && err != io.EOF {
			t.Error(err)
		}
	}()

	go func() {
		err := s.Close()
		if err != nil {
			t.Error(err)
		}
		close(closeDoneChan)
	}()

	timeout := time.After(100 * time.Millisecond)
	select {
	case <-timeout:
		t.Error("timeout")
		return
	case <-s.getDoneChan():
		<-clientDoneChan
		return
	}
}

func TestServerHandshakeTimeout(t *testing.T) {
	l := newLocalTCPListener()

	s := &Server{
		HandshakeTimeout: time.Millisecond,
	}
	go func() {
		if err := s.Serve(l); err != nil {
			t.Error(err)
		}
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	ch := make(chan struct{})
	go func() {
		defer close(ch)
		io.Copy(io.Discard, conn)
	}()

	select {
	case <-ch:
		return
	case <-time.After(time.Second):
		t.Fatal("client connection was not force-closed")
		return
	}
}

// TestServerConnHandshakeDeadlineRace checks that clearing the
// handshake deadline is safe while other goroutines call
// updateDeadline, which is what Read and Write do on every packet when
// IdleTimeout is set. It requires -race to detect the race, and fails
// if handshakeDeadline is a non-atomic *time.Time field.
func TestServerConnHandshakeDeadlineRace(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	deadline := time.Now().Add(time.Minute)
	conn := &serverConn{
		Conn:        c1,
		idleTimeout: time.Minute,
	}
	conn.handshakeDeadline.Store(&deadline)

	stop := make(chan struct{})
	var reads atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				// Read and Write call updateDeadline on every
				// packet once idleTimeout is set.
				conn.updateDeadline()
				reads.Add(1)
			}
		}
	}()

	// Store nil, as HandleConn does after the handshake, until
	// concurrent updateDeadline calls are under way.
	for reads.Load() < 100 {
		conn.handshakeDeadline.Store(nil)
	}
	close(stop)
	<-done
}

// TestServerHandshakeTimeoutClearedAfterHandshake checks that the
// handshake deadline does not apply after the handshake completes:
// with HandshakeTimeout set, a session whose handler runs longer than
// the grace period still completes. The host key is generated before
// the server is started so the handshake itself stays well inside the
// grace period.
func TestServerHandshakeTimeoutClearedAfterHandshake(t *testing.T) {
	signer, err := generateSigner()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		HandshakeTimeout: time.Second,
		IdleTimeout:      time.Minute,
		Handler: func(s Session) {
			time.Sleep(1500 * time.Millisecond)
		},
	}
	s.AddHostKey(signer)
	sess, _, cleanup := newTestSession(t, s, nil)
	defer cleanup()
	if err := sess.Run(""); err != nil {
		t.Fatalf("session run: %v", err)
	}
}
