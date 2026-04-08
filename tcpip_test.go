package ssh

import (
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

var sampleServerResponse = []byte("Hello world")

func sampleTCPSocketServer() net.Listener {
	l := newLocalTCPListener()

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

func newTestSessionWithForwarding(t *testing.T, forwardingEnabled bool) (net.Listener, *gossh.Client, func()) {
	l := sampleTCPSocketServer()

	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {},
		LocalPortForwardingCallback: func(ctx Context, destinationHost string, destinationPort uint32) bool {
			addr := net.JoinHostPort(destinationHost, strconv.FormatInt(int64(destinationPort), 10))
			if addr != l.Addr().String() {
				panic("unexpected destinationHost: " + addr)
			}
			return forwardingEnabled
		},
	}, nil)

	return l, client, func() {
		cleanup()
		l.Close()
	}
}

func TestLocalPortForwardingWorks(t *testing.T) {
	t.Parallel()

	l, client, cleanup := newTestSessionWithForwarding(t, true)
	defer cleanup()

	conn, err := client.Dial("tcp", l.Addr().String())
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

func TestLocalPortForwardingRespectsCallback(t *testing.T) {
	t.Parallel()

	l, client, cleanup := newTestSessionWithForwarding(t, false)
	defer cleanup()

	_, err := client.Dial("tcp", l.Addr().String())
	if err == nil {
		t.Fatalf("Expected error connecting to %v but it succeeded", l.Addr().String())
	}
	if !strings.Contains(err.Error(), "port forwarding is disabled") {
		t.Fatalf("Expected permission error but got %#v", err)
	}
}

func TestReverseTCPForwardingWorks(t *testing.T) {
	t.Parallel()

	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {},
		ReversePortForwardingCallback: func(ctx Context, bindHost string, bindPort uint32) bool {
			if bindHost != "127.0.0.1" {
				panic("unexpected bindHost: " + bindHost)
			}
			if bindPort != 0 {
				panic("unexpected bindPort: " + strconv.Itoa(int(bindPort)))
			}
			return true
		},
	}, nil)
	defer cleanup()

	l, err := client.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on a random TCP port over SSH: %v", err)
	}
	defer l.Close() //nolint:errcheck
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		_, _ = conn.Write(sampleServerResponse)
		_ = conn.Close()
	}()

	// Dial the listener that should've been created by the server.
	conn, err := net.Dial("tcp", l.Addr().String())
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

	// Close the listener and make sure that the port is no longer in use.
	err = l.Close()
	if err != nil {
		t.Fatalf("failed to close remote listener: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	var d net.Dialer
	_, err = d.DialContext(ctx, "tcp", l.Addr().String())
	if err == nil {
		t.Fatalf("expected error connecting to %v but it succeeded", l.Addr().String())
	}
}

func TestReverseTCPForwardingRespectsCallback(t *testing.T) {
	t.Parallel()

	var called int64
	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {},
		ReversePortForwardingCallback: func(ctx Context, bindHost string, bindPort uint32) bool {
			atomic.AddInt64(&called, 1)
			if bindHost != "127.0.0.1" {
				panic("unexpected bindHost: " + bindHost)
			}
			if bindPort != 0 {
				panic("unexpected bindPort: " + strconv.Itoa(int(bindPort)))
			}
			return false
		},
	}, nil)
	defer cleanup()

	_, err := client.Listen("tcp", "127.0.0.1:0")
	if err == nil {
		t.Fatalf("Expected error listening on random port but it succeeded")
	}

	if atomic.LoadInt64(&called) != 1 {
		t.Fatalf("Expected callback to be called once but it was called %d times", called)
	}
}

// newTCPConnPair creates a pair of connected TCP connections using a
// localhost listener. The returned connections support half-close via
// [net.TCPConn.CloseWrite], making them suitable for testing bicopy.
func newTCPConnPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var serverConn net.Conn
	var acceptErr error
	var wg sync.WaitGroup
	wg.Go(func() {
		serverConn, acceptErr = ln.Accept()
	})

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if acceptErr != nil {
		t.Fatal(acceptErr)
	}
	return clientConn, serverConn
}

func TestBicopyNormal(t *testing.T) {
	t.Parallel()

	// ext1 <--TCP--> c1 <-- bicopy --> c2 <--TCP--> ext2
	ext1, c1 := newTCPConnPair(t)
	ext2, c2 := newTCPConnPair(t)
	defer ext1.Close()
	defer ext2.Close()

	done := make(chan struct{})
	go func() {
		bicopy(context.Background(), c1, c2)
		close(done)
	}()

	// ext1 sends data; ext2 should receive it via bicopy
	msg := []byte("hello through bicopy")
	go func() {
		ext1.Write(msg)
		ext1.(*net.TCPConn).CloseWrite()
	}()

	buf, err := io.ReadAll(ext2)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("got %q, want %q", buf, msg)
	}

	// Close ext2's write side so bicopy's other direction finishes
	ext2.(*net.TCPConn).CloseWrite()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("bicopy did not complete in time")
	}
}

func TestBicopyContextCancel(t *testing.T) {
	t.Parallel()

	ext1, c1 := newTCPConnPair(t)
	ext2, c2 := newTCPConnPair(t)
	defer ext1.Close()
	defer ext2.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		bicopy(ctx, c1, c2)
		close(done)
	}()

	// Cancel the context; bicopy should force-close both and return
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("bicopy did not complete after context cancellation")
	}
}

func TestBicopyHalfClosePropagation(t *testing.T) {
	t.Parallel()

	// Verify that when one side finishes sending, the other side
	// can still complete its transfer (no premature teardown).
	// This is the key property that half-close provides over the
	// old cancel-on-first-direction-complete approach.

	// ext1 <--TCP--> c1 <-- bicopy --> c2 <--TCP--> ext2
	ext1, c1 := newTCPConnPair(t)
	ext2, c2 := newTCPConnPair(t)
	defer ext1.Close()
	defer ext2.Close()

	done := make(chan struct{})
	go func() {
		bicopy(context.Background(), c1, c2)
		close(done)
	}()

	// ext1 sends a message and immediately closes its write side (fast direction)
	fastMsg := []byte("fast side done")
	ext1.Write(fastMsg)
	ext1.(*net.TCPConn).CloseWrite()

	// ext2 reads the fast message
	buf := make([]byte, len(fastMsg))
	if _, err := io.ReadFull(ext2, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if !bytes.Equal(buf, fastMsg) {
		t.Fatalf("got %q, want %q", buf, fastMsg)
	}

	// ext2 sends a reply after a delay (slow direction).
	// With the old bicopy (cancel on first direction complete),
	// this data would be lost. With half-close, it gets through.
	slowMsg := []byte("slow side reply")
	go func() {
		time.Sleep(50 * time.Millisecond)
		ext2.Write(slowMsg)
		ext2.(*net.TCPConn).CloseWrite()
	}()

	// ext1 should receive the slow reply
	reply, err := io.ReadAll(ext1)
	if err != nil {
		t.Fatalf("ReadAll reply: %v", err)
	}
	if !bytes.Equal(reply, slowMsg) {
		t.Fatalf("got reply %q, want %q", reply, slowMsg)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("bicopy did not complete in time")
	}
}

// opaqueRWC wraps an [io.ReadWriteCloser] to hide any half-close methods
// (CloseWrite, CloseRead) from type assertions. This simulates a connection
// type that does not support half-close, which is useful for testing that
// halfCloseWrite and halfCloseRead are safe no-ops rather than falling back
// to a full Close that would break the other direction.
type opaqueRWC struct {
	io.ReadWriteCloser
}

func TestHalfCloseWriteNoOpPreservesConnection(t *testing.T) {
	t.Parallel()

	// Verify that halfCloseWrite is a no-op for types without CloseWrite
	// support, leaving the connection open for continued reading. A
	// c.Close() fallback would break this: the connection would be fully
	// closed and the subsequent ReadAll would fail.
	c1, c2 := net.Pipe()
	defer c2.Close()
	wrapped := &opaqueRWC{c1}
	defer wrapped.Close()

	halfCloseWrite(wrapped)

	// Connection must still be readable after the no-op halfCloseWrite.
	go func() {
		c2.Write([]byte("still works"))
		c2.Close()
	}()

	buf, err := io.ReadAll(wrapped)
	if err != nil {
		t.Fatalf("ReadAll after halfCloseWrite should succeed: %v", err)
	}
	if string(buf) != "still works" {
		t.Fatalf("got %q, want %q", string(buf), "still works")
	}
}

func TestHalfCloseReadNoOpPreservesConnection(t *testing.T) {
	t.Parallel()

	// Verify that halfCloseRead is a no-op for types without CloseRead
	// support, leaving the connection open for continued writing. A
	// c.Close() fallback would break this: the connection would be fully
	// closed and the subsequent Write would fail.
	c1, c2 := net.Pipe()
	defer c2.Close()
	wrapped := &opaqueRWC{c1}

	halfCloseRead(wrapped)

	// Connection must still be writable after the no-op halfCloseRead.
	done := make(chan []byte, 1)
	go func() {
		buf, _ := io.ReadAll(c2)
		done <- buf
	}()

	msg := []byte("still works")
	if _, err := wrapped.Write(msg); err != nil {
		t.Fatalf("Write after halfCloseRead should succeed: %v", err)
	}
	wrapped.Close()

	select {
	case buf := <-done:
		if string(buf) != string(msg) {
			t.Fatalf("got %q, want %q", string(buf), string(msg))
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for data")
	}
}
