//go:build !unix

package ssh

import (
	"errors"
	"net"
	"os"
)

func spawnPrivsepChild(_, _ int, _ []int) (*privsepChild, error) {
	return nil, errors.New("forwarding privsep child is not supported on this platform")
}

func fileFromOOB(_ []byte) *os.File { return nil }

// errnoFromCode is a stub for platforms without an errno model. The privsep
// child that would send a code cannot spawn here.
func errnoFromCode(_ int) error { return nil }

// disableParentUnlink is a stub for platforms without UnixListener unlink
// support; the privsep child that would reach it cannot spawn here.
func disableParentUnlink(_ *net.UnixListener) {}
