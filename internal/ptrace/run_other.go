//go:build !linux || !amd64

package ptrace

import "os/exec"

// Run on unsupported platforms returns ErrUnsupported without touching
// the supplied cmd. The shape of the API is preserved so callers don't
// need build tags around their imports.
func Run(cmd *exec.Cmd) (*Result, error) {
	return nil, ErrUnsupported
}
