// Package ptrace runs a child command under ptrace and records every
// filesystem-related syscall that the child (or any of its descendants)
// makes which returns an error. For each failure it captures the syscall
// name, the resolved absolute path of each path operand, and the errno.
//
// This is a library form of the standalone supervisor demo. The supported
// platform is linux/amd64; on any other platform Run returns
// ErrUnsupported and the package compiles to no-op types so callers don't
// need build tags themselves.
//
// Typical use from a tool that wants to detect EACCES/EPERM precisely:
//
//	var buf bytes.Buffer
//	cmd := exec.Command("sh", "-c", userCmd)
//	cmd.Stdout = &buf
//	cmd.Stderr = &buf
//	res, err := ptrace.Run(cmd)
//	if err != nil { ... }
//	for _, f := range res.Failures {
//	    if f.Errno == syscall.EACCES || f.Errno == syscall.EPERM { ... }
//	}
//
// The kernel feature this builds on (PTRACE_GET_SYSCALL_INFO) was added in
// Linux 5.3. Older kernels return ENOSYS from the underlying ptrace
// request and Run will surface that error verbatim.
package ptrace

import (
	"errors"
	"syscall"
)

// ErrUnsupported is returned by Run on platforms where ptrace tracing of
// filesystem syscalls is not implemented by this package (anything other
// than linux/amd64).
var ErrUnsupported = errors.New("ptrace: not supported on this platform (requires linux/amd64)")

// Failure is one recorded entry: a single FS-touching syscall that returned
// an error. PID is the tracee that made the call. Syscall is its canonical
// name (e.g. "openat"). Paths are the absolute paths of each path operand
// in argument order; for *at-family syscalls relative paths are resolved
// against the corresponding dirfd via /proc/<pid>/fd. Errno is the negated
// return value reported by the kernel.
type Failure struct {
	PID     int
	Syscall string
	Paths   []string
	Errno   syscall.Errno
}

// Result is what Run returns on success. WaitStatus is the wait4 status of
// the root tracee at the moment it exited (or was killed). Failures is the
// list of every failed FS syscall observed across the whole process tree,
// in the order they were seen.
type Result struct {
	WaitStatus syscall.WaitStatus
	Failures   []Failure
}

// SyscallIntent classifies an FS syscall as needing read or write access.
// For open/openat/openat2 the answer truly depends on the flags argument
// which the tracer doesn't decode today; those default to IntentRead. The
// returned value is suitable as a hint for the user-facing "ro/rw"
// permission prompt.
type SyscallIntent int

const (
	IntentRead SyscallIntent = iota
	IntentWrite
)

var writeSyscalls = map[string]bool{
	"creat":      true,
	"mkdir":      true,
	"mkdirat":    true,
	"rmdir":      true,
	"unlink":     true,
	"unlinkat":   true,
	"rename":     true,
	"renameat":   true,
	"renameat2":  true,
	"link":       true,
	"linkat":     true,
	"symlink":    true,
	"symlinkat":  true,
	"chmod":      true,
	"fchmodat":   true,
	"chown":      true,
	"lchown":     true,
	"fchownat":   true,
	"truncate":   true,
	"mknod":      true,
	"mknodat":    true,
	"utimensat":  true,
}

// IntentOf returns the access intent (read vs write) for a syscall name as
// captured in Failure.Syscall. Unknown names and the open family default
// to IntentRead.
func IntentOf(syscallName string) SyscallIntent {
	if writeSyscalls[syscallName] {
		return IntentWrite
	}
	return IntentRead
}
