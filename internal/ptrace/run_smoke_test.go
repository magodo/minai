//go:build linux && amd64

package ptrace_test

import (
	"bytes"
	"fmt"
	"os/exec"
	"syscall"
	"testing"

	"minai/internal/ptrace"
)

// TestSmokeBasic is a sanity check that Run captures the combined output
// of a shell command and surfaces filesystem syscall failures with the
// expected errnos. It is not a strict correctness test of every code
// path; it just confirms the package is hooked up to a working kernel.
func TestSmokeBasic(t *testing.T) {
	var buf bytes.Buffer
	cmd := exec.Command("sh", "-c",
		"cat /etc/shadow 2>&1 ; ls /definitely-not-there 2>&1 ; echo done")
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	res, err := ptrace.Run(cmd)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	out := buf.String()
	if !bytes.Contains(buf.Bytes(), []byte("done")) {
		t.Fatalf("expected combined output to contain 'done'; got:\n%s", out)
	}
	t.Logf("combined output:\n%s", out)
	t.Logf("wait status: exited=%v code=%d signaled=%v",
		res.WaitStatus.Exited(), res.WaitStatus.ExitStatus(), res.WaitStatus.Signaled())

	var sawAccess, sawNoEnt bool
	for _, f := range res.Failures {
		t.Logf("  [pid %d] %s(%v) errno=%s", f.PID, f.Syscall, f.Paths, f.Errno)
		if f.Errno == syscall.EACCES || f.Errno == syscall.EPERM {
			sawAccess = true
		}
		if f.Errno == syscall.ENOENT {
			sawNoEnt = true
		}
	}
	if !sawAccess {
		t.Errorf("expected at least one EACCES/EPERM failure (from /etc/shadow); got none")
	}
	if !sawNoEnt {
		t.Errorf("expected at least one ENOENT failure (from /definitely-not-there); got none")
	}
	if got, want := ptrace.IntentOf("mkdir"), ptrace.IntentWrite; got != want {
		t.Errorf("IntentOf(mkdir) = %v, want %v", got, want)
	}
	if got, want := ptrace.IntentOf("openat"), ptrace.IntentRead; got != want {
		t.Errorf("IntentOf(openat) = %v, want %v", got, want)
	}
	fmt.Println()
}
