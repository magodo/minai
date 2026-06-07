//go:build linux

package sandbox_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"minai/internal/sandbox"
)

// TestMain wears two hats. When the test binary is re-execed by
// sandbox.Exec (i.e. MINAI_TOOL_EXEC=1 is set), it dispatches to
// sandbox.RunChild and exits, just like cmd/minai/main.go does. Otherwise
// it runs the normal test loop.
func TestMain(m *testing.M) {
	if sandbox.IsChild() {
		sandbox.RunChild(slog.New(slog.DiscardHandler))
		return
	}
	os.Exit(m.Run())
}

// TestExec_ShellPtrace_EACCES end-to-end-validates the ptrace mode by
// running a `cat` on a file the running user definitely can't read (the
// /etc/shadow database is 0600 root:root on every reasonable Linux
// distro) and asserting that the sandbox surfaces the path as a
// structured denial. This exercises the full pipeline:
//
//	tools.runShell(ptrace) -> ptrace.Run -> synthesized *fs.PathError
//	-> sandbox.pathFromError -> Result.DeniedPath / .DeniedMode
func TestExec_ShellPtrace_EACCES(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; /etc/shadow would be readable")
	}
	args, err := json.Marshal(struct {
		Command string `json:"command"`
	}{Command: "cat /etc/shadow"})
	if err != nil {
		t.Fatal(err)
	}
	env := sandbox.Envelope{
		Tool:       "run_shell",
		Args:       args,
		DetectMode: "ptrace",
	}
	res, err := sandbox.Exec(context.Background(), env, nil)
	if err != nil {
		t.Fatalf("sandbox.Exec: %v", err)
	}
	t.Logf("result: %+v", *res)
	if res.DeniedPath == "" {
		t.Fatalf("expected DeniedPath; got %+v", *res)
	}
	want := filepath.Clean("/etc/shadow")
	if res.DeniedPath != want {
		t.Errorf("DeniedPath = %q, want %q", res.DeniedPath, want)
	}
	if res.DeniedMode != "ro" {
		t.Errorf("DeniedMode = %q, want %q", res.DeniedMode, "ro")
	}
}

// TestExec_ShellDefault_EACCES is the equivalent check for the default
// regex-based detection: it should also surface the path, just via the
// `pathFromText` route instead of the synthesized PathError.
func TestExec_ShellDefault_EACCES(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; /etc/shadow would be readable")
	}
	args, err := json.Marshal(struct {
		Command string `json:"command"`
	}{Command: "cat /etc/shadow"})
	if err != nil {
		t.Fatal(err)
	}
	env := sandbox.Envelope{
		Tool:       "run_shell",
		Args:       args,
		DetectMode: "default",
	}
	res, err := sandbox.Exec(context.Background(), env, nil)
	if err != nil {
		t.Fatalf("sandbox.Exec: %v", err)
	}
	t.Logf("result: %+v", *res)
	if res.DeniedPath == "" {
		t.Fatalf("expected DeniedPath; got %+v", *res)
	}
	if !strings.Contains(res.DeniedPath, "shadow") {
		t.Errorf("DeniedPath = %q, want it to contain 'shadow'", res.DeniedPath)
	}
}

// TestExec_ShellPtrace_ENOENT_NotReported sanity-checks the ptrace mode's
// EACCES/EPERM filter: a missing-file shell command (which generates
// plenty of ENOENT from PATH probing and from the missing target itself)
// must NOT show up as a structured denial.
func TestExec_ShellPtrace_ENOENT_NotReported(t *testing.T) {
	args, err := json.Marshal(struct {
		Command string `json:"command"`
	}{Command: "ls /definitely-not-there 2>/dev/null; echo ok"})
	if err != nil {
		t.Fatal(err)
	}
	env := sandbox.Envelope{
		Tool:       "run_shell",
		Args:       args,
		DetectMode: "ptrace",
	}
	res, err := sandbox.Exec(context.Background(), env, nil)
	if err != nil {
		t.Fatalf("sandbox.Exec: %v", err)
	}
	t.Logf("result: %+v", *res)
	if res.DeniedPath != "" {
		t.Errorf("expected DeniedPath to be empty for an ENOENT-only command; got %q", res.DeniedPath)
	}
	if !strings.Contains(res.Output, "ok") {
		t.Errorf("expected output to contain 'ok'; got %q", res.Output)
	}
}
