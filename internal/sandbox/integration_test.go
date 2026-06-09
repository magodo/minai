//go:build linux

package sandbox_test

import (
	"context"
	"encoding/json"
	"fmt"
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
//	-> sandbox.denialsFromError -> Result.Denials
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
	if len(res.Denials) == 0 {
		t.Fatalf("expected at least one Denial; got %+v", *res)
	}
	want := filepath.Clean("/etc/shadow")
	if res.Denials[0].Path != want {
		t.Errorf("Denials[0].Path = %q, want %q", res.Denials[0].Path, want)
	}
	if res.Denials[0].Mode != "ro" {
		t.Errorf("Denials[0].Mode = %q, want %q", res.Denials[0].Mode, "ro")
	}
}

// TestExec_ShellPtrace_MultipleDenials covers the new behavior where a
// single ptrace-traced command can surface multiple distinct denied
// paths in one Result. We create two unreadable files under a temp dir,
// pre-grant the dir via AllowedRO so Landlock doesn't deny first, then
// run a shell command that touches both files. The POSIX layer rejects
// each open() with EACCES and both paths should show up in res.Denials.
//
// The command intentionally ends on the second cat (no `echo done` or
// other success-tail) so the shell's overall exit status is non-zero;
// runShellPtrace suppresses denials on a clean exit since they would
// then be tolerated probes rather than actual access failures.
func TestExec_ShellPtrace_MultipleDenials(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; chmod 0000 has no effect")
	}
	dir := t.TempDir()
	a := filepath.Join(dir, "a.txt")
	b := filepath.Join(dir, "b.txt")
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, []byte("x"), 0o000); err != nil {
			t.Fatalf("create %s: %v", p, err)
		}
		// Re-chmod in case umask/fs masked the perms above.
		if err := os.Chmod(p, 0o000); err != nil {
			t.Fatalf("chmod %s: %v", p, err)
		}
	}
	args, err := json.Marshal(struct {
		Command string `json:"command"`
	}{Command: fmt.Sprintf("cat %s 2>&1; cat %s 2>&1", a, b)})
	if err != nil {
		t.Fatal(err)
	}
	env := sandbox.Envelope{
		Tool:       "run_shell",
		Args:       args,
		DetectMode: "ptrace",
		AllowedRO:  []string{dir},
	}
	res, err := sandbox.Exec(context.Background(), env, nil)
	if err != nil {
		t.Fatalf("sandbox.Exec: %v", err)
	}
	t.Logf("result: %+v", *res)
	if len(res.Denials) < 2 {
		t.Fatalf("expected at least 2 Denials (one per file); got %d: %+v",
			len(res.Denials), res.Denials)
	}
	seen := map[string]bool{}
	for _, d := range res.Denials {
		seen[d.Path] = true
		if d.Mode != "ro" {
			t.Errorf("Denial for %s: Mode = %q, want %q", d.Path, d.Mode, "ro")
		}
	}
	if !seen[filepath.Clean(a)] {
		t.Errorf("expected a Denial for %s; got %+v", a, res.Denials)
	}
	if !seen[filepath.Clean(b)] {
		t.Errorf("expected a Denial for %s; got %+v", b, res.Denials)
	}
}

// TestExec_ShellDefault_EACCES is the equivalent check for the default
// regex-based detection: it should also surface the path, just via the
// `pathFromText` route instead of the synthesized PathError. The
// default mode only ever produces a single denial regardless of how
// many "Permission denied" lines appear in the output.
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
	if len(res.Denials) == 0 {
		t.Fatalf("expected at least one Denial; got %+v", *res)
	}
	if !strings.Contains(res.Denials[0].Path, "shadow") {
		t.Errorf("Denials[0].Path = %q, want it to contain 'shadow'", res.Denials[0].Path)
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
	if len(res.Denials) != 0 {
		t.Errorf("expected no Denials for an ENOENT-only command; got %+v", res.Denials)
	}
	if !strings.Contains(res.Output, "ok") {
		t.Errorf("expected output to contain 'ok'; got %q", res.Output)
	}
}

// TestExec_ShellPtrace_SuccessSuppressesDenials verifies that a command
// which encounters EACCES on a probe but still exits cleanly does not
// surface any denials. The motivating case: a tool that tries to read
// an optional dotfile, doesn't find it / can't read it, and proceeds
// with defaults. We model that with a subshell that swallows the cat
// failure (`2>/dev/null || true`) and then prints a success marker, so
// the whole `sh -c` exits 0. The EACCES on the unreadable file is real
// at the kernel layer (and ptrace captures it), but suppressed at the
// MultiPathError boundary because the command got what it needed.
func TestExec_ShellPtrace_SuccessSuppressesDenials(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; chmod 0000 has no effect")
	}
	dir := t.TempDir()
	probe := filepath.Join(dir, "optional.cfg")
	if err := os.WriteFile(probe, []byte("x"), 0o000); err != nil {
		t.Fatalf("create %s: %v", probe, err)
	}
	if err := os.Chmod(probe, 0o000); err != nil {
		t.Fatalf("chmod %s: %v", probe, err)
	}
	args, err := json.Marshal(struct {
		Command string `json:"command"`
	}{Command: fmt.Sprintf("cat %s 2>/dev/null || true; echo ok", probe)})
	if err != nil {
		t.Fatal(err)
	}
	env := sandbox.Envelope{
		Tool:       "run_shell",
		Args:       args,
		DetectMode: "ptrace",
		AllowedRO:  []string{dir},
	}
	res, err := sandbox.Exec(context.Background(), env, nil)
	if err != nil {
		t.Fatalf("sandbox.Exec: %v", err)
	}
	t.Logf("result: %+v", *res)
	if len(res.Denials) != 0 {
		t.Errorf("expected no Denials when the command exits 0; got %+v",
			res.Denials)
	}
	if !strings.Contains(res.Output, "ok") {
		t.Errorf("expected output to contain 'ok'; got %q", res.Output)
	}
}
