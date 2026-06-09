// Package tools defines the local-action tools the agent can invoke.
package tools

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"minai/internal/copilot"
	"minai/internal/env"
	"minai/internal/ptrace"
)

// Handler executes a tool call. args is the raw JSON arguments object sent by
// the model. The returned string becomes the "tool" message content fed back
// into the next chat turn.
type Handler func(args json.RawMessage) (string, error)

// Tool bundles the schema sent to the model with the local handler.
type Tool struct {
	Spec    copilot.Tool
	Handler Handler
}

// Default returns the built-in toolset: read_file, write_file, list_dir,
// run_shell.
func Default() []Tool {
	return []Tool{
		readFile(),
		writeFile(),
		listDir(),
		runShell(),
	}
}

func readFile() Tool {
	return Tool{
		Spec: copilot.Tool{
			Type: "function",
			Function: copilot.ToolFunction{
				Name:        "read_file",
				Description: "Read the contents of a UTF-8 text file from the local filesystem.",
				Parameters: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"path": map[string]any{
							"type":        "string",
							"description": "Absolute or relative file path.",
						},
					},
					"required": []string{"path"},
				},
			},
		},
		Handler: func(args json.RawMessage) (string, error) {
			var a struct {
				Path string `json:"path"`
			}
			if err := json.Unmarshal(args, &a); err != nil {
				return "", err
			}
			b, err := os.ReadFile(a.Path)
			if err != nil {
				return "", err
			}
			return string(b), nil
		},
	}
}

func writeFile() Tool {
	return Tool{
		Spec: copilot.Tool{
			Type: "function",
			Function: copilot.ToolFunction{
				Name:        "write_file",
				Description: "Create or overwrite a UTF-8 text file. Parent directories are created as needed.",
				Parameters: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"path":    map[string]any{"type": "string"},
						"content": map[string]any{"type": "string"},
					},
					"required": []string{"path", "content"},
				},
			},
		},
		Handler: func(args json.RawMessage) (string, error) {
			var a struct {
				Path    string `json:"path"`
				Content string `json:"content"`
			}
			if err := json.Unmarshal(args, &a); err != nil {
				return "", err
			}
			if dir := filepath.Dir(a.Path); dir != "" && dir != "." {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					return "", err
				}
			}
			if err := os.WriteFile(a.Path, []byte(a.Content), 0o644); err != nil {
				return "", err
			}
			return fmt.Sprintf("wrote %d bytes to %s", len(a.Content), a.Path), nil
		},
	}
}

func listDir() Tool {
	return Tool{
		Spec: copilot.Tool{
			Type: "function",
			Function: copilot.ToolFunction{
				Name:        "list_dir",
				Description: "List the entries of a directory. Directories are suffixed with '/'.",
				Parameters: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"path": map[string]any{"type": "string"},
					},
					"required": []string{"path"},
				},
			},
		},
		Handler: func(args json.RawMessage) (string, error) {
			var a struct {
				Path string `json:"path"`
			}
			if err := json.Unmarshal(args, &a); err != nil {
				return "", err
			}
			entries, err := os.ReadDir(a.Path)
			if err != nil {
				return "", err
			}
			var sb strings.Builder
			for _, e := range entries {
				suffix := ""
				if e.IsDir() {
					suffix = "/"
				}
				fmt.Fprintf(&sb, "%s%s\n", e.Name(), suffix)
			}
			return sb.String(), nil
		},
	}
}

func runShell() Tool {
	return Tool{
		Spec: copilot.Tool{
			Type: "function",
			Function: copilot.ToolFunction{
				Name: "run_shell",
				Description: "Execute a shell command via `sh -c` and return combined stdout/stderr. " +
					"The user is prompted for confirmation before each invocation.",
				Parameters: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"command": map[string]any{"type": "string"},
					},
					"required": []string{"command"},
				},
			},
		},
		Handler: func(args json.RawMessage) (string, error) {
			var a struct {
				Command string `json:"command"`
			}
			if err := json.Unmarshal(args, &a); err != nil {
				return "", err
			}
			// Per-call access-failure detection mode set by the
			// sandbox child from Envelope.DetectMode. Empty / unknown
			// values fall through to the regex-based path, so any
			// future addition that forgets to set it is harmless.
			switch os.Getenv(env.DetectMode) {
			case "ptrace":
				return runShellPtrace(a.Command)
			default:
				return runShellDefault(a.Command)
			}
		},
	}
}

// runShellDefault is the historical implementation: shell out, capture
// combined stdout+stderr, append a tag line on non-zero exit. Access
// failures are detected in the sandbox child via `pathFromText` regex over
// this returned string.
func runShellDefault(command string) (string, error) {
	out, err := exec.Command("sh", "-c", command).CombinedOutput()
	res := string(out)
	if err != nil {
		res += "\n[exit error: " + err.Error() + "]"
	}
	return res, nil
}

// MultiPathError aggregates one or more *fs.PathError values produced
// during a single tool invocation. The run_shell tool emits it in ptrace
// mode when the command (or any of its descendants) triggers multiple
// distinct EACCES/EPERM filesystem syscalls, so the sandbox layer can
// prompt the user for every denied path in a single pass instead of
// forcing the "fix one path per retry" loop. The Errs slice preserves
// first-seen order and is deduplicated by path; if the same path was
// hit by both a read- and a write-intent syscall the write-intent
// variant wins, so the user is prompted for the most permissive grant
// the command actually needs.
type MultiPathError struct {
	Errs []*fs.PathError
}

// Error returns a compact, human-readable summary suitable for logging
// and for the "error: ..." string the sandbox propagates back to the
// model when every denial in this batch is ultimately rejected.
func (m *MultiPathError) Error() string {
	switch len(m.Errs) {
	case 0:
		return "(no path errors)"
	case 1:
		return m.Errs[0].Error()
	}
	paths := make([]string, len(m.Errs))
	for i, e := range m.Errs {
		paths[i] = e.Path
	}
	return fmt.Sprintf("permission denied on %d paths: %s",
		len(m.Errs), strings.Join(paths, ", "))
}

// Unwrap exposes the constituent errors so callers that traverse error
// trees (errors.Is/As, custom walkers) can reach the individual
// *fs.PathError values.
func (m *MultiPathError) Unwrap() []error {
	out := make([]error, len(m.Errs))
	for i, e := range m.Errs {
		out[i] = e
	}
	return out
}

// runShellPtrace runs the shell command under ptrace so that every failed
// filesystem syscall the command (or any descendant) makes is captured at
// the source. EACCES/EPERM failures are deduplicated by path (read+write
// on the same path collapse to a single write-intent denial) and the full
// set is returned as a *MultiPathError so the sandbox layer can prompt
// the user for each denied path in one pass.
//
// Denials are only surfaced when the shell exits non-zero. A command that
// hit EACCES on an optional probe (config files, PATH lookups, recursive
// walks that gracefully skip unreadable nodes, ...) and still exited 0
// did not actually need that access, and prompting the user to grant it
// would be noise. The denials list reflects the failures the user has a
// reason to care about; the surface here matches what they'd see if they
// just inspected the command's exit status themselves.
//
// Other failed FS syscalls (ENOENT for PATH probing, missing locale
// catalogs, etc.) are intentionally ignored to stay semantically aligned
// with the default regex mode, which only matches "Permission denied".
//
// If the ptrace machinery itself fails (e.g. on a kernel older than 5.3
// that lacks PTRACE_GET_SYSCALL_INFO), we fall back to the default
// implementation rather than failing the user's command, and annotate the
// output so the failure mode is visible.
func runShellPtrace(command string) (string, error) {
	var buf bytes.Buffer
	cmd := exec.Command("sh", "-c", command)
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	res, err := ptrace.Run(cmd)
	if err != nil {
		// Fall back so the user gets *something* useful; tag the
		// output so the regression is visible in the log and to the
		// model.
		out, dErr := runShellDefault(command)
		return "[ptrace setup failed: " + err.Error() + "; falling back to default mode]\n" + out, dErr
	}

	output := buf.String()
	if !res.WaitStatus.Exited() || res.WaitStatus.ExitStatus() != 0 {
		output += "\n[exit error: " + waitStatusString(res.WaitStatus) + "]"
	}

	// Walk every recorded failure and accumulate one PathError per
	// distinct path. A single command typically hits the same path
	// through several syscalls (e.g. an access(R_OK) probe followed
	// by an openat()), and we don't want to bother the user multiple
	// times for the same target. If different syscalls on the same
	// path disagree on intent we keep the most permissive one (write)
	// so the eventual user grant covers every observed need.
	//
	// Op strings are mapped so sandbox.modeFromPathError classifies
	// them correctly:
	//   - IntentRead  -> "stat"  -> "ro"
	//   - IntentWrite -> "write" -> "rw"
	indexByPath := map[string]int{}
	var errs []*fs.PathError
	for _, f := range res.Failures {
		if f.Errno != syscall.EACCES && f.Errno != syscall.EPERM {
			continue
		}
		path := firstNonEmpty(f.Paths)
		if path == "" {
			continue
		}
		op := "stat"
		if ptrace.IntentOf(f.Syscall) == ptrace.IntentWrite {
			op = "write"
		}
		if i, ok := indexByPath[path]; ok {
			// Upgrade ro -> rw if any later occurrence on the same
			// path needs write access. Never downgrade.
			if op == "write" && errs[i].Op != "write" {
				errs[i].Op = "write"
				errs[i].Err = f.Errno
			}
			continue
		}
		indexByPath[path] = len(errs)
		errs = append(errs, &fs.PathError{Op: op, Path: path, Err: f.Errno})
	}

	if len(errs) == 0 {
		return output, nil
	}
	// If the command itself succeeded, the EACCES/EPERM failures we
	// observed were tolerated by the process (probes, optional config
	// files, recursive walks that skip unreadable nodes, ...). The
	// command got what it needed; don't bother the user with grant
	// prompts for paths whose absence didn't actually break anything.
	if res.WaitStatus.Exited() && res.WaitStatus.ExitStatus() == 0 {
		return output, nil
	}
	return output, &MultiPathError{Errs: errs}
}

// waitStatusString renders a syscall.WaitStatus the same way
// os/exec would in its *ExitError.String, without us having to
// construct one. Keeps the trailing "[exit error: ...]" tag readable.
func waitStatusString(ws syscall.WaitStatus) string {
	switch {
	case ws.Exited():
		return fmt.Sprintf("exit status %d", ws.ExitStatus())
	case ws.Signaled():
		return fmt.Sprintf("signal: %s", ws.Signal())
	case ws.Stopped():
		return fmt.Sprintf("stopped: %s", ws.StopSignal())
	default:
		return "unknown wait status"
	}
}

func firstNonEmpty(ss []string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
