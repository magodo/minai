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

// runShellPtrace runs the shell command under ptrace so that every failed
// filesystem syscall the command (or any descendant) makes is captured at
// the source. When at least one EACCES/EPERM failure is observed, we
// synthesize an *fs.PathError pointing at the first such path and return
// it as the handler's error: the sandbox child's existing detection path
// (`pathFromError` + `modeFromOp`) then surfaces it to the agent as a
// structured denial, identical to the way the Go-native tools do.
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

	// Find the first EACCES/EPERM failure with a non-empty path and
	// synthesize a PathError so the sandbox's existing detection path
	// can pick it up.
	for _, f := range res.Failures {
		if f.Errno != syscall.EACCES && f.Errno != syscall.EPERM {
			continue
		}
		path := firstNonEmpty(f.Paths)
		if path == "" {
			continue
		}
		// Map the ptrace syscall name to a PathError.Op string that
		// sandbox.modeFromOp already classifies correctly:
		//   - IntentRead -> "stat" -> "ro"
		//   - IntentWrite -> "write" -> "rw"
		op := "stat"
		if ptrace.IntentOf(f.Syscall) == ptrace.IntentWrite {
			op = "write"
		}
		return output, &fs.PathError{
			Op:   op,
			Path: path,
			Err:  f.Errno,
		}
	}
	return output, nil
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
