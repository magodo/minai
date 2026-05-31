// Package tools defines the local-action tools the agent can invoke.
package tools

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"minai/internal/copilot"
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
			out, err := exec.Command("sh", "-c", a.Command).CombinedOutput()
			res := string(out)
			if err != nil {
				res += "\n[exit error: " + err.Error() + "]"
			}
			return res, nil
		},
	}
}
