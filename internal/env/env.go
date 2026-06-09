// Package env centralizes the names of every environment variable that
// minai reads or writes, plus a small Truthy helper for the loose boolean
// pattern used throughout the codebase.
//
// Keeping these constants in one place avoids stringly-typed call sites
// and gives a single point of truth for renames, documentation, and audits
// of "which env vars does minai touch?". All exported names live in this
// file with a short doc comment so `go doc minai/internal/env` is enough
// to enumerate them.
//
// All variables share the MINAI_ prefix to avoid stomping on the user's
// environment.
package env

import "os"

// Auth and model selection (read in internal/copilot and cmd/minai).
const (
	// CopilotToken is the GitHub Copilot API bearer token. Required.
	CopilotToken = "MINAI_COPILOT_TOKEN"

	// CopilotEndpoint optionally overrides the chat-completions host;
	// defaults to https://api.githubcopilot.com.
	CopilotEndpoint = "MINAI_COPILOT_ENDPOINT"

	// Model optionally overrides the default LLM model name (gpt-4o).
	Model = "MINAI_MODEL"
)

// CLI-flag mirrors. cmd/minai/main.go promotes its boolean flags to these
// env vars so the sandboxed child process - which is just `/proc/self/exe`
// re-execed with ToolExec=1 - inherits the same behavior.
const (
	// Debug, when Truthy, enables verbose slog output on stderr.
	// Mirrors the -debug CLI flag.
	Debug = "MINAI_DEBUG"

	// Audit, when Truthy, enables Landlock kernel audit logging for
	// sandbox denials. Mirrors the -l CLI flag.
	Audit = "MINAI_AUDIT"
)

// Behavior toggles.
const (
	// Yes, when Truthy, auto-approves all interactive prompts (tool
	// confirmation and sandbox access grants). Convenient for one-shot
	// / CI runs; use with care.
	Yes = "MINAI_YES"
)

// Internal sandbox/agent contract. These are set by minai itself and not
// meant to be set by the user.
const (
	// ToolExec is the marker cmd/minai/main.go uses at startup to
	// recognize it has been re-execed as the sandboxed tool runner.
	// The expected value is exactly "1".
	ToolExec = "MINAI_TOOL_EXEC"

	// DetectMode propagates Envelope.DetectMode from the sandboxed
	// child process to the tool handler without changing the Handler
	// signature. Set immediately before the handler runs and unset
	// right after.
	DetectMode = "MINAI_DETECT_MODE"
)

// Truthy reports whether the named environment variable is set to a value
// other than the empty string or "0". This matches the loose boolean
// convention used by minai's flag-mirror env vars (Debug, Audit, Yes).
//
// Use os.Getenv directly for variables that carry an arbitrary value
// (CopilotToken, Model, DetectMode, ...).
func Truthy(name string) bool {
	v := os.Getenv(name)
	return v != "" && v != "0"
}
