// Package agent implements a minimal ReAct loop on top of an LLM that supports
// OpenAI-style tool calling.
//
// Loop:
//
//  1. Append the user message to history.
//  2. Send (system + history) along with the tool specs to the model.
//  3. If the assistant returns tool_calls, execute each one (in a sandboxed
//     subprocess), append a "tool" message per call, and go back to step 2.
//  4. Otherwise print the final assistant content and end the turn.
//
// Sandboxing: every tool call is dispatched to a Landlock-restricted child
// process via internal/sandbox. The child denies all filesystem access by
// default (except a baseline of system RO paths). When a tool fails with
// EACCES on a path that hasn't been pre-approved, the agent prompts the user
// to allow read-only or read-write access. Approvals live in an in-memory
// AccessStore for the rest of the session and are re-applied on retry.
//
// Per-call configuration: each Envelope carries a DetectMode which selects
// the access-failure detection strategy the run_shell tool uses (regex over
// stdout/stderr vs. ptrace-based syscall interception). The active mode is
// owned by the Agent and switched at runtime via SetDetectMode (driven by
// the /detect REPL command).
package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"minai/internal/copilot"
	"minai/internal/env"
	"minai/internal/sandbox"
	"minai/internal/tools"
)

// SystemPrompt is the default persona / safety preamble.
const SystemPrompt = `You are minai, a minimal Go-based ReAct agent.
You have tools to inspect and modify the local filesystem and to run shell commands.
Each tool call runs in a Landlock-sandboxed subprocess that denies filesystem
access by default; the user is prompted when a path needs to be unlocked.
Think briefly, call tools when they help, then return a concise final answer.
Prefer the smallest set of tool calls that solves the task.
Do not run destructive shell commands unless the user explicitly asks for them.`

// Agent owns the conversation state for one REPL session.
type Agent struct {
	client   *copilot.Client
	tools    map[string]tools.Tool
	specs    []copilot.Tool
	history  []copilot.Message
	out      io.Writer
	in       *bufio.Reader
	maxSteps int
	log      *slog.Logger

	access *accessStore

	// detectMode names the access-failure detection strategy used for
	// the run_shell tool. It is mutable at runtime via SetDetectMode
	// (driven by the /detect REPL command). Other tools ignore it.
	mu         sync.Mutex
	detectMode string
}

// Supported values for Agent.detectMode and Envelope.DetectMode.
const (
	DetectModeDefault = "default"
	DetectModePtrace  = "ptrace"
)

// New builds an Agent. The reader is used only for tool-confirmation prompts;
// the caller should pass the same *bufio.Reader it uses for its own input loop
// so they do not fight over stdin. logger may be nil, in which case a no-op
// logger is installed.
func New(c *copilot.Client, ts []tools.Tool, out io.Writer, in *bufio.Reader, logger *slog.Logger) *Agent {
	m := make(map[string]tools.Tool, len(ts))
	specs := make([]copilot.Tool, 0, len(ts))
	for _, t := range ts {
		m[t.Spec.Function.Name] = t
		specs = append(specs, t.Spec)
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Agent{
		client:     c,
		tools:      m,
		specs:      specs,
		history:    []copilot.Message{{Role: "system", Content: SystemPrompt}},
		out:        out,
		in:         in,
		maxSteps:   20,
		log:        logger,
		access:     newAccessStore(),
		detectMode: DetectModeDefault,
	}
}

// DetectMode returns the active access-failure detection mode for the
// run_shell tool. The default for a fresh Agent is DetectModeDefault.
func (a *Agent) DetectMode() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.detectMode
}

// SetDetectMode switches the access-failure detection mode used for the
// run_shell tool. It returns an error for unknown values so callers (e.g.
// the REPL's /detect command) can surface a useful message.
func (a *Agent) SetDetectMode(mode string) error {
	switch mode {
	case DetectModeDefault, DetectModePtrace:
		a.mu.Lock()
		a.detectMode = mode
		a.mu.Unlock()
		return nil
	default:
		return fmt.Errorf("unknown detect mode %q (want %q or %q)",
			mode, DetectModeDefault, DetectModePtrace)
	}
}

// Turn runs the ReAct loop until the model produces an answer with no further
// tool calls, or maxSteps is reached.
func (a *Agent) Turn(ctx context.Context, userInput string) error {
	a.history = append(a.history, copilot.Message{Role: "user", Content: userInput})
	for step := 0; step < a.maxSteps; step++ {
		msg, err := a.client.Chat(ctx, a.history, a.specs)
		if err != nil {
			return err
		}
		a.history = append(a.history, *msg)

		if len(msg.ToolCalls) == 0 {
			if c := strings.TrimSpace(msg.Content); c != "" {
				fmt.Fprintf(a.out, "\n%s\n", c)
			}
			return nil
		}
		for _, tc := range msg.ToolCalls {
			result := a.dispatch(ctx, tc)
			a.history = append(a.history, copilot.Message{
				Role:       "tool",
				ToolCallID: tc.ID,
				Name:       tc.Function.Name,
				Content:    result,
			})
		}
	}
	return fmt.Errorf("max ReAct steps (%d) exceeded", a.maxSteps)
}

// maxPermissionRetries caps how many times we'll prompt+retry a single tool
// call as the user incrementally unlocks paths. Stops loops where a tool
// keeps hitting new denied paths forever.
const maxPermissionRetries = 8

func (a *Agent) dispatch(ctx context.Context, tc copilot.ToolCall) string {
	if _, ok := a.tools[tc.Function.Name]; !ok {
		a.log.Warn("unknown tool", "tool", tc.Function.Name)
		return "error: unknown tool " + tc.Function.Name
	}
	fmt.Fprintf(a.out, "\n\x1b[2m→ %s(%s)\x1b[0m\n", tc.Function.Name, compactJSON(tc.Function.Arguments))
	a.log.Info("tool call", "tool", tc.Function.Name, "args", compactJSON(tc.Function.Arguments))

	for attempt := 0; attempt < maxPermissionRetries; attempt++ {
		ro, rw := a.access.snapshot()
		detectMode := a.DetectMode()
		env := sandbox.Envelope{
			Tool:       tc.Function.Name,
			Args:       json.RawMessage(tc.Function.Arguments),
			AllowedRO:  ro,
			AllowedRW:  rw,
			DetectMode: detectMode,
		}
		a.log.Debug("sandbox exec",
			"attempt", attempt+1,
			"tool", tc.Function.Name,
			"detect_mode", detectMode,
			"allowed_ro", ro,
			"allowed_rw", rw)
		res, err := sandbox.Exec(ctx, env, a.log)
		if err != nil {
			msg := "error: sandbox: " + err.Error()
			a.log.Error("sandbox exec failed", "err", err)
			fmt.Fprintf(a.out, "\x1b[2m← %s\x1b[0m\n", firstLine(msg))
			return msg
		}
		a.log.Debug("sandbox result",
			"denied_path", res.DeniedPath,
			"denied_mode", res.DeniedMode,
			"err", res.Error,
			"output_bytes", len(res.Output))

		if res.DeniedPath != "" {
			fmt.Fprintf(a.out, "\x1b[33m  sandbox blocked %s access to %s\x1b[0m\n",
				res.DeniedMode, res.DeniedPath)
			a.log.Info("access denied by sandbox",
				"path", res.DeniedPath, "mode", res.DeniedMode, "attempt", attempt+1)
			grantPath, mode := a.promptAccess(res.DeniedPath, res.DeniedMode)
			if mode == "" {
				deny := "error: user denied sandbox access to " + res.DeniedPath
				a.log.Info("user denied", "path", res.DeniedPath)
				fmt.Fprintf(a.out, "\x1b[2m← %s\x1b[0m\n", firstLine(deny))
				return deny
			}
			a.log.Info("user granted",
				"requested", res.DeniedPath, "grant_path", grantPath, "mode", mode)
			a.access.allow(grantPath, mode)
			continue
		}

		if res.Error != "" {
			msg := "error: " + res.Error
			a.log.Warn("tool returned error", "tool", tc.Function.Name, "err", res.Error)
			fmt.Fprintf(a.out, "\x1b[2m← %s\x1b[0m\n", firstLine(msg))
			return msg
		}
		out := res.Output
		const maxToolOut = 8000
		if len(out) > maxToolOut {
			out = out[:maxToolOut] + "\n...[truncated]"
		}
		fmt.Fprintf(a.out, "\x1b[2m← %s\x1b[0m\n", firstLine(out))
		return out
	}
	a.log.Warn("too many permission retries", "tool", tc.Function.Name)
	return "error: too many sandbox permission prompts; aborting"
}

func (a *Agent) confirm(prompt string) bool {
	// Allow non-interactive auto-approval (handy for one-shot / CI runs).
	if env.Truthy(env.Yes) {
		return true
	}
	fmt.Fprint(a.out, prompt)
	line, err := a.in.ReadString('\n')
	if err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(line), "y")
}

// promptAccess asks the user whether to grant access to the denied path.
// Returns (grantPath, mode); mode is "" if denied. suggested is the mode the
// tool actually wanted; it becomes the default if the user just hits enter.
//
// If the requested path doesn't yet exist (typical for write_file targets),
// Landlock cannot grant access to it directly — the smallest workable grant
// is the nearest existing ancestor directory. We surface that explicitly
// rather than silently widening the approval scope.
func (a *Agent) promptAccess(path, suggested string) (string, string) {
	grantPath, widened := resolveGrantTarget(path)

	if env.Truthy(env.Yes) {
		if suggested == "" {
			suggested = "rw"
		}
		return grantPath, suggested
	}
	def := suggested
	if def == "" {
		def = "ro"
	}
	if widened {
		fmt.Fprintf(a.out,
			"\x1b[33m  note: %s does not exist; the smallest possible grant\n"+
				"        is %s access on its nearest existing ancestor: %s\x1b[0m\n",
			path, def, grantPath)
	}
	if fi, err := os.Stat(grantPath); err == nil && fi.IsDir() {
		fmt.Fprintf(a.out,
			"\x1b[33m  note: %s is a directory; the grant applies recursively\n"+
				"        to all files and subdirectories beneath it\x1b[0m\n",
			grantPath)
	}
	fmt.Fprintf(a.out, "  allow %s? [r=read-only / w=read-write / n=deny] (default %s): ", grantPath, def)
	line, err := a.in.ReadString('\n')
	if err != nil {
		return grantPath, ""
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "":
		return grantPath, def
	case "r", "ro", "read":
		return grantPath, "ro"
	case "w", "rw", "write":
		return grantPath, "rw"
	default:
		return grantPath, ""
	}
}

// resolveGrantTarget returns the path that should actually be passed to
// Landlock and reports whether it differs from the requested path (i.e. the
// approval would cover a strictly larger scope than the user asked about).
func resolveGrantTarget(p string) (target string, widened bool) {
	if p == "" {
		return p, false
	}
	if abs, err := filepath.Abs(p); err == nil {
		p = filepath.Clean(abs)
	} else {
		p = filepath.Clean(p)
	}
	if _, err := os.Stat(p); err == nil {
		return p, false
	}
	for cur := filepath.Dir(p); cur != "/" && cur != "."; cur = filepath.Dir(cur) {
		if _, err := os.Stat(cur); err == nil {
			return cur, true
		}
	}
	return "/", true
}

// accessStore tracks per-session path approvals. It is safe for concurrent
// use (the agent itself is single-threaded today, but the store may be
// queried from goroutines if dispatch ever fans out).
type accessStore struct {
	mu sync.Mutex
	m  map[string]string // path -> "ro" | "rw"
}

func newAccessStore() *accessStore {
	return &accessStore{m: map[string]string{}}
}

func (s *accessStore) allow(path, mode string) {
	if path == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Upgrade ro -> rw, never downgrade.
	if cur, ok := s.m[path]; ok && cur == "rw" {
		return
	}
	s.m[path] = mode
}

func (s *accessStore) snapshot() (ro, rw []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for p, m := range s.m {
		if m == "rw" {
			rw = append(rw, p)
		} else {
			ro = append(ro, p)
		}
	}
	sort.Strings(ro)
	sort.Strings(rw)
	return
}

func compactJSON(s string) string {
	var v any
	if json.Unmarshal([]byte(s), &v) != nil {
		return s
	}
	b, err := json.Marshal(v)
	if err != nil {
		return s
	}
	return string(b)
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i] + " ..."
	}
	if len(s) > 120 {
		return s[:120] + " ..."
	}
	if s == "" {
		return "(ok)"
	}
	return s
}
