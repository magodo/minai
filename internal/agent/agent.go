// Package agent implements a minimal ReAct loop on top of an LLM that supports
// OpenAI-style tool calling.
//
// Loop:
//
//  1. Append the user message to history.
//  2. Send (system + history) along with the tool specs to the model.
//  3. If the assistant returns tool_calls, execute each one, append a "tool"
//     message per call, and go back to step 2.
//  4. Otherwise print the final assistant content and end the turn.
package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"minai/internal/copilot"
	"minai/internal/tools"
)

// SystemPrompt is the default persona / safety preamble.
const SystemPrompt = `You are minai, a minimal Go-based ReAct agent.
You have tools to inspect and modify the local filesystem and to run shell commands.
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
}

// New builds an Agent. The reader is used only for tool-confirmation prompts;
// the caller should pass the same *bufio.Reader it uses for its own input loop
// so they do not fight over stdin.
func New(c *copilot.Client, ts []tools.Tool, out io.Writer, in *bufio.Reader) *Agent {
	m := make(map[string]tools.Tool, len(ts))
	specs := make([]copilot.Tool, 0, len(ts))
	for _, t := range ts {
		m[t.Spec.Function.Name] = t
		specs = append(specs, t.Spec)
	}
	return &Agent{
		client:   c,
		tools:    m,
		specs:    specs,
		history:  []copilot.Message{{Role: "system", Content: SystemPrompt}},
		out:      out,
		in:       in,
		maxSteps: 20,
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
			result := a.dispatch(tc)
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

func (a *Agent) dispatch(tc copilot.ToolCall) string {
	t, ok := a.tools[tc.Function.Name]
	if !ok {
		return "error: unknown tool " + tc.Function.Name
	}
	fmt.Fprintf(a.out, "\n\x1b[2m→ %s(%s)\x1b[0m\n", tc.Function.Name, compactJSON(tc.Function.Arguments))

	if tc.Function.Name == "run_shell" && !a.confirm("  allow shell command? [y/N]: ") {
		fmt.Fprintln(a.out, "\x1b[2m← denied\x1b[0m")
		return "user denied execution"
	}

	out, err := t.Handler(json.RawMessage(tc.Function.Arguments))
	if err != nil {
		msg := "error: " + err.Error()
		fmt.Fprintf(a.out, "\x1b[2m← %s\x1b[0m\n", firstLine(msg))
		return msg
	}
	// Cap the payload fed back to the model so a runaway tool can't blow up
	// the context window.
	const maxToolOut = 8000
	if len(out) > maxToolOut {
		out = out[:maxToolOut] + "\n...[truncated]"
	}
	fmt.Fprintf(a.out, "\x1b[2m← %s\x1b[0m\n", firstLine(out))
	return out
}

func (a *Agent) confirm(prompt string) bool {
	// Allow non-interactive auto-approval (handy for one-shot / CI runs).
	if v := os.Getenv("MINAI_YES"); v != "" && v != "0" {
		return true
	}
	fmt.Fprint(a.out, prompt)
	line, err := a.in.ReadString('\n')
	if err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(line), "y")
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
