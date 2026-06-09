// Command minai is a minimal ReAct-style AI agent using GitHub Copilot as the
// LLM provider.
//
// Usage:
//
//	minai                       # interactive REPL
//	minai -p "your prompt"      # one-shot: run a single turn and exit
//	echo "prompt" | minai -p -  # one-shot: read prompt from stdin
//	minai -debug                # verbose slog output on stderr
//	minai -l                    # enable Landlock kernel audit log for denials
//
// REPL commands:
//
//	/help                       list available commands
//	/quit, /exit                exit
//	/detect                     show the current access-failure detection
//	                            mode used by the run_shell tool
//	/detect default | ptrace    switch the detection mode at runtime.
//	                            "default" matches the historical regex
//	                            over the command's combined output;
//	                            "ptrace" intercepts FS syscalls (linux/amd64
//	                            kernel >=5.3) and reports EACCES/EPERM at
//	                            their source, including the exact path.
//
// Environment:
//
//	MINAI_MODEL                 # override default model (gpt-4o)
//	MINAI_COPILOT_TOKEN         # Copilot API token (Bearer), required
//	MINAI_COPILOT_ENDPOINT      # override API host (default api.githubcopilot.com)
//	MINAI_YES                   # if set, auto-approve run_shell (use with care)
//	MINAI_DEBUG                 # if set (and not "0"), same as -debug; also
//	                            # inherited by the sandboxed child process
//	MINAI_AUDIT                 # if set (and not "0"), same as -l; inherited
//	                            # by the sandboxed child so it leaves Landlock
//	                            # kernel audit logging at its default (on for
//	                            # the originating process on ABI v7+).
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"

	"minai/internal/agent"
	"minai/internal/copilot"
	"minai/internal/env"
	"minai/internal/sandbox"
	"minai/internal/tools"
)

func main() {
	// If we were re-execed as a sandboxed tool runner, hand off immediately
	// before touching auth, flags, or anything else the child has no business
	// doing. RunChild terminates the process.
	if sandbox.IsChild() {
		sandbox.RunChild(newLogger(debugEnabled(), "child"))
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "minai: error:", err)
		os.Exit(1)
	}
}

// debugEnabled reports whether MINAI_DEBUG is set to a truthy value. The CLI
// flag also sets this env var so the value propagates to the sandboxed child.
func debugEnabled() bool {
	return env.Truthy(env.Debug)
}

// newLogger builds a slog.Logger writing to stderr. When debug is off it
// returns a discard logger so no logging output reaches the user — the CLI
// stays quiet by default. The "component" tag lets callers tell parent
// ("agent") and child ("child") log lines apart when they interleave.
func newLogger(debug bool, component string) *slog.Logger {
	if !debug {
		return slog.New(slog.DiscardHandler)
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(h).With("component", component)
}

func run() error {
	var (
		prompt string
		debug  bool
		audit  bool
	)
	flag.StringVar(&prompt, "p", "", "one-shot prompt; use '-' to read from stdin")
	flag.BoolVar(&debug, "debug", false, "enable debug logging on stderr (also via MINAI_DEBUG=1)")
	flag.BoolVar(&audit, "l", false, "enable Landlock kernel audit log for sandbox denials (also via MINAI_AUDIT=1)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [-debug] [-l] [-p PROMPT|-]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	// Promote the flags into env vars so the sandboxed child inherits them.
	if debug {
		os.Setenv(env.Debug, "1")
	}
	if audit {
		os.Setenv(env.Audit, "1")
	}
	logger := newLogger(debugEnabled(), "agent")

	model := os.Getenv(env.Model)
	if model == "" {
		model = "gpt-4o"
	}
	logger.Debug("startup", "model", model, "debug", debugEnabled())

	auth, err := copilot.NewAuth()
	if err != nil {
		return err
	}
	client := copilot.NewClient(auth, model)

	// Share one bufio.Reader between the REPL and the agent's confirmation
	// prompts so they don't both buffer-steal from os.Stdin.
	stdin := bufio.NewReader(os.Stdin)
	ag := agent.New(client, tools.Default(), os.Stdout, stdin, logger)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// One-shot mode.
	if prompt != "" {
		if prompt == "-" {
			data, err := io.ReadAll(stdin)
			if err != nil {
				return fmt.Errorf("read stdin: %w", err)
			}
			prompt = strings.TrimSpace(string(data))
			if prompt == "" {
				return errors.New("empty prompt on stdin")
			}
		}
		return ag.Turn(ctx, prompt)
	}

	// Interactive REPL.
	fmt.Printf("minai (model=%s) — type /help for commands, /quit to exit\n", model)
	for {
		fmt.Print("\n> ")
		line, err := stdin.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				fmt.Println()
				return nil
			}
			return err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "/") {
			done, err := dispatchSlash(line, ag, os.Stdout)
			if err != nil {
				fmt.Fprintln(os.Stderr, "minai:", err)
			}
			if done {
				return nil
			}
			continue
		}
		if err := ag.Turn(ctx, line); err != nil {
			fmt.Fprintln(os.Stderr, "turn error:", err)
		}
	}
}

// dispatchSlash handles the REPL's slash commands. It returns done=true
// when the caller should exit the REPL loop (e.g. /quit), and an error
// for diagnostics that should be printed to stderr but do not terminate
// the session.
func dispatchSlash(line string, ag *agent.Agent, out io.Writer) (done bool, err error) {
	cmd, arg, _ := strings.Cut(line, " ")
	arg = strings.TrimSpace(arg)
	switch cmd {
	case "/quit", "/exit":
		return true, nil
	case "/help":
		fmt.Fprintln(out, "commands:")
		fmt.Fprintln(out, "  /help                       show this list")
		fmt.Fprintln(out, "  /quit, /exit                exit the REPL")
		fmt.Fprintln(out, "  /detect                     show the current shell access-failure detection mode")
		fmt.Fprintln(out, "  /detect default | ptrace    switch detection mode for the run_shell tool")
		return false, nil
	case "/detect":
		if arg == "" {
			fmt.Fprintf(out, "detect mode: %s\n", ag.DetectMode())
			return false, nil
		}
		if err := ag.SetDetectMode(arg); err != nil {
			return false, err
		}
		fmt.Fprintf(out, "detect mode: %s\n", ag.DetectMode())
		return false, nil
	default:
		return false, fmt.Errorf("unknown command %q (try /help)", cmd)
	}
}
