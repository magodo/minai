// Command minai is a minimal ReAct-style AI agent using GitHub Copilot as the
// LLM provider.
//
// Usage:
//
//	minai                       # interactive REPL
//	minai -p "your prompt"      # one-shot: run a single turn and exit
//	echo "prompt" | minai -p -  # one-shot: read prompt from stdin
//
// Environment:
//
//	MINAI_MODEL                 # override default model (gpt-4o)
//	MINAI_COPILOT_TOKEN         # Copilot API token (Bearer), required
//	MINAI_COPILOT_ENDPOINT      # override API host (default api.githubcopilot.com)
//	MINAI_YES                   # if set, auto-approve run_shell (use with care)
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	"minai/internal/agent"
	"minai/internal/copilot"
	"minai/internal/tools"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "minai: error:", err)
		os.Exit(1)
	}
}

func run() error {
	var prompt string
	flag.StringVar(&prompt, "p", "", "one-shot prompt; use '-' to read from stdin")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [-p PROMPT|-]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	model := os.Getenv("MINAI_MODEL")
	if model == "" {
		model = "gpt-4o"
	}

	auth, err := copilot.NewAuth()
	if err != nil {
		return err
	}
	client := copilot.NewClient(auth, model)

	// Share one bufio.Reader between the REPL and the agent's confirmation
	// prompts so they don't both buffer-steal from os.Stdin.
	stdin := bufio.NewReader(os.Stdin)
	ag := agent.New(client, tools.Default(), os.Stdout, stdin)

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
	fmt.Printf("minai (model=%s) — type /quit to exit\n", model)
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
		switch line {
		case "":
			continue
		case "/quit", "/exit":
			return nil
		}
		if err := ag.Turn(ctx, line); err != nil {
			fmt.Fprintln(os.Stderr, "turn error:", err)
		}
	}
}
