// Package sandbox runs a single tool invocation in a Landlock-restricted
// subprocess.
//
// The main agent re-execs itself ("/proc/self/exe") with the environment
// variable MINAI_TOOL_EXEC=1 set. The child reads a JSON Envelope from stdin
// describing which tool to run, the JSON args to pass, the lists of
// filesystem paths it is allowed to access (read-only and read-write), and
// the per-call access-failure detection mode. The child applies Landlock to
// itself with a small baseline of system RO paths plus the caller-provided
// allow lists, then executes the tool handler and writes a JSON Result to
// stdout.
//
// On EACCES the Result includes the offending path and the desired mode
// ("ro"/"rw") so the parent can prompt the user and retry. Two detection
// strategies are wired in:
//
//   - A Go-error route (`pathFromError`) that unwraps `*fs.PathError` from
//     handlers that return an error containing one. This works for both
//     direct Go syscall wrappers (read_file, write_file, ...) and for the
//     run_shell tool when it runs under the "ptrace" detect mode and
//     synthesizes a PathError from a ptrace-observed EACCES/EPERM syscall.
//   - A combined-output regex route (`pathFromText`) that matches typical
//     coreutils / shell "Permission denied" lines. This is the fallback
//     for run_shell in its default detect mode.
//
// Landlock self-restriction is irrevocable for the calling process, which is
// why every tool call uses a fresh subprocess.
package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/landlock-lsm/go-landlock/landlock"

	"minai/internal/env"
	"minai/internal/tools"
)

// Envelope is what the parent writes to the child's stdin.
//
// DetectMode is the per-call name of the access-failure detection strategy
// a tool should use. It is currently only consulted by the run_shell tool,
// which supports "default" (regex over the command's combined output) and
// "ptrace" (syscall-level interception via the ptrace package). The empty
// string is treated as "default". Tools that don't care simply ignore it.
type Envelope struct {
	Tool       string          `json:"tool"`
	Args       json.RawMessage `json:"args"`
	AllowedRO  []string        `json:"allowed_ro"`
	AllowedRW  []string        `json:"allowed_rw"`
	DetectMode string          `json:"detect_mode,omitempty"`
}

// Result is what the child writes to its stdout.
type Result struct {
	Output     string `json:"output"`
	Error      string `json:"error"`
	DeniedPath string `json:"denied_path,omitempty"`
	DeniedMode string `json:"denied_mode,omitempty"` // "ro" or "rw"
}

// BaselineRO is the set of system directories we always allow the sandboxed
// child to read+execute so that shared libraries, /bin/sh, etc. continue to
// work. Project / user data paths are NOT in here on purpose.
var BaselineRO = []string{
	"/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc",
	"/proc", "/sys",
}

// BaselineRWFiles are the pseudo-device files standard CLI tools expect to
// be able to open for I/O (stdin/stdout redirections, randomness, etc.).
// Granted as files-only so the sandbox doesn't unlock the whole /dev tree.
var BaselineRWFiles = []string{
	"/dev/null", "/dev/zero", "/dev/full",
	"/dev/random", "/dev/urandom", "/dev/tty",
}

// IsChild reports whether the current process was spawned as a sandboxed
// tool runner. Call this very early in main().
func IsChild() bool {
	return os.Getenv(env.ToolExec) == "1"
}

// Exec spawns a sandboxed child, runs the named tool, and returns the parsed
// Result. It is safe to call concurrently. logger may be nil.
//
// When debug logging is enabled (MINAI_DEBUG=1 in the inherited env), the
// child's stderr is teed through to the parent's os.Stderr so its slog
// records interleave naturally with the parent's. Otherwise stderr is just
// captured in case it's needed for an error message.
func Exec(ctx context.Context, enve Envelope, logger *slog.Logger) (*Result, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("locate self: %w", err)
	}
	payload, err := json.Marshal(enve)
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}

	cmd := exec.CommandContext(ctx, self)
	cmd.Env = append(os.Environ(), env.ToolExec+"=1")
	cmd.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	if debugEnabled() {
		// Tee: keep a copy for diagnostics, but also stream live to our stderr.
		cmd.Stderr = io.MultiWriter(&stderr, os.Stderr)
	} else {
		cmd.Stderr = &stderr
	}

	logger.Debug("spawn sandbox child",
		"tool", enve.Tool, "exe", self,
		"allowed_ro", enve.AllowedRO, "allowed_rw", enve.AllowedRW)

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("sandboxed child failed: %w (stderr=%q)", err, stderr.String())
	}
	var res Result
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		return nil, fmt.Errorf("decode child result: %w (stdout=%q stderr=%q)",
			err, stdout.String(), stderr.String())
	}
	return &res, nil
}

// debugEnabled mirrors the parent CLI flag for the sandbox package without
// pulling in a cross-package dependency.
func debugEnabled() bool {
	return env.Truthy(env.Debug)
}

// auditEnabled reports whether the user asked for Landlock kernel audit
// logging (via -l on the parent, propagated as MINAI_AUDIT=1).
func auditEnabled() bool {
	return env.Truthy(env.Audit)
}

// RunChild is the entry point of the sandboxed subprocess. It reads an
// Envelope from stdin, applies Landlock, runs the tool, and writes the
// resulting JSON to stdout. It always exits the process (success or not).
// logger may be nil.
func RunChild(logger *slog.Logger) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	res := runChild(logger)
	out, _ := json.Marshal(res)
	os.Stdout.Write(out)
	os.Exit(0)
}

func runChild(log *slog.Logger) Result {
	var enve Envelope
	if err := json.NewDecoder(os.Stdin).Decode(&enve); err != nil {
		log.Error("decode envelope", "err", err)
		return Result{Error: "decode envelope: " + err.Error()}
	}
	log.Debug("envelope received",
		"tool", enve.Tool,
		"allowed_ro", enve.AllowedRO,
		"allowed_rw", enve.AllowedRW)

	registry := map[string]tools.Tool{}
	for _, t := range tools.Default() {
		registry[t.Spec.Function.Name] = t
	}
	tool, ok := registry[enve.Tool]
	if !ok {
		log.Error("unknown tool", "tool", enve.Tool)
		return Result{Error: "unknown tool: " + enve.Tool}
	}

	// Apply Landlock. We accept paths that may not exist (IgnoreIfMissing)
	// so the user can pre-approve a planned write target. BestEffort lets us
	// silently degrade on kernels that lack Landlock (the sandbox is then a
	// no-op, but the rest of the wiring still works for testing).
	// Baseline keeps IgnoreIfMissing because the hardcoded system paths
	// legitimately vary across distros / minimal containers (no /lib64,
	// no /dev/full, etc.). User-approved paths skip IgnoreIfMissing: by
	// the time they reach us they've been stat-verified by the parent and
	// further pruned by splitDirsFiles, so anything reaching Landlock is
	// known to exist.
	rules := []landlock.Rule{
		landlock.RODirs(BaselineRO...).IgnoreIfMissing(),
		landlock.RWFiles(BaselineRWFiles...).IgnoreIfMissing(),
	}
	roDirs, roFiles := splitDirsFiles(enve.AllowedRO)
	rwDirs, rwFiles := splitDirsFiles(enve.AllowedRW)
	if len(roDirs) > 0 {
		rules = append(rules, landlock.RODirs(roDirs...))
	}
	if len(roFiles) > 0 {
		rules = append(rules, landlock.ROFiles(roFiles...))
	}
	if len(rwDirs) > 0 {
		rules = append(rules, landlock.RWDirs(rwDirs...))
	}
	if len(rwFiles) > 0 {
		rules = append(rules, landlock.RWFiles(rwFiles...))
	}
	cfg := landlock.V8.BestEffort()
	if auditEnabled() {
		// Library default already logs denials for the originating process on
		// ABI v7+; opt in subprocesses too so a shelled-out child also shows
		// up in the kernel audit stream.
		cfg = cfg.EnableLoggingForSubprocesses()
	}
	if err := cfg.RestrictPaths(rules...); err != nil {
		log.Error("apply landlock failed", "err", err)
		return Result{Error: "apply landlock: " + err.Error()}
	}
	log.Debug("landlock applied",
		"baseline_ro", BaselineRO,
		"baseline_rw_files", BaselineRWFiles,
		"ro_dirs", roDirs, "ro_files", roFiles,
		"rw_dirs", rwDirs, "rw_files", rwFiles,
		"audit", auditEnabled())

	// Expose the per-call detect mode to the tool handler via env var so
	// the Handler signature can stay free of plumbing. Cleared again
	// after the call to avoid leaking into anything that re-reads
	// os.Environ later in the same process (the child exits immediately
	// after, so this is belt-and-suspenders).
	if enve.DetectMode != "" {
		os.Setenv(env.DetectMode, enve.DetectMode)
		defer os.Unsetenv(env.DetectMode)
	}

	output, err := tool.Handler(enve.Args)
	defaultMode := "ro"

	if err != nil {
		log.Debug("tool returned error", "tool", enve.Tool, "err", err.Error(), "output", output)
		if path := pathFromError(err); path != "" {
			mode := modeFromOp(err, defaultMode)
			log.Info("EACCES detected via PathError",
				"path", path, "mode", mode, "err", err)
			// Output is kept too: the Go-native tools always return
			// "" on error so this is a no-op for them, but the
			// run_shell tool's ptrace-mode handler returns the
			// command's combined output alongside a synthesized
			// PathError and we don't want to drop it.
			return Result{
				Output:     output,
				Error:      err.Error(),
				DeniedPath: canonical(path),
				DeniedMode: mode,
			}
		}
		return Result{Error: err.Error()}
	}

	if path := pathFromText(output); path != "" {
		log.Info("EACCES detected via output(stdout+stderr) regex",
			"path", path, "mode", defaultMode, "output", output)
		return Result{
			Output:     output,
			DeniedPath: canonical(path),
			DeniedMode: defaultMode,
		}
	}

	log.Debug("tool succeeded", "tool", enve.Tool, "output_bytes", len(output))
	return Result{Output: output}
}

// pathFromError searches err's tree for an fs.PathError carrying a permission
// denial and returns the offending path.
func pathFromError(err error) string {
	if pe, ok := errors.AsType[*fs.PathError](err); ok && os.IsPermission(pe.Err) {
		return pe.Path
	}
	return ""
}

// modeFromOp inspects fs.PathError.Op to decide whether the access attempt
// was read-only or read-write. Falls back to the caller-supplied default.
func modeFromOp(err error, fallback string) string {
	if pe, ok := errors.AsType[*fs.PathError](err); ok {
		switch pe.Op {
		case "stat", "lstat", "readdir", "readlink":
			return "ro"
		case "write", "mkdir", "create", "remove", "rename", "chmod", "chown", "truncate":
			return "rw"
		}
	}
	return fallback
}

// permRe matches typical shell / coreutils permission errors of the form
// `something: <path>: Permission denied` or `<path>: Permission denied`.
// The path may be wrapped in single or double quotes (as `ls` and similar
// tools do); the optional [`'"] characters are excluded from the capture
// group so the result is the bare path.
var permRe = regexp.MustCompile(`[` + "`" + `'"]?([^\s:` + "`" + `'"]+(?:/[^\s:` + "`" + `'"]+)*)[` + "`" + `'"]?: [Pp]ermission denied`)

func pathFromText(s string) string {
	if !strings.Contains(strings.ToLower(s), "permission denied") {
		return ""
	}
	m := permRe.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func canonical(p string) string {
	if p == "" {
		return p
	}
	if abs, err := filepath.Abs(p); err == nil {
		return filepath.Clean(abs)
	}
	return filepath.Clean(p)
}

// splitDirsFiles partitions paths into directories and regular files based
// on a stat() at call time. Missing paths are dropped silently: a memorized
// approval whose target vanished isn't an error worth aborting on — the tool
// will simply re-hit EACCES and the parent's retry loop can prompt again
// against whatever the current filesystem looks like.
func splitDirsFiles(paths []string) (dirs, files []string) {
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if fi.IsDir() {
			dirs = append(dirs, p)
		} else {
			files = append(files, p)
		}
	}
	return
}
