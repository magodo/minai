//go:build linux && amd64

package ptrace

// This file is the linux/amd64 implementation of Run. It is a refactor of
// the standalone supervisor demo into a library function: instead of
// owning argv / stdio / exit propagation itself, it accepts a fully
// configured *exec.Cmd from the caller and only manages the ptrace
// machinery on top.
//
// The trace loop runs on a dedicated goroutine pinned to its OS thread for
// the lifetime of the trace, because every PTRACE_* request for a given
// tracee must come from the OS thread that first attached to it.

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// pathOperand describes one path argument of a filesystem syscall.
//
//	pathArg   index (0..5) of the register holding the C-string pointer to
//	          this path operand. Maps to rdi, rsi, rdx, r10, r8, r9.
//	dirfdArg  index of the register holding the dirfd that this path is
//	          resolved against (for *at-style syscalls), or -1 when there is
//	          no dirfd and the path is resolved against the cwd.
//
// We only model operands that the kernel actually resolves as paths.
// Arguments like symlink(2)'s target - which is stored verbatim inside the
// new symlink and never path-walked - are deliberately omitted, since the
// absolute-path view we report wouldn't make sense for them.
type pathOperand struct {
	pathArg  int
	dirfdArg int
}

// syscallInfo describes a filesystem syscall we want to monitor: its name
// and the ordered list of its path operands. Most syscalls have exactly
// one operand; rename/link and their *at variants have two.
type syscallInfo struct {
	name     string
	operands []pathOperand
}

func one(pathArg, dirfdArg int) []pathOperand {
	return []pathOperand{{pathArg, dirfdArg}}
}
func two(p1, d1, p2, d2 int) []pathOperand {
	return []pathOperand{{p1, d1}, {p2, d2}}
}

// fsSyscalls is the set of filesystem-touching syscalls we monitor.
// Numbers are Linux x86_64 syscall numbers (see <asm/unistd_64.h>).
//
// For syscalls that take two paths (rename, link, ...) we record both
// operands in argument order. For symlink/symlinkat we only record the
// linkpath: the target is just an opaque string the kernel stores inside
// the new symlink, so resolving it to an absolute path would be misleading.
var fsSyscalls = map[uint64]syscallInfo{
	// Single-path syscalls.
	unix.SYS_OPEN:       {"open", one(0, -1)},
	unix.SYS_OPENAT:     {"openat", one(1, 0)},
	unix.SYS_OPENAT2:    {"openat2", one(1, 0)},
	unix.SYS_CREAT:      {"creat", one(0, -1)},
	unix.SYS_MKDIR:      {"mkdir", one(0, -1)},
	unix.SYS_MKDIRAT:    {"mkdirat", one(1, 0)},
	unix.SYS_RMDIR:      {"rmdir", one(0, -1)},
	unix.SYS_UNLINK:     {"unlink", one(0, -1)},
	unix.SYS_UNLINKAT:   {"unlinkat", one(1, 0)},
	unix.SYS_STAT:       {"stat", one(0, -1)},
	unix.SYS_LSTAT:      {"lstat", one(0, -1)},
	unix.SYS_NEWFSTATAT: {"newfstatat", one(1, 0)},
	unix.SYS_STATX:      {"statx", one(1, 0)},
	unix.SYS_ACCESS:     {"access", one(0, -1)},
	unix.SYS_FACCESSAT:  {"faccessat", one(1, 0)},
	unix.SYS_FACCESSAT2: {"faccessat2", one(1, 0)},
	unix.SYS_CHDIR:      {"chdir", one(0, -1)},
	unix.SYS_READLINK:   {"readlink", one(0, -1)},
	unix.SYS_READLINKAT: {"readlinkat", one(1, 0)},
	unix.SYS_CHMOD:      {"chmod", one(0, -1)},
	unix.SYS_FCHMODAT:   {"fchmodat", one(1, 0)},
	unix.SYS_CHOWN:      {"chown", one(0, -1)},
	unix.SYS_LCHOWN:     {"lchown", one(0, -1)},
	unix.SYS_FCHOWNAT:   {"fchownat", one(1, 0)},
	unix.SYS_TRUNCATE:   {"truncate", one(0, -1)},
	unix.SYS_STATFS:     {"statfs", one(0, -1)},
	unix.SYS_EXECVE:     {"execve", one(0, -1)},
	unix.SYS_EXECVEAT:   {"execveat", one(1, 0)},
	unix.SYS_UTIMENSAT:  {"utimensat", one(1, 0)},
	unix.SYS_MKNOD:      {"mknod", one(0, -1)},
	unix.SYS_MKNODAT:    {"mknodat", one(1, 0)},

	// Two-path syscalls.
	unix.SYS_RENAME:    {"rename", two(0, -1, 1, -1)},
	unix.SYS_RENAMEAT:  {"renameat", two(1, 0, 3, 2)},
	unix.SYS_RENAMEAT2: {"renameat2", two(1, 0, 3, 2)},
	unix.SYS_LINK:      {"link", two(0, -1, 1, -1)},
	unix.SYS_LINKAT:    {"linkat", two(1, 0, 3, 2)},
	unix.SYS_SYMLINK:   {"symlink", one(1, -1)},
	unix.SYS_SYMLINKAT: {"symlinkat", one(2, 1)},
}

// capturedOperand is the on-entry snapshot of a single path operand: the
// pointer into the tracee's address space and the dirfd it would be
// resolved against. We snapshot at entry because the path memory may be
// freed/reused and registers may be clobbered by the time we see the exit
// stop.
type capturedOperand struct {
	pathAddr uintptr
	dirfd    int32
}

// tracee holds per-process bookkeeping.
//
// name is the name of the syscall we entered, or "" if the current syscall
// isn't one we care about. Cleared on every entry and only set when the
// syscall matches fsSyscalls, so at exit time we use it both as the "is
// this an FS syscall?" predicate and as the name to report.
//
// started tracks whether we've ever resumed this tracee with
// PtraceSyscall. New tracees auto-attached via PTRACE_O_TRACE*FORK receive
// an initial SIGSTOP from the kernel - we swallow exactly that first
// SIGSTOP and then flip started to true, after which any further SIGSTOP
// is a real one and gets forwarded.
type tracee struct {
	name     string
	operands []capturedOperand
	started  bool
}

// Run starts cmd under ptrace, captures every failed filesystem syscall
// across the whole process tree, and returns when the root tracee has
// exited. The caller must pre-configure cmd's Path/Args and any desired
// Stdin/Stdout/Stderr; Run sets SysProcAttr.Ptrace itself.
//
// Run intentionally does not call cmd.Wait(): on Linux the runtime's
// wait machinery would conflict with the manual wait4 loop the ptrace
// protocol requires. The exit status of the root process is returned in
// Result.WaitStatus instead. cmd.ProcessState is left nil.
//
// Run blocks until the trace is complete. It is safe to call from any
// goroutine: internally it spawns a dedicated worker pinned to its OS
// thread, which is required for ptrace correctness.
func Run(cmd *exec.Cmd) (*Result, error) {
	if cmd == nil {
		return nil, fmt.Errorf("ptrace: nil cmd")
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Ptrace = true

	type runResult struct {
		res *Result
		err error
	}
	done := make(chan runResult, 1)

	go func() {
		// All PTRACE_* requests for a given tracee must come from the
		// same OS thread that attached to it. Pinning this goroutine to
		// its thread is the simplest way to guarantee that. Goroutine
		// exit (return below) destroys the thread, so we don't leak.
		runtime.LockOSThread()

		res, err := runLocked(cmd)
		done <- runResult{res, err}
	}()

	r := <-done
	return r.res, r.err
}

// runLocked performs the actual trace dance. The caller must have locked
// the goroutine to an OS thread before invoking this function.
func runLocked(cmd *exec.Cmd) (*Result, error) {
	// cmd.Start performs the fork + PTRACE_TRACEME + raise(SIGSTOP) +
	// execve dance on the locked thread. The runtime guarantees the
	// fork is issued by the current OS thread when SysProcAttr.Ptrace
	// is set.
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("ptrace: start: %w", err)
	}
	rootPid := cmd.Process.Pid

	// Wait for the initial post-exec stop. If the exec itself failed,
	// the child won't reach the SIGSTOP and we'll see an exit here.
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(rootPid, &ws, 0, nil); err != nil {
		return nil, fmt.Errorf("ptrace: initial wait: %w", err)
	}
	if !ws.Stopped() {
		// Child exited or was killed before we got to attach. Return
		// what we have so the caller can still surface a meaningful
		// status.
		return &Result{WaitStatus: ws}, nil
	}

	// Configure tracing:
	//   PTRACE_O_TRACESYSGOOD  - report syscall stops as SIGTRAP|0x80
	//                            so we can tell them apart from real
	//                            SIGTRAPs.
	//   PTRACE_O_TRACEFORK/VFORK/CLONE - automatically trace children
	//                            so we don't miss file accesses by
	//                            sub-processes (think `sh -c`, build
	//                            systems, etc.).
	//   PTRACE_O_TRACEEXEC     - get a distinct stop on execve, easier
	//                            to reason about.
	opts := syscall.PTRACE_O_TRACESYSGOOD |
		syscall.PTRACE_O_TRACEFORK |
		syscall.PTRACE_O_TRACEVFORK |
		syscall.PTRACE_O_TRACECLONE |
		syscall.PTRACE_O_TRACEEXEC
	if err := syscall.PtraceSetOptions(rootPid, opts); err != nil {
		// Best-effort: kill the tracee so we don't leak it.
		_ = syscall.Kill(rootPid, syscall.SIGKILL)
		_, _ = syscall.Wait4(rootPid, nil, 0, nil)
		return nil, fmt.Errorf("ptrace: setoptions: %w", err)
	}

	tracees := map[int]*tracee{rootPid: {}}
	var failures []Failure
	var rootStatus syscall.WaitStatus

	// Kick off the first PTRACE_SYSCALL on the root.
	if err := syscall.PtraceSyscall(rootPid, 0); err != nil {
		return nil, fmt.Errorf("ptrace: initial syscall: %w", err)
	}

	// Main loop: wait for any tracee (-1) and dispatch based on stop
	// reason. We exit once all tracees are gone (ECHILD from wait4).
	for {
		pid, err := syscall.Wait4(-1, &ws, syscall.WALL, nil)
		if err != nil {
			if err == syscall.ECHILD {
				break
			}
			if err == syscall.EINTR {
				continue
			}
			return nil, fmt.Errorf("ptrace: wait4: %w", err)
		}

		t, ok := tracees[pid]
		if !ok {
			// We didn't pre-register this pid (either it was created
			// without us being notified, or its first wait4 beat the
			// parent's event stop in our scheduler). Track it now as a
			// fallback.
			t = &tracee{}
			tracees[pid] = t
		}

		switch {
		case ws.Exited() || ws.Signaled():
			if pid == rootPid {
				rootStatus = ws
			}
			delete(tracees, pid)
			continue
		case ws.Stopped():
			sig := ws.StopSignal()
			injected := 0

			switch {
			case sig == syscall.SIGTRAP|0x80:
				// Syscall-stop (entry or exit), thanks to TRACESYSGOOD.
				handleSyscallStop(pid, t, &failures)

			case sig == syscall.SIGTRAP && ws.TrapCause() != 0:
				// PTRACE_EVENT_* stop. For fork/vfork/clone we ask the
				// kernel for the new child's pid via PTRACE_GETEVENTMSG
				// and pre-register a tracee entry, so we're ready when
				// the child's first stop arrives at wait4. For exec we
				// don't need to do anything special;
				// PTRACE_GET_SYSCALL_INFO will keep telling us the
				// correct ENTRY/EXIT op for the new image.
				switch ws.TrapCause() {
				case syscall.PTRACE_EVENT_FORK,
					syscall.PTRACE_EVENT_VFORK,
					syscall.PTRACE_EVENT_CLONE:
					if childPid, err := syscall.PtraceGetEventMsg(pid); err == nil {
						if _, exists := tracees[int(childPid)]; !exists {
							tracees[int(childPid)] = &tracee{}
						}
					}
				}

			case sig == syscall.SIGTRAP:
				// Plain SIGTRAP (e.g. group-stop on a new tracee that
				// hasn't been seen yet). Do not forward.

			case sig == syscall.SIGSTOP && !t.started:
				// Initial auto-attach stop for a fork/clone/vfork
				// child; swallow it. Subsequent SIGSTOPs are real and
				// get forwarded by the default branch.

			default:
				// Genuine signal delivered to the tracee: forward it.
				injected = int(sig)
			}

			// Resume the tracee, asking for the next syscall stop. Any
			// injected signal is delivered on resume.
			t.started = true
			if err := syscall.PtraceSyscall(pid, injected); err != nil {
				// Tracee may have died between the wait and the
				// resume; that's fine - we'll observe its exit on the
				// next wait4.
				if err != syscall.ESRCH {
					return nil, fmt.Errorf("ptrace: ptrace(SYSCALL, %d): %w", pid, err)
				}
			}
		}
	}

	return &Result{WaitStatus: rootStatus, Failures: failures}, nil
}

// handleSyscallStop processes a single syscall-stop for pid. It asks the
// kernel via PTRACE_GET_SYSCALL_INFO whether this is an entry or an exit
// stop and dispatches accordingly:
//
//	entry: if the syscall is in fsSyscalls, snapshot every path operand
//	       (its pointer and dirfd) from info.entry.args for use at exit.
//	exit:  if the saved syscall failed (info.exit.is_error), read each
//	       captured path from the tracee's memory, resolve it, and
//	       append a failure record.
func handleSyscallStop(pid int, t *tracee, failures *[]Failure) {
	var info ptraceSyscallInfo
	if err := getSyscallInfo(pid, &info); err != nil {
		// Best-effort: a failed introspection on one stop shouldn't
		// abort the whole trace. Silently skip; the caller still sees
		// every successfully decoded failure.
		return
	}

	switch info.Op {
	case ptraceSysInfoEntry, ptraceSysInfoSeccomp:
		t.name = ""
		t.operands = t.operands[:0] // reuse backing array

		nr, args := info.entry()
		si, ok := fsSyscalls[nr]
		if !ok {
			return
		}
		t.name = si.name
		for _, op := range si.operands {
			c := capturedOperand{
				pathAddr: uintptr(args[op.pathArg]),
			}
			if op.dirfdArg >= 0 {
				// dirfd is an int; cast through int32 to preserve the
				// sign of AT_FDCWD (-100), which is otherwise
				// 0xFFFFFFFFFFFFFF9C when read as uint64.
				c.dirfd = int32(args[op.dirfdArg])
			} else {
				c.dirfd = unix.AT_FDCWD
			}
			t.operands = append(t.operands, c)
		}

	case ptraceSysInfoExit:
		if t.name == "" {
			return
		}
		rval, isError := info.exit()
		if !isError {
			return
		}
		errno := syscall.Errno(-rval)

		paths := make([]string, len(t.operands))
		for i, op := range t.operands {
			raw, _ := readCString(pid, op.pathAddr)
			paths[i] = resolveAbsPath(pid, op.dirfd, raw)
		}

		*failures = append(*failures, Failure{
			PID:     pid,
			Syscall: t.name,
			Paths:   paths,
			Errno:   errno,
		})

	case ptraceSysInfoNone:
		// Not actually in a syscall (e.g. raised signal-delivery-stop
		// reported as SIGTRAP|0x80 - shouldn't normally happen, but be
		// defensive).
	}
}

// readCString reads a NUL-terminated string from the tracee's address
// space at addr. It uses /proc/<pid>/mem because it is dramatically
// faster than PTRACE_PEEKDATA and works fine while the tracee is stopped.
//
// A short string (<= 4 KiB) is more than enough for any PATH_MAX operand
// (typically 4096 on Linux).
func readCString(pid int, addr uintptr) (string, error) {
	if addr == 0 {
		return "", nil
	}
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/mem")
	if err != nil {
		return "", err
	}
	defer f.Close()

	const max = 4096
	buf := make([]byte, max)
	n, err := f.ReadAt(buf, int64(addr))
	if n == 0 && err != nil {
		return "", err
	}
	if i := bytes.IndexByte(buf[:n], 0); i >= 0 {
		return string(buf[:i]), nil
	}
	return string(buf[:n]), nil
}

// resolveAbsPath turns a (possibly relative) path that a tracee passed to
// a syscall into an absolute path, mirroring how the kernel would resolve
// it. Best-effort: if /proc lookup fails (e.g. the tracee already exited)
// we fall back to returning the raw path.
func resolveAbsPath(pid int, dirfd int32, path string) string {
	if path == "" {
		return ""
	}
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}

	var base string
	var err error
	if dirfd == unix.AT_FDCWD {
		base, err = os.Readlink("/proc/" + strconv.Itoa(pid) + "/cwd")
	} else {
		base, err = os.Readlink("/proc/" + strconv.Itoa(pid) + "/fd/" + strconv.Itoa(int(dirfd)))
	}
	if err != nil {
		return path
	}
	return filepath.Clean(filepath.Join(base, path))
}
