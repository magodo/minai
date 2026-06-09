---
theme: seriph
title: minai
info: |
  ## minai
  A minimal ReAct-style AI agent with per-call filesystem sandboxing,
  built on Landlock and ptrace.
class: text-center
drawings:
  persist: false
transition: slide-left
mdc: true
---

# minai

A minimal AI agent that asks before it touches your files

<div class="pt-8 opacity-75 text-sm">
  Landlock for the sandbox &middot; ptrace for the shell &middot; ReAct on top
</div>

<div class="abs-br m-6 text-xs opacity-50">
  github.com/magodo/minai
</div>

---
transition: fade-out
---

# The problem

LLM agents need tools. Tools touch the filesystem. **That is the risk.**

A typical agent loop:

1. User types a prompt.
2. The model decides to call `read_file`, `write_file`, `run_shell`, ...
3. The agent runs that call **with the user's own credentials**.

<v-clicks>

- One stray `rm -rf` and your home directory is gone.
- One curl-piped-to-shell and your SSH keys are exfiltrated.
- The model has no idea what it is allowed to touch &mdash; *we* have to tell it.

</v-clicks>

<div v-click class="mt-8 p-4 border-l-4 border-amber-500 bg-amber-500/10">
We want tool calls to be <b>opt-in</b> per path, decided <b>by the human</b>,
and <b>cheap enough</b> that the friction does not break the loop.
</div>

---
layout: two-cols-header
---

# Existing sandbox solutions

What people usually reach for when they want to confine a process.

::left::

**Containers**
- `docker`, `podman`, `nsjail`, `gVisor`
- Strong isolation, but a whole image to manage.
- Heavy for a one-shot tool call.

**User-space sandboxes**
- `bubblewrap`, `firejail`
- Bind-mount magic, setuid helpers, root-ish.
- Great for desktop apps, awkward to embed.

::right::

**Kernel primitives**
- `seccomp-bpf` &mdash; filters syscalls, not paths.
- `chroot` &mdash; trivially escaped, root-only.
- `SELinux` / `AppArmor` &mdash; admin policy, not per-call.

**Tracing / interception**
- `ptrace`, `LD_PRELOAD`
- Powerful but slow / fragile as a sole enforcement mechanism.

<div class="mt-6 text-sm opacity-75">
None of these are wrong &mdash; they just want to own the whole process tree.
A per-tool-call sandbox needs something lighter.
</div>

---
layout: default
---

# What is Landlock?

A Linux LSM (since 5.13) that lets an **unprivileged process restrict itself**.

<div class="grid grid-cols-2 gap-6 mt-4">
<div>

**Properties**
- No root, no capabilities, no setuid helper.
- Rules are **filesystem-path scoped** (RO dirs, RW files, ...).
- **Irrevocable**: once you tighten, you can only tighten further.
- Inherited across `exec(2)` and `fork(2)`.

</div>
<div>

**The shape of a rule**
```go
landlock.V8.BestEffort().RestrictPaths(
    landlock.RODirs("/usr", "/lib", "/etc"),
    landlock.RWFiles("/dev/null", "/dev/urandom"),
    landlock.RODirs(userApprovedReadPaths...),
    landlock.RWDirs(userApprovedWritePaths...),
)
```

After this call, any syscall outside the allow-list returns **`EACCES`**.

</div>
</div>

<div class="mt-6 p-3 border-l-4 border-sky-500 bg-sky-500/10 text-sm">
The irrevocability is the punchline: a sandboxed process cannot widen its
own grant. That is exactly the guarantee we want for an agent's tool call.
</div>

---
layout: default
---

# The idea

One sandboxed subprocess **per tool call**. The user decides what gets unlocked.

<pre class="font-mono text-xs leading-tight bg-gray-500/10 rounded p-3 mt-2">
   ┌──────────────────────────────────────────────────┐
   │ Parent (agent) — builds envelope                 │
   └────────────────────┬─────────────────────────────┘
                        │  fork + exec self (MINAI_TOOL_EXEC=1)
                        ▼
   ┌──────────────────────────────────────────────────┐
   │ Child                                            │
   │  ┌────────────────────────────────────────────┐  │
   │  │ Landlock.RestrictPaths(baseline+approved)  │  │
   │  └────────────────────┬───────────────────────┘  │
   │                       ▼                          │
   │  ┌────────────────────────────────────────────┐  │
   │  │ run the tool handler                       │  │
   │  └────────────────────┬───────────────────────┘  │
   └───────────────────────┼──────────────────────────┘
                           ▼  Result { output, denials[] }
                ┌─────────────────────┐
            no  │     denials?        │  yes
         ┌──────┤                     ├──────┐
         ▼      └─────────────────────┘      ▼
   return to model       prompt user (ro/rw/no),
                         persist for the session, retry
</pre>

<div class="mt-2 p-2 border-l-4 border-emerald-500 bg-emerald-500/10 text-sm">
Default-deny, prompt-on-deny, persist-for-the-session &mdash; the human
authorises each surface exactly once.
</div>

---
layout: default
---

# A wrinkle: the `run_shell` tool

For Go-native tools (`read_file`, `write_file`, ...) Landlock's `EACCES` arrives
as a typed `*fs.PathError` &mdash; **we know the exact path**. `run_shell` exec'd
through `sh -c` only gives us combined output:

```text
ls: cannot access '/etc/shadow': Permission denied
cat: /home/alice/.ssh/id_rsa: Permission denied
```

So the first version does the obvious thing &mdash; **regex the output**:

```go
var permRe = regexp.MustCompile(`['"]?([^\s:'"]+): [Pp]ermission denied`)
```

And the obvious things break:

- **Locale**: `LANG=de_DE.UTF-8` &rarr; `Keine Berechtigung`.
- **Quoting**: `ls`, `cp`, `find` each format paths differently.
- **Partial failures**: many denied paths in one run &rarr; N-round prompt loop.
- **Exit 0 with denials**: should we even prompt? *(spoiler: no)*

---
layout: default
---

# What is `ptrace`?

The original Linux process-tracing API. The way `strace`, `gdb`, and
`rr` see what a child is doing.

<div class="grid grid-cols-2 gap-6 mt-4">
<div>

**What we use**
- `PTRACE_TRACEME` so the child opts in to being traced before its `exec` (via Go's `SysProcAttr.Ptrace = true`).
- `PTRACE_O_TRACESYSGOOD` + `TRACEFORK`/`VFORK`/`CLONE`/`EXEC` to mark syscall stops and follow descendants.
- `PTRACE_SYSCALL` to stop on every syscall entry and exit.
- `PTRACE_GET_SYSCALL_INFO` (Linux **5.3+**) to read the syscall number, arguments, and return value **without** decoding registers ourselves.

</div>
<div>

**What it gives us**
- The exact syscall name (`openat`, `access`, `stat`, ...).
- The full argument list, including path operands.
- The kernel's return value &mdash; including the precise `errno`.
- Visibility into **every descendant** of the traced process.

</div>
</div>

<div class="mt-6 p-3 border-l-4 border-sky-500 bg-sky-500/10 text-sm">
Think of it as a debugger that watches syscalls instead of breakpoints.
We do not change the program's behaviour &mdash; we just record what the kernel told it.
</div>

---
layout: default
---

# `ptrace` solves the shell problem

`run_shell` now has two detection modes, picked at runtime with `/detect`.

<div class="grid grid-cols-2 gap-4 mt-4 text-sm">
<div class="p-3 border border-gray-500/30 rounded">

**`default`** &mdash; regex on stdout/stderr
- Locale-sensitive, quoting-sensitive.
- One denial per retry.
- Zero kernel dependency.

</div>
<div class="p-3 border border-emerald-500/50 rounded bg-emerald-500/5">

**`ptrace`** &mdash; intercept syscalls
- Catches `EACCES` / `EPERM` at the source.
- Resolves `*at()` paths via `/proc/<pid>/fd`.
- Deduplicates per path; upgrades `ro` &rarr; `rw` if needed.
- **All denials in one batch** &rarr; one prompt round.
- Suppresses denials on `exit 0` (those were tolerated probes).

</div>
</div>

<div class="mt-4 p-3 border-l-4 border-emerald-500 bg-emerald-500/10 text-sm">
Both modes funnel into the same downstream pipeline: every denial becomes a
typed <code>*fs.PathError</code> (the ptrace mode aggregates them in a
<code>MultiPathError</code>), and the sandbox layer just walks the error tree.
</div>

---
layout: default
---

# The full picture

<pre class="font-mono text-xs leading-tight bg-gray-500/10 rounded p-3 mt-2">
                              ┌──────────────────────────────┐
                              │     LLM (GitHub Copilot)     │
                              └───────▲──────────────┬───────┘
                                      │              │
                              tool result         tool_call
                                      │              ▼
  ┌──────┐    prompt       ┌──────────┴────────────────────────┐
  │ User │ ──────────────▶ │           REPL / Agent            │
  │      │ ◀────────────── │     + in-memory Access Store      │
  └──────┘    answer       └────────┬─────────────────▲────────┘
                                    │                 │
                                    │ envelope        │ Result
                                    │ JSON            │ { output,
                                    ▼                 │   denials[] }
                            ┌────────────────────────────────────┐
                            │          Sandbox child             │
                            │     Landlock.RestrictPaths(...)    │
                            │     tool handler  (+ ptrace?)      │
                            └────────────────────────────────────┘

  Denial?  ─▶  prompt user (ro/rw/no)  ─▶  persist to access store  ─▶  retry
</pre>

<div class="mt-3 grid grid-cols-3 gap-3 text-xs">
<div class="p-2 border-l-4 border-sky-500">
<b>Landlock</b> is the wall.<br/>Default-deny, opt-in paths.
</div>
<div class="p-2 border-l-4 border-emerald-500">
<b>ptrace</b> is the microscope.<br/>Names the path that hit the wall, even through <code>sh -c</code>.
</div>
<div class="p-2 border-l-4 border-amber-500">
<b>The human</b> is the policy.<br/>One prompt per surface, remembered for the session.
</div>
</div>

---
layout: center
class: text-center
---

# Try it

```bash {class:'!text-left'}
git clone https://github.com/magodo/minai
cd minai && go build ./cmd/minai
export MINAI_COPILOT_TOKEN=...    # GitHub Copilot bearer token
./minai                            # interactive REPL
```

<div class="mt-6 text-sm opacity-75">

In the REPL, `/detect ptrace` switches `run_shell` to syscall-level
denial detection; `/detect default` falls back to the regex mode.

</div>

<div class="mt-10 text-xs opacity-50">
Requires Linux 5.13+ for Landlock V4.<br/>
ptrace detection mode is currently linux/amd64 only.
</div>
