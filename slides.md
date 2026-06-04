---
theme: seriph
background: https://cover.sli.dev
title: minai — A Minimal Landlock-Sandboxed AI Agent
info: |
  ## minai
  A minimal ReAct-style AI agent with built-in, on-demand Landlock sandboxing.
class: text-center
drawings:
  persist: false
transition: slide-left
mdc: true
---

# minai

A minimal, **Landlock-sandboxed** ReAct AI agent

<div class="pt-8 opacity-80">
  <span class="px-2 py-1 rounded bg-white/10">Go</span>
  <span class="px-2 py-1 rounded bg-white/10 ml-2">Linux</span>
  <span class="px-2 py-1 rounded bg-white/10 ml-2">Landlock LSM</span>
  <span class="px-2 py-1 rounded bg-white/10 ml-2">~600 LoC</span>
</div>

<div class="abs-br m-6 text-xl">
  <a href="https://github.com/magodo/minai" target="_blank" class="slidev-icon-btn">
    <carbon:logo-github />
  </a>
</div>

<!--
minai = "minimal AI". The point of this talk is not the agent loop — that's
trivial — but the sandboxing model: how Landlock can give a local AI agent
useful, fine-grained filesystem isolation without forcing the user into a
VM or a container.
-->

---
transition: fade-out
---

# Why sandbox an AI agent?

LLM agents now routinely:

- Read & write files on your behalf
- Run shell commands
- Install packages, edit configs, push code
- Call MCP servers and other agents

<v-click>

The model is **non-deterministic** and **prompt-injectable**:

- A README, a web page, an email — anything in its context — can become an instruction
- One bad tool call can leak SSH keys, exfiltrate `.env`, `rm -rf` a repo
- "Just trust the model" does not scale as agents become more autonomous

</v-click>

<v-click>

> The right question is no longer *"will the agent misbehave?"* but
> *"when it does, what's the blast radius?"*

</v-click>

---

# Sandboxing is the blast-radius control

What we want from a sandbox for an AI agent:

| Property | Why it matters |
|----------|----------------|
| **Filesystem isolation** | The most common damage vector (read secrets / overwrite files) |
| **Network isolation** | Prevent exfiltration to attacker-controlled endpoints |
| **Per-call scope**     | Each tool call should only see what *it* needs |
| **Low friction**       | If it's painful, users disable it |
| **Composable trust**   | The user grants access incrementally, not up-front |

<v-click>

The existing ecosystem clusters around a few patterns. Each makes a different
trade between **isolation strength** and **friction**.

</v-click>

---
layout: two-cols
layoutClass: gap-8
---

# VMs & containers

**Fully isolated environment**

- VMs: Firecracker, QEMU, Cloud Hypervisor
- Containers: Docker, Podman, OCI runtimes
- Managed: E2B, Modal, Daytona, Codespaces, devcontainers

::right::

<div class="pt-12">

**Strengths**

- Strong isolation boundary (kernel or hypervisor)
- Reproducible environments
- Easy network egress control

**Costs**

- Heavy: image pull, cold start, RAM
- The agent works on a *copy* of your code, not your code
- Edits need to be synced back (mounts, git, rsync)
- Editor / shell integration becomes awkward
- "It works in the sandbox" ≠ "it works on my machine"

</div>

---
layout: two-cols
layoutClass: gap-8
---

# Bubblewrap-based sandboxes

**`bwrap` + user namespaces + mount namespaces**

- Examples: `sandbox-rt`, `mxc`, Flatpak's runtime, `bubblejail`
- Build a custom view of the filesystem per invocation
- Bind-mount only what the tool needs; everything else is invisible

::right::

<div class="pt-12">

**Strengths**

- Native performance, no VM overhead
- Strong filesystem & namespace isolation
- Works on the user's real files (via bind mounts)

**Costs**

- Needs unprivileged user namespaces (off on some distros)
- Per-call namespace setup is non-trivial
- Mount view can confuse symlink-following tools
- Granting a new path mid-session means tearing down the namespace

</div>

---

# Where does Landlock fit?

**Landlock** is a Linux LSM (since 5.13, mature in 6.x) for **unprivileged self-sandboxing**.

- A process declares: *"from now on, I can only access these paths, in these modes."*
- The kernel enforces it. No root, no namespaces, no setuid helpers.
- The restriction is **irrevocable** for that process and inherited by children.
- Path-based, mode-aware (`RO files`, `RO dirs`, `RW files`, `RW dirs`, …).

<v-click>

```text
                 ┌──────────────────────────┐
   parent ──fork ┤  child: applies Landlock │── exec tool ──► restricted view of FS
                 └──────────────────────────┘
```

</v-click>

<v-click>

For a **local** AI agent this is almost ideal:

- No image, no namespace, no daemon, no root
- Operates on the user's *actual* working tree
- Per-call granularity: every tool invocation gets its own scope

</v-click>

---

# Landlock vs. the alternatives

| | VM / Container | Bubblewrap | **Landlock** |
|---|---|---|---|
| Isolation strength | ★★★★★ | ★★★★ | ★★★ (FS + a bit more) |
| Startup cost       | high | medium | **negligible** (just `exec`) |
| Works on real files| no (copy / mount) | yes (bind mount) | **yes (direct)** |
| Requires root / caps | sometimes | sometimes (userns) | **no** |
| Per-call scoping   | awkward | possible | **natural** |
| Network isolation  | yes | yes | **partial** (TCP bind/connect, Linux ≥ 6.7) |
| Kernel support     | universal | universal | Linux ≥ 5.13 |

---

# Why this matters for *local* agents

Most coding agents today live in one of two unhappy places:

<div grid="~ cols-2 gap-8" class="pt-4">

<div>

### 🐌 Full sandbox (VM/container)

- Safe, but disconnected from your real editor
- Slow loop: change → sync → run → sync back
- You stop using it because it's annoying

</div>

<div>

### 🔓 No sandbox

- "Approve every tool call?" — fatigue in 5 minutes
- "Approve everything"? — see: every recent agent incident
- Trust is binary instead of incremental

</div>

</div>

<v-click>

Landlock lets us pick a **third point**: native speed, real files,
and a sandbox that the agent itself *participates in* — asking only for
what it needs, when it needs it.

</v-click>

---

# Integrating Landlock into the agent loop

The key insight: **the agent already knows when it needs more access** — the
tool call just returned `EACCES`.

```text
   model ──tool_call──▶ agent ──spawn──▶ landlocked child ──run tool
                          ▲                       │
                          │                       ▼
                          │              EACCES on /home/me/foo
                          │                       │
                          └─prompt user───────────┘
                            "allow /home/me/foo ? [r/w/n]"
```

<v-click>

This turns permission management into a **conversation**, not a config file:

- No allowlist required up-front (a persistent one is still useful — see roadmap)
- The user sees *exactly* which path is needed and *why* (which tool / which call)
- Approvals accumulate per session — the second `read_file` on the same dir is silent

</v-click>

---

# How minai does it — architecture

```text
┌─────────── parent (agent) ────────────┐
│  REPL ─▶ ReAct loop                   │
│            │                          │
│            ▼                          │
│   Copilot Chat API ──tool_calls──┐    │
│                                  ▼    │
│   AccessStore ──ro,rw──▶ sandbox.Exec │
│   (ro/rw paths)        (fork+exec)    │
└──────────────────────────────┬────────┘
                               │ JSON envelope (tool,args,ro,rw)
                     ┌─────────▼────────┐
                     │ child (re-exec)  │
                     │ • apply Landlock │
                     │ • run tool       │
                     │ • JSON result    │
                     └──────────────────┘
```

- One **re-exec'd subprocess per tool call** — Landlock is irrevocable, so each call gets a fresh slate
- Parent keeps a session-scoped `AccessStore` of approved paths (`ro` / `rw`)
- Child gets a tiny baseline (`/usr`, `/lib`, `/bin`, `/etc`, `/dev/null`, …) + caller-approved paths

---

# Inside the child: applying Landlock

The child does the same three steps for every tool call:

```go
// 1. Build the ruleset: baseline + caller-approved paths
rules := []landlock.Rule{
    landlock.RODirs(BaselineRO...).IgnoreIfMissing(),
    landlock.RWFiles(BaselineRWFiles...).IgnoreIfMissing(),
    // ... + env.AllowedRO / env.AllowedRW from the envelope
}

// 2. Self-restrict — irrevocable for the rest of this process
landlock.V8.BestEffort().RestrictPaths(rules...)

// 3. Run the tool *under* the restriction
output, err := tool.Handler(env.Args)
```

The order matters: **restrict first, then run**. Anything the tool touches
after step 2 is filtered by the kernel.

---

# Detecting denials and asking the user

When the tool returns an error, the child tries to extract the offending path:

```go
// 1. Structured: Go's fs.PathError carries Op + Path + Err
if pe, ok := errors.AsType[*fs.PathError](err); ok && os.IsPermission(pe.Err) {
    return Result{DeniedPath: pe.Path, DeniedMode: modeFromOp(err, "ro")}
}

// 2. Unstructured: shell tools just print "foo: Permission denied"
//    permRe captures the path out of stdout/stderr.
if path := pathFromText(output); path != "" {
    return Result{Output: output, DeniedPath: path, DeniedMode: "ro"}
}
```

<v-click>

The parent then prompts the user (`allow ... ? [r/w/n]`), records the
approval in `AccessStore`, and retries the same tool call.

</v-click>

---

# Smart defaults: nearest-existing-ancestor

What if the model wants to `write_file("/home/me/new-dir/out.txt")` and
`new-dir` doesn't exist yet?

- Landlock can't grant access to a path that doesn't exist
- The minimum workable grant is the **nearest existing ancestor** — walk
  upward from the requested path until `stat` succeeds

…and we **surface that to the user** rather than silently widening scope:

```text
  note: /home/me/new-dir/out.txt does not exist; the smallest possible grant
        is rw access on its nearest existing ancestor: /home/me
  allow /home/me? [r/w/n] (default rw):
```

---
layout: center
class: text-center
---

# Demo

<div class="pt-8 text-[12rem] opacity-80">
  <carbon:terminal />
</div>

---

# What's still missing: the `EACCES` ↔ Landlock gap

minai today detects denials by inspecting **the tool's own error**.

That works for `read_file` / `list_dir` / `write_file`. It is **fragile** for `run_shell`:

- Some tools swallow `EACCES` and exit non-zero with a generic message
- Some report the wrong path (`open("a") → /b/a` after a `chdir`)
- A regex over stdout cannot tell *Landlock denied this* from *the file is genuinely 0700 for another user*

<v-click>

We can't distinguish:

```text
cat /etc/shadow         # denied by file perms — legitimate
cat /home/me/.ssh/id_rsa  # denied by Landlock — user should be prompted
```

</v-click>

---

# The fix: `ptrace` for *real* access failures

Idea: the sandbox supervisor `ptrace`s the child and watches syscall exits.

- On any `openat` / `execve` / `stat` returning `-EACCES`, we know **the kernel** said no
- We can read the path argument from the tracee's memory
- We can correlate against `AccessStore` to know whether Landlock was the cause

<v-click>

```text
  syscall  openat(AT_FDCWD, "/home/me/.ssh/id_rsa", O_RDONLY) = -13 EACCES
           │
           ▼
  supervisor: path not in AllowedRO ∪ AllowedRW ∪ Baseline
           → "Landlock denied" → prompt user
           vs
           → "real permission error" → forward to model as-is
```

</v-click>

<v-click>

Bonus: ptrace gives us a syscall-level audit log per tool call — useful for
explaining to the user *what the agent actually did*.

</v-click>

---

# Roadmap

**Done**

- Per-tool-call Landlock sandbox via re-exec
- Interactive, incremental path approvals (`ro` / `rw`)
- Structured + regex-based denial detection

**Next**

- **ptrace-based denial detection** — distinguish Landlock from real `EACCES`
- Persistent per-project approval cache (`.minai/allow.json`)
- Landlock **network rules** (Linux 6.7+: `TCP bind/connect`)
- Per-tool baseline tightening (e.g. `read_file` doesn't need `/dev/tty`)
- MCP tool support, with the same sandbox model

---
layout: center
class: text-center
---

# Takeaways

**Local AI agents need a sandbox that doesn't feel like one.**

<div class="pt-6 text-left max-w-2xl mx-auto opacity-90">

- VMs / containers are too heavy for a fast inner loop on your real files
- Bubblewrap is great but assumes mount-namespace gymnastics
- **Landlock** gives you cheap, per-call, path-scoped restrictions with zero root
- The agent *asks* for access as it discovers it needs it — trust is incremental

</div>

<div class="pt-12 opacity-70">
  <a href="https://github.com/magodo/minai" target="_blank">github.com/magodo/minai</a>
</div>
