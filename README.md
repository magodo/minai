# minai

This is a PoC to have a built-in sandbox experience for a minimal AI harness.

[![asciicast](https://asciinema.org/a/1219481.svg)](https://asciinema.org/a/1219481)

## Why

Most AI harness has a built-in permission model with permission popups, which works well for most built-in tools (e.g. `read_file`), while it can be easily bypassed for tools that can run unmanaged code (e.g. `run_shell`). Many sandbox solutions today (e.g. `bubblewrap` based ones like `sandbox-rt`, `mxc` used by `Copilot CLI`) requires to setup for which files/directories to access/deny, which sometimes can be hard to figure out upfront. 

I'm trying to combine the permission popup experience with a sandbox solution, to have a streamlined sandbox experience for an AI harness.

## AI Harness

The AI harness here contains the minimal functionality:

- Using a Copilot access token to connect to Copilot provider
- A simple loop with basic toolings: read_file, write_file, list_dir, run_shell

## Sandbox

This project aims on FS sandbox, which [uses](landlock.io) under the hood. The idea is that each time a tool gets invoked, it fork and exec as a child process, restricting itself with the landlock ruleset. When the execution fails due to FS access errors (`EACCES` or `EPERM`), the harness will pops up (one more more times) to ask for permission(s) and rerun, until no new permission granted, or succeed (This requires the execution to be re-entrant).

There is no obvious way to identify failures of the `run_shell` is caused by lack of FS access (as we can only inspect the `stdout/stderr` of the run). There is a `ptrace` mode (invoked by `/detect ptrace`) to enable ptrace to allow the main process to inspect the tool process, especially for those FS syscall failures. This returns a precise of those FS access errors from the tool run.

## Problems

1. The retry loop above requires the `run_shell` execution is re-entrant.
1. Landlock rule granted for a directory applies to all the child items (that's why it officially [recommend to set access rights to file hierarchy leaves as much as possible](https://docs.kernel.org/userspace-api/landlock.html#good-practices)), which might not be what the user wanted. For which, I raised a feature request to landlock to have an exact-inode option: https://github.com/landlock-lsm/linux/issues/60. 
