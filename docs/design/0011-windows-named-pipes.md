# 0011. Named pipes on Windows, with seven controls

**Status:** Proposed, 2026-10-18. Built on `api-0.1` and compile-checked only; awaiting maintainer review and Windows CI.

## Context

`sheaf-instance` used AF_UNIX on Windows through `uds_windows`. The folder wasn't checked, the peer wasn't checked, elevated and normal processes mixed, and foreground rights were granted to any process (`ASFW_ANY`). Pipe names are visible to every user on the machine, so on a terminal server a predictable name could be squatted.

## Decision

Named pipes, with seven controls:

1. A random name, 128 bits per owner, published in `instance.pipe` inside the private folder, so other users can't squat it.
2. `FILE_FLAG_FIRST_PIPE_INSTANCE`.
3. A protected DACL that grants access only to the user's SID, with an explicit owner.
4. A mandatory label at the owner's integrity level (no-write-up, no-read-up).
5. `PIPE_REJECT_REMOTE_CLIENTS`.
6. The client opens with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, and checks that the pipe's owner SID is its own, and the pipe's label its own level, before sending anything.
7. A handoff across integrity levels is refused both ways ([0012](0012-privilege-levels.md)). `AllowSetForegroundWindow` names the owner's pid, never `ASFW_ANY`.

## Why

- The owner can read the client's token, which AF_UNIX on Windows doesn't offer.
- Named pipes have no 108-byte path limit and don't need Windows 10 1803.
- .NET, VS Code and Zed use them for the same job.

## Consequences

- About 450 lines of overlapped I/O on `windows-sys`.
- It is written and lint-clean, but nothing has run on Windows yet. Windows CI is a release blocker.
