# 0011. Named pipes on Windows, with seven controls

**Status:** Accepted, 2026-10-18, by the maintainer. Built on `api-0.1`. Control 7 follows [0012](0012-privilege-levels.md) and [0015](0015-state-keyed-identity.md).

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
- It passes Windows CI at high and medium integrity, and passed on a Windows 11 machine with UAC on (2026-10-18).
- Remote means another computer, reached through file sharing. Launches from SSH, Remote Desktop and RDS or AVD sessions on the same machine are local, and reach the pipe.
- [0016](0016-windows-address-file.md) has the owner keep `instance.pipe` open, so a delete can't remove it.
