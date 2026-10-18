# 0014. Process ids come from the OS, never from the peer

**Status:** Proposed, 2026-10-18. Built on `api-0.1`; awaiting maintainer review.

## Context

The owner's pid (`OwnerInfo::pid`) and the launcher's pid (`Request::launcher_pid`) let an app raise the right window, or report who is running. A pid that a peer writes about itself can be wrong. Every Flatpak instance runs in its own PID namespace, so a self-reported pid names a different process on the other side.

## Decision

Pids come from the OS: the peer credentials of the socket (`SO_PEERCRED`, `LOCAL_PEERPID`) or the pipe (`GetNamedPipeClientProcessId`). Where the platform doesn't give one, or the peer is in another PID namespace (the OS reports 0), the pid is `None`.

## Why

A wrong pid is worse than none: it can raise, or signal, an unrelated process. `None` makes the app handle the case.

## Consequences

- Inside Flatpak, apps get `None` and must find their window some other way, for example through the activation token.
- `AllowSetForegroundWindow` uses the OS-reported pid ([0011](0011-windows-named-pipes.md)).
