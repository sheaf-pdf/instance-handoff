# 0008. One right runtime folder, never a fallback

**Status:** Proposed, 2026-10-18. Built on `api-0.1`; awaiting maintainer review. The maintainer accepted its consequences for root on Linux ([0013](0013-root-on-linux.md)).

## Context

`sheaf-instance` chose its folder from environment variables (`XDG_RUNTIME_DIR`, then fallbacks). Those variables differ between launches of one user under `sudo`, cron, SSH and session-less starts. In a test of eight launch-context pairs, five produced two owners for one user.

## Decision

Each platform has one rule, and a launch that can't use its one folder runs alone and says why. It never tries a second location. The crate docs ("Where the lock lives") give the rule for each platform. In short:

- Linux with systemd: `/run/user/<euid>/<id>`, only if that folder is a real folder owned by the user with mode 0700. Otherwise `Reason::NoSession`. `XDG_RUNTIME_DIR` is ignored, except inside Flatpak and snap, where the sandbox sets it.
- Linux without systemd, the BSDs and illumos: `/tmp/<id>-<euid>`, created private.
- macOS: the per-user temporary folder from `confstr(_CS_DARWIN_USER_TEMP_DIR)`, not `$TMPDIR`, which is the same for GUI apps, agents, SSH and cron.
- Windows: `<id>\run` under Local AppData, which never roams, with a folder per integrity level ([0012](0012-privilege-levels.md)).

The owner touches its files every hour so that age-based cleaners leave them alone. Every minute it checks that its lock is still in place, re-creates it if it was deleted, and reports `End::LostLock` if another process took over meanwhile.

## Why

Every fallback chain that was tested produced two owners. A fallback only fires when two launches disagree about the environment, and that disagreement is exactly when they end up in different folders. Running alone with a reason is safe, and tells the app what to fix. A second owner corrupts state silently.

## Consequences

- An `@reboot` cron job, or a service started outside a login session, gets `NoSession` on Linux with systemd. The crate docs show how to fix that: lingering, `PAMName=`, or `Builder::dir`.
- A root launch under `sudo` usually gets `NoSession` ([0013](0013-root-on-linux.md)).
- In `sheaf-instance`, a cleaner or `rm` that deleted the lock file let a second owner start, and the second owner then deleted the live owner's socket. Now the owner re-creates its lock within a minute, and if another process became owner in that window, it is told so (`End::LostLock`).
