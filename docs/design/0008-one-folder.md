# 0008. One right runtime folder, never a fallback

**Status:** Accepted in part, 2026-10-18, by the maintainer. Built on `api-0.1`. Accepted: one folder per platform, never a fallback, and a launch that can't use it runs alone and says why. Which folder each platform uses follows [0015](0015-state-keyed-identity.md), built on `migrate-to-0015` (2026-10-20), as the Decision below now gives it. The maintainer had already accepted its consequences for root on Linux ([0013](0013-root-on-linux.md)).

## Context

`sheaf-instance` chose its folder from environment variables (`XDG_RUNTIME_DIR`, then fallbacks). Those variables differ between launches of one user under `sudo`, cron, SSH and session-less starts. In a test of eight launch-context pairs, five produced two owners for one user.

## Decision

Each platform has one rule, and a launch that can't use its one folder runs alone and says why. It never tries a second location. The crate docs ("Where the lock lives") give the rule for each platform. In short:

- Linux with systemd: `/run/user/<uid>/<id>`, only if that folder is a real folder owned by the user with mode 0700. Otherwise `Reason::NoSession`. `XDG_RUNTIME_DIR` is ignored, except inside Flatpak and snap, where the sandbox sets it.
- Root: `/run/instance-handoff/<id>` on Linux, and `/var/run/instance-handoff/<id>` on the BSDs and illumos, whether or not root is logged in ([0015](0015-state-keyed-identity.md)).
- Linux without systemd, the BSDs and illumos: `/tmp/<id>-<uid>`, created private.
- macOS: the per-user temporary folder from `confstr(_CS_DARWIN_USER_TEMP_DIR)`, not `$TMPDIR`, which is the same for GUI apps, agents, SSH and cron.
- Windows: `<id>` under Local AppData, which never roams. Every integrity level shares it ([0015](0015-state-keyed-identity.md)).

In that folder, the lock is in the instance folder of the state: `i-` and a hash of the state folder and the scope. On Windows each integrity level has its own address folder in the instance folder.

The owner touches its files every hour so that age-based cleaners leave them alone. Every minute it checks that its lock is still in place, re-creates it if it was deleted, and reports `End::LostLock` if another process took over meanwhile. It also checks the state folder's guard, and ends with `End::LostState` when the state folder was removed or replaced.

## Why

Every fallback chain that was tested produced two owners. A fallback only fires when two launches disagree about the environment, and that disagreement is exactly when they end up in different folders. Running alone with a reason is safe, and tells the app what to fix. A second owner corrupts state silently.

## Consequences

- An `@reboot` cron job, or a service started outside a login session, gets `NoSession` on Linux with systemd. The crate docs show how to fix that: lingering, `PAMName=`, or `Builder::dir`.
- A root launch under `sudo` used to get `NoSession` ([0013](0013-root-on-linux.md)). Since [0015](0015-state-keyed-identity.md), root has a fixed folder, and a raised launch hands off to root's owner but doesn't become it by default.
- In `sheaf-instance`, a cleaner or `rm` that deleted the lock file let a second owner start, and the second owner then deleted the live owner's socket. Now the owner re-creates its lock within a minute, and if another process became owner in that window, it is told so (`End::LostLock`).
- On Unix, a launch can become a second owner until the first owner's next check. The maintainer kept the check at once a minute (2026-10-18). The hourly touch keeps age-based cleaners away, so this takes a deliberate `rm`, or an owner that outlives its user's last session, in `tmux` for example. Watching the folder with inotify or kqueue would notice within milliseconds without extra wakeups. That can come later.
- On Windows a held lock can't be deleted, so no second owner starts this way. The address file can be, which [0016](0016-windows-address-file.md) addresses.
