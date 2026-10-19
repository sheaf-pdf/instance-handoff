# 0015. One owner per state; rights and placement decided separately

**Status:** Proposed, 2026-10-18, by the identity review. Awaiting the maintainer's decisions. If accepted, it replaces the per-level owners of [0012](0012-privilege-levels.md) but keeps that record's principle, and it revisits [0013](0013-root-on-linux.md).

## Context

[0012](0012-privilege-levels.md) gave each privilege level its own owner. On Windows that means a launch from an admin terminal, from Windows `sudo` or from an elevated SSH session becomes a second owner at high integrity. That owner writes the same profile as the normal one. So a request never crossed a level, but the crate's first guarantee (one owner) broke for apps whose state lives in the profile, which is nearly all of them. On Linux, whether a `sudo` launch met an owner depended on whether root happened to be logged in somewhere ([0013](0013-root-on-linux.md)).

A review then traced 90 scenarios: `sudo` and `su`, root logins, terminal services and AVD, elevated standard users, admin terminals, SSH and mosh, CI runners, daemons, containers and others. 76 agents took part, and sceptical verifiers checked 56 load-bearing claims.

## Decision (proposed)

Three separate decisions, in place of one folder rule:

1. **Ownership.** Two launches are the same instance when they share the app id and its kind (windowed or headless), the user, the canonical state folder (or both `State::none()`) and the scope. That set names the instance folder. The owner also holds a guard lock inside the state folder. On one host, no difference in integrity level, session, display or namespace makes a second owner of that state.
2. **Rights.** Only kernel-attested facts decide admission. A request never goes to another user and never goes up. It goes down only when the app sets `hand_down`, and the owner is told what was given up. Otherwise the launch gets `MoreRights` or `OwnerHasMoreRights` at once, naming the owner. A raised launch (Windows full elevation; Unix root reached through `sudo`, `su`, `doas`, `pkexec` or `run0`) doesn't own by default.
3. **Placement.** A windowed app's `start` delivers only where the request's window would appear, and never to another person the kernel can tell apart. This is behaviour, not contract, so it is staged for 0.2.

Recommended for 0.1:

- state-keyed identity with the guard (`Guard::Local`, `Guard::Off`);
- one Windows lock per profile shared by every level, with the owner's level read from a lock byte;
- `hand_down`, `ElevatedOwner`, and the windowed and headless kinds;
- `exclusive()` in place of `Mode`;
- `scope` with a shared guard;
- the set-id and sandbox exclusions;
- refusals that answer at once on the wire;
- a fixed root folder on Linux.

Staged for 0.2 or later: screens and persons, completion (`--wait`), Linux capabilities, `runas /netonly`, and the diagnostics (`Claim::others`, `Guard::Always`).

The review's full API sketch, including the staged parts, is in [0015-api-sketch.md](0015-api-sketch.md).

## Why

- All five independent designs, and all three judges, reached the ownership and rights model.
- No token property tells deliberate elevation from incidental elevation (Microsoft Learn, partly verified). So only the app can decide to drop rights, and the default must not.
- Sessions of one Windows user aren't a security boundary (MSRC ADV190010), so a per-session or per-level owner protects nothing that one shared lock doesn't, while it splits the state.
- The guard catches what folder rules can't: containers, distrobox, bind mounts, and owners that outlive their session. Each was verified with `bwrap` on Linux.
- The placement rules rest on facts that are still unverified: Windows session APIs across RDS sessions, and one GUI session per macOS user. They also travel in optional wire records, which is why they can wait.

## Consequences

- `Builder::new` takes the state, and `AppId` gains a kind. `Mode` and `launcher_pid` go.
- A `.instance-handoff.lock` file appears in the app's state folder. Folders that sync tools manage need `Guard::Off`.
- A shell whose environment points at another state folder gets an owner of its own. Each owner is still the only writer of its state.
- Apps must never replace their state folder, or the owner ends with `End::LostState`.
- Without a display, a windowed app's tests can't own, so they need Xvfb or a test hook.
- The Windows layout depends on a medium process being able to lock a file that a high process created. On GitHub's Windows runner (2026-10-18, the probe in `tests/levels.rs`, run by `just levels`), a medium process with a Basic User token could open, write and lock a high process's file labelled medium or not labelled at all. It could lock a file labelled high (no-write-up) through a read-only handle, but not write it. Byte-range locks conflicted across levels in both directions, so each level reads the other's level byte correctly.
- That runner can't settle it alone. Its user is the built-in Administrator, which UAC exempts, so what it makes at high is owned by the user. On a machine with UAC on, an elevated process's files are typically owned by Administrators instead. That case, and real UAC tokens, need testing on such a machine before the layout freezes.
