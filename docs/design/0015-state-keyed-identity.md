# 0015. One owner per state; rights and placement decided separately

**Status:** Accepted with changes, 2026-10-18, by the maintainer. Not built yet. It supersedes [0012](0012-privilege-levels.md), whose principle it keeps, and [0013](0013-root-on-linux.md). The calls on the review's twelve questions are under "The maintainer's calls".

## Context

[0012](0012-privilege-levels.md) gave each privilege level its own owner. On Windows that means a launch from an admin terminal, from Windows `sudo` or from an elevated SSH session becomes a second owner at high integrity. That owner writes the same profile as the normal one. So a request never crossed a level, but the crate's first guarantee (one owner) broke for apps whose state lives in the profile, which is nearly all of them. On Linux, whether a `sudo` launch met an owner depended on whether root happened to be logged in somewhere ([0013](0013-root-on-linux.md)).

A review then traced 90 scenarios: `sudo` and `su`, root logins, terminal services and AVD, elevated standard users, admin terminals, SSH and mosh, CI runners, daemons, containers and others. 76 agents took part, and sceptical verifiers checked 56 load-bearing claims.

## Decision

Three separate decisions, in place of one folder rule:

1. **Ownership.** Two launches are the same instance when they share the app id and its kind (windowed or headless), the user, the canonical state folder (or both `State::none()`) and the scope. That set names the instance folder. The owner also holds a guard lock inside the state folder. On one host, no difference in integrity level, session, display or namespace makes a second owner of that state.
2. **Rights.** Only kernel-attested facts decide admission. A request never goes to another user and never goes up. It goes down only when the app sets `hand_down`, and the owner is told what was given up. Otherwise the launch gets `MoreRights` or `OwnerHasMoreRights` at once, naming the owner. A raised launch (Windows full elevation; Unix root reached through `sudo`, `su`, `doas`, `pkexec` or `run0`) doesn't own by default.
3. **Placement.** A windowed app's `start` delivers only where the request's window would appear, and never to another person the kernel can tell apart. This is behaviour, not contract, so it is staged for 0.2.

For 0.1:

- state-keyed identity with the guard (`Guard::Local`, `Guard::Off`);
- one Windows lock per profile shared by every level, with the owner's level read from a lock byte;
- `hand_down`, `ElevatedOwner`, and the windowed and headless kinds;
- `exclusive()` in place of `Mode`;
- `scope` with a shared guard;
- the set-id and sandbox exclusions;
- refusals that answer at once on the wire;
- a fixed root folder on Linux.

Staged for 0.2: screens and persons, completion (`--wait`) and Linux capabilities. When an app asks: `runas /netonly`, the diagnostics (`Claim::others`, `Guard::Always`, `canonical_path`), and root handing down to the user's owner.

## The maintainer's calls

| # | Question | Call |
|---|---|---|
| 1 | What makes two launches one instance | Accepted |
| 2 | Windows: one lock per state, shared by every integrity level | Accepted. Its precondition was measured on CI and under real UAC ([0015-windows-measurements.md](0015-windows-measurements.md)) |
| 3 | An elevated launch meets a normal owner | Accepted: `MoreRights` at once, and `hand_down` as an app's opt-in |
| 4 | Whether a raised launch may own when nobody does | Accepted: `ElevatedOwner::NotRaised` by default. This adopts, for owning, the exception 0013 deferred. The evidence is installers that start the app elevated from their finish page |
| 5 | Root on Linux | Changed: root gets the fixed folder `/run/instance-handoff`, but a raised launch of a windowed app isn't refused a root owner. Whether it should be waits for placement in 0.2 |
| 6 | Windowed or headless | Accepted, reworded: a kind says who may become the owner, not whether the owner shows windows. Windowed: only a launch that can show windows. Headless: any launch, including a daemon that opens windows for its clients, as Emacs's does. Most single-instance apps are GUIs; a case the two kinds don't fit is revisited when an app needs it |
| 7 | `exclusive()` replaces `Mode` | Accepted |
| 8 | `scope`, with keyed owners sharing the guard; drop the `XDG_SESSION_ID` advice | Accepted |
| 9 | Screens | 0.2. Until then a launch hands off to the owner wherever it is, and the docs say so |
| 10 | Completion (`--wait`, `$EDITOR`, sudoedit) | 0.2, with [0005](0005-replies-later.md) |
| 11 | Linux capabilities | 0.2. Until then the docs keep saying they aren't compared |
| 12 | `runas /netonly`, `Claim::others`, `Guard::Always`, `canonical_path`, root handing down | When an app asks |

The review's full API sketch, including the staged parts, is in [0015-api-sketch.md](0015-api-sketch.md). Where the calls above differ from it, the calls win.

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
- Placement needs a test on a multi-session AVD host before it's built: two users on one host, and one user with two sessions there. Today a launch in one of those sessions hands off to the app in the other, where its window can't be seen. This is beyond 0.1's scope.
- The Windows layout depends on a medium process being able to lock a file that a high process created. On 2026-10-18 this was measured on GitHub's Windows runner and on a Windows 11 machine with UAC on, with the probe in `tests/levels.rs` (`just levels`) and, on the second, a real limited token as well. The details are in [0015-windows-measurements.md](0015-windows-measurements.md).
  - A medium process could open, write and lock a high process's file labelled medium or not labelled at all. It could lock a file labelled high (no-write-up) through a read-only handle, but not write it. A high no-read-up label shut it out.
  - Byte-range locks conflicted across levels in both directions, so each level reads the other's level byte correctly.
  - With UAC on, what high makes is owned by Administrators, not the user as on the runner. That changed none of the results. Access comes from the access list and the label; being the owner only adds the right to read and change the access list.
- So the lock file must be made like the crate's folders are: with an explicit access list for the user, not one inherited from wherever the state lives, and with a medium label or none. It must never sit in, or inherit from, a folder labelled for a higher level.
