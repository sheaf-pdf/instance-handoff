# 0015: requirements

What the accepted records ask to be built for 0.1, with the maintainer's calls applied: the planning run's list, which the slices in [0015-plan.md](0015-plan.md) cite by id. Answers to the questions it raised are in [0015-calls.md](0015-calls.md), and they win where the two differ.

## R01. AppId carries its kind; AppId::new removed

*api; all. Source: 0015 Decision 1, For 0.1 bullet 3, call 6; sketch 'AppId' (lines 25-43) and 'Removed'; notes cut row 'The kind is part of the app'.*

Add `Kind { Windowed, Headless }` (Debug, Clone, Copy, PartialEq, Eq, Hash), `AppId::windowed(&'static str)` and `AppId::headless(&'static str)` as const fns that panic on a bad id, so a bad literal in a `const` is a compile error. Add `AppId::parse(id, kind) -> Result<AppId, InvalidAppId>` and `AppId::kind() -> Kind`. Remove `AppId::new`. The kind is part of an AppId's equality and hash. `as_str` and Display stay the bare id, because folder names, the thread name, the pipe name and instance.pipe use it. Docs use call 6's wording, not the sketch's: a kind says who may become the owner. Windowed: only a launch that can show windows. Headless: any launch, including a daemon that opens windows for its clients, as Emacs's does. The same commit must update all 17 `AppId::new` sites: src/id.rs (tests and the compile_fail doctest), src/server.rs tests, sys/unix.rs and sys/windows.rs tests, the lib.rs and builder.rs doctests, tests/handoff.rs, process.rs, levels.rs (`child_builder` uses `.parse()`), both examples and the README. `FromStr` can't carry a kind (see conflicts).

## R02. State type: State::dir, State::none

*api; all. Source: 0015 Decision 1, For 0.1 bullet 1, Consequences 1; sketch 'State' (lines 45-68); notes cut row 'The state is required'.*

New `pub struct State` with private fields, `State::dir(impl Into<PathBuf>)`, `State::none()`, `impl From<PathBuf>` and `impl From<&Path>`, re-exported. Docs follow sketch lines 47-64. Pass the folder the app's storage layer writes, computed by the same function; environment-following functions isolate env-isolated tests and account-following ones (Windows known folders) don't. An app with several folders passes the one the others derive from. The folder must never be replaced or renamed, though files inside it may be. `none()`: identity is (user, app id, scope), with no guard and no ForeignState check.

## R03. Builder::new(app, state); Mode, Builder::mode and Reason::OwnerRunning removed

*api; all. Source: 0015 Consequences 1, For 0.1 bullet 4, call 7; 0002 status line; sketch 'Builder' and 'Removed'; notes cut rows 1 and 'Batch work'.*

`Builder::new(app: AppId, state: impl Into<State>) -> Builder`. Defaults: Guard::Local, hand_down false, ElevatedOwner::NotRaised, 5 s timeout, payload version 0. Remove `Mode` and its re-export, `Builder::mode`, `Reason::OwnerRunning` and its Display arm, the Separate path in launch.rs (SEPARATE_RETRY at lines 12-14, the branch at 190-201), and the 'Ignores Builder::mode' sentences in the hand_off and probe docs (builder.rs:178-198). The same commit updates every `Builder::new` site: 25 sites in src/owner.rs, lib.rs, builder.rs (the doc example at 28-35 uses Mode), sys/unix.rs, tests/handoff.rs (`builder()` helper; the Separate test at 98-109), process.rs, levels.rs, examples and README.

## R04. scope becomes part of the instance key, with a shared guard

*api; all. Source: 0015 For 0.1 bullet 5, call 8; sketch Builder::scope (lines 87-95), 'Removed' (XDG_SESSION_ID).*

Keep `Builder::scope(impl AsRef<OsStr>)`. The key is hashed with the canonical state into the instance folder name (R24) instead of naming a 16-hex subfolder (naming::scope_folder, builder.rs:160-162). Keyed owners take the state guard shared (R26): they coexist with one another but not with an unkeyed owner or exclusive(). New docs: one owner per (state, key); the app must make concurrent writes to the shared state safe; the key names a runtime meeting point only; never derive a state folder from a session id. Drop the `XDG_SESSION_ID` advice (builder.rs:63-64).

## R05. Builder::guard and Guard { Local, Off }

*api; all. Source: 0015 For 0.1 bullet 1, Consequences 2; sketch Guard (lines 185-203); notes cut row 'State outcomes'.*

`Builder::guard(Guard)` and `#[non_exhaustive] #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)] pub enum Guard { #[default] Local, Off }`. There is no `Always` in 0.1. Local locks the guard on local volumes and skips it on network volumes (NFS, CIFS/SMB, 9p; macOS/BSD without MNT_LOCAL; Windows DRIVE_REMOTE). It then reports `Claim::guarded() == false`, so each host has its own owner, and it never locks a user out after another host crashed. Off is for read-only or shared config and folders under sync tools.

## R06. Builder::hand_down(bool)

*api; all (effective on Windows only in 0.1). Source: 0015 Decision 2, For 0.1 bullet 3, call 3; sketch Builder::hand_down (lines 100-116); notes cut row 'Rights across levels'.*

`Builder::hand_down(self, allow: bool) -> Builder`, default false. It applies to start and hand_off; probe carries no rights. In 0.1 the only right compared is the Windows integrity level (Rights::Level). The docs list admin terminal, Windows sudo, Run as administrator, elevated SSH or WinRM, and UIAccess; they don't list /netonly or Linux capabilities, which are staged. Docs also say: no token property tells deliberate from incidental elevation, so the crate never decides this; set it per call, on a clone, for commands that need no rights; the owner sees Request::handed_down; a request is never handed up and never crosses users; Unix sudo, su, doas, pkexec and run0 reach root's instance.

## R07. Builder::elevated_owner and ElevatedOwner

*api; all. Source: 0015 Decision 2, For 0.1 bullet 3, call 4 (NotRaised default); sketch ElevatedOwner; notes 'Who may own'.*

`Builder::elevated_owner(ElevatedOwner)` and `#[non_exhaustive] #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)] pub enum ElevatedOwner { #[default] NotRaised, NotAboveNormal, Allow }`, documented as in sketch lines 205-225. NotRaised: Windows TokenElevationTypeFull, and Unix root whose person is known and isn't root, don't own; RID 500, UAC off, an elevated OpenSSH logon and root's own login still own. NotAboveNormal: also no owner above medium, though UIAccess (0x2010) may own. Allow: any eligible launch owns, and later normal launches get OwnerHasMoreRights.

## R08. Builder::exclusive() and Exclusive

*api; all. Source: 0015 For 0.1 bullet 4, call 7; sketch Builder::exclusive (lines 177-182), Exclusive (360-364).*

`Builder::exclusive(&self) -> Result<Exclusive, Reason>` and `#[must_use = "dropping an Exclusive releases the state at once"] pub struct Exclusive`, with `state_dir(&self) -> Option<&Path>` and `release(self)`. Drop or process exit releases it. It takes the state guard exclusive, needs no runtime folder, and behaves the same whoever is logged in. It gives StateInUse when any owner, keyed or not, or another exclusive run holds the guard. It never waits and creates no thread. Exclusive is Send + Sync (add to the bounds test). It replaces Mode::Separate for batch subcommands, migrations, cron, CI steps and `--new-instance`.

## R09. Builder::dir and runtime_dir under the new layout

*api; all. Source: sketch Builder::dir (lines 151-163); notes on-disk; 0015 call 2.*

`Builder::dir` replaces the default base, and the instance folder `i-<hex16>` is still added inside it. `Builder::runtime_dir()` returns a path ending in `i-<hex16>` and still creates nothing. On Windows the dir base is shared by every integrity level: it is created with an explicit user access list and no level label, and is no longer refused when another level made it. That reverses builder.rs:84-89 and windows.rs:478-483 (`create_private_dir(&path, true)`, `check_dir(.., made, made)`). The sketch also adds RuntimeDir for a network volume, for root a folder inside another user's tree, and a socket path the OS can't bind (macOS binds up to SOCK_MAXADDRLEN-1). These are sketch-only: see conflicts.

## R10. Level type (Windows integrity level)

*api; all (meaningful on Windows). Source: sketch 'Context, Level, Logon' (lines 300-308); OwnerInfo::level and Rights in notes cut row 'Rights across levels'.*

`#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)] pub struct Level(u32)`, ordered by RID, with consts LOW, MEDIUM, UI_ACCESS, MEDIUM_PLUS, HIGH and SYSTEM, `const fn rid(self) -> u32`, and Display (named levels, otherwise the hex RID). It compiles on every target. OwnerInfo::level and Rights::Level need it. The sketch puts it in context.rs, which is 0.2, so in 0.1 it lives elsewhere and is re-exported. The notes' cut table doesn't name it.

## R11. Rights, Ineligible and Excluded enums

*api; all. Source: sketch 'Outcomes' (lines 318-330); notes cut rows 'Rights across levels', 'Who may own'.*

`#[non_exhaustive] #[derive(Debug, Clone, PartialEq, Eq)] pub enum Rights { Level { launch: Level, owner: Level } }`. NetworkCredentials and Capabilities are staged. `#[non_exhaustive] #[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum Ineligible { Headless, Raised, AboveNormal }`, with Capable and Wait staged for 0.2. `#[non_exhaustive] #[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum Excluded { SetId, Sandboxed }`. Each has Display, which Reason's messages and the 'It will lack {rights}' prompt use.

## R12. New Reason variants; changed Reason docs

*api; all. Source: sketch 'Reason: new and changed variants' (lines 405-439); notes cut rows 'Rights across levels', 'Who may own', 'State outcomes'.*

Add #[non_exhaustive] struct variants: `MoreRights { owner: OwnerInfo, rights: Rights }` (nothing was sent; this launch must not write the state); `OwnerHasMoreRights { owner: OwnerInfo, rights: Rights }`; `MayNotOwn { why: Ineligible }`; `Excluded { why: Excluded }`; `StateInUse { path: PathBuf }` (a holder field is open, see conflicts); `ForeignState { path: PathBuf }` (nothing was created). Each gets Display and Error::source arms, and Reason stays Send + Sync. Changed docs: Peer now means only another user's socket or pipe at this user's address, not another integrity level (outcome.rs:203-210); RuntimeDir drops 'made for another integrity level' and gains R09's cases; NoSession no longer lists su and sudo, is never returned to root, and is never returned from hand_off (R41).

## R13. End::LostState; LostLock narrowed

*api; all. Source: sketch 'End' (line 441); notes cut row 'State outcomes'; 0015 Consequences 4.*

Add `End::LostState`: the guard or the state folder was replaced or removed, so stop writing. `End::LostLock` now applies only under Guard::Off or a skipped guard. An owner that lost only its runtime folder is not ended: it re-creates its address. Add a Display arm. Core::end must let LostState, like LostLock, replace an earlier Stopped (server.rs:208-214). Update Owner::ended docs, Quitting step 3 in lib.rs, and the LostLock checks in the examples.

## R14. OwnerInfo gains level, handed_down and Display

*api; all. Source: sketch OwnerInfo (lines 347-358), Builder::probe (172-176); notes cut row 'Rights across levels'.*

Add `level(&self) -> Option<Level>` (Windows: read from the lock marker; None on Unix), `handed_down(&self) -> Option<&Rights>`, and `impl Display for OwnerInfo` (for example 'pid 4242, high'). confirmed()'s docs change: it is false for an owner the launch reported without talking to it, such as a medium probe of a high owner, and is no longer 'always true from probe' (outcome.rs:55-65). The fields are pub(crate), and the OwnerInfo literals in launch.rs (303, 391, 430) gain the new fields.

## R15. Claim::state_dir, Claim::guarded, Owner::state_dir

*api; all. Source: sketch 'Claim, Owner, Request' (lines 369-386); notes cut rows 1 and 'State outcomes'.*

`Claim::state_dir(&self) -> Option<&Path>` returns the canonical state folder, or None for State::none. Docs say to write state through it, and only while a Claim or an Exclusive exists. `Claim::guarded(&self) -> bool` is false under Guard::Off, on a network volume under Guard::Local, or where locks are unsupported. Add `Owner::state_dir(&self) -> Option<&Path>`, and include these in the Debug impls. `Claim::dir()` and `Owner::dir()` stay; which folder they return on Windows is open.

## R16. Request::handed_down (launcher_pid's fate open)

*api; all. Source: sketch Request (lines 388-399); notes cut row 'Rights across levels'; 0015 Consequences 1.*

Add `Request::handed_down(&self) -> Option<&Rights>`, set by the owner from the client token's integrity level, which the kernel attests. It is None for Request::local and for same-level requests. `map`, Clone and Debug carry it (request.rs:150-218), and `Request::remote` takes it from Session. `launcher_pid` is kept or removed per the conflict on 0015 Consequences 1 against the 0.2 staging of Request::origin.

## R17. Re-exports and thread-bounds test

*api; all. Source: sketch 'Re-exports' (lines 5-14), with staged items dropped.*

lib.rs:339-346 becomes `pub use builder::{Builder, ElevatedOwner, Guard, State}`, `id::{AppId, InvalidAppId, Kind}` and `outcome::{End, Excluded, Exclusive, Ineligible, Level, OwnerInfo, Reason, Rights, Started}`, with owner, payload and request unchanged and Mode gone. The `bounds` test (lib.rs:348-365) adds Exclusive, State and Rights to send_sync. Missing_docs stays clean.

## R18. Wire: the APP record gains the kind byte

*wire; all. Source: sketch 'Wire' (line 456), AppId notes (41-43); notes 'On the wire'.*

HELLO record 2 (APP, wire.rs:36-37, 236, 251-253) carries the owner's kind as well as its id. The encoding and position are open: for example, one kind byte before the UTF-8 id. The launch compares id and kind, and a mismatch is Reason::OtherApp (launch.rs:365-367). The kind is not hashed into the instance folder (see conflicts), so a windowed launch and a headless owner of the same id and state meet there and refuse each other.

## R19. Wire: HELLO LEVEL, STATE and FEATURES records

*wire; all. Source: sketch 'Wire' (lines 457-463); notes 'On the wire'.*

New non-critical HELLO records. Tag 7 LEVEL: the owner's integrity RID as u32 LE, sent by Windows owners (whether Unix sends it is open). Tag 9 STATE: the canonical state path and the scope, in native bytes (encoding open); the launch compares it with its own, and a mismatch means an FNV collision and is refused, never delivered. Tag 11 FEATURES: a bitmap (width open) whose bit 0 means the owner answers refusals with REFUSED and a cause; every 0.1 owner sets it. Bit 1 (WAIT), and tags 8 CONTEXT, 10 EXE and 12 LOGON, are reserved and not sent. Rename the internal `hello::STATE` constant (tag 6, the serving state) so it doesn't clash. server::Ctx (server.rs:45-67) carries the kind, level, state and scope that HELLO sends.

## R20. Wire: critical REQUEST record 0x8A HAND_DOWN

*wire; all (sent on Windows in 0.1). Source: sketch 'Wire' (lines 464-469); 0015 Decision 2; notes 'On the wire'.*

New critical REQUEST record 0x8A HAND_DOWN, carrying the Rights (encoding open: for example, a variant byte plus the launch and owner RIDs as u32 LE). A launch sends it only when it actually hands down, meaning hand_down is set and its level is above the owner's. An older owner refuses it with UNSUPPORTED. An owner admits a client above its own level only with this record. It computes Request::handed_down from the client's token, the attested fact, and treats the record only as the launch's consent. Tags 7 CONTEXT, 8 CWD_FINAL, 9 MNT_NS and 0x8B WAIT are reserved.

## R21. Wire: refusal causes, and unknown codes read as Declined

*wire; all. Source: sketch 'Wire' (line 470); notes 'On the wire'.*

New REPLY refusal codes: 8 PRIVILEGE, which carries the owner's LEVEL in a new REPLY record (tag open); 10 PEER; 11 STATE (meaning open). Codes 9 SCREEN and 12 PERSON are reserved for 0.2. Launch mapping in launch.rs:471-488: PRIVILEGE becomes MoreRights or OwnerHasMoreRights by comparing levels, and PEER becomes Peer. A code the launch doesn't know becomes Declined, where today `_ => WireVersion` (lines 483-486). WIRE, MALFORMED and UNSUPPORTED stay WireVersion.

## R22. Owners never close a refused connection silently

*wire; Unix, Windows. Source: 0015 For 0.1 bullet 7; sketch 'Wire' (line 472); notes 'On the wire'.*

Two places close a launch silently today, leaving it to wait out its timeout and report Unresponsive: the Unix accept() peer-uid mismatch or peer-check error (sys/unix.rs:1333-1345, `continue` before HELLO) and the Windows check_client failure (sys/windows.rs:1531-1537, `c.session.broken()`). Both instead send HELLO, then REPLY REFUSED with a cause (PEER or PRIVILEGE plus the owner's LEVEL), then drain. Session (server.rs:245-267) gains the peer's attested facts (pid and Windows level) and a refused path, and Session::request enforces the level and HAND_DOWN rule. The pre-HELLO close for MAX_CONNECTIONS overflow stays: it is a retry signal.

## R23. Protocol stays version 1, redefined

*wire; all. Source: sketch 'Wire (protocol 1, redefined; nothing is published)'; 0009.*

WIRE_MIN and WIRE_MAX stay 1. The protocol is redefined in place because nothing is published. The commit that changes each message also updates its frozen-byte test (hello_bytes_are_frozen at wire.rs:439, plus R51).

## R24. Instance folder <base>/i-<16 hex>

*on-disk; all. Source: 0015 Decision 1; notes 'On disk'; sketch 'Frozen on disk' (line 477).*

The runtime folder is `<base>/i-<hex16>`: the FNV-1a 64 (naming.rs:10) of the canonical state path and the scope, formatted as hex16. It replaces the scope subfolder, so naming::scope_folder and its test are replaced (naming.rs:73-76, 106-114). The exact preimage (separators, State::none, no scope) must be defined and frozen. HELLO's STATE record (R19) turns a collision into a refusal. It applies on every platform, including inside a Builder::dir base, and on Windows it is the shared key folder (R31).

## R25. Canonical state path

*on-disk; all. Source: 0015 Decision 1 ('canonical state folder'); notes plan step 2; sketch canonical_path doc (lines 16-22).*

State::dir is resolved to a canonical path before anything is named or created: the nearest existing ancestor is resolved and the rest appended. On Unix that is realpath. On Windows it is GetFinalPathNameByHandleW, so SUBST becomes the real path and a mapped drive becomes UNC. The canonical path feeds the instance hash (R24), HELLO STATE (R19), state_dir() (R15), the guard's location (R26) and the ForeignState check (R39). The public `canonical_path` fn is not built (when asked).

## R26. The state guard: <state>/.instance-handoff.lock

*on-disk; all. Source: 0015 Decision 1, For 0.1 bullet 1, Consequences 2 and 8; notes 'On disk' (Guard); sketch 'Frozen on disk' (line 478).*

The owner holds `<state>/.instance-handoff.lock` for its whole life. On Unix it takes flock LOCK_EX|LOCK_NB when unkeyed or exclusive() and LOCK_SH|LOCK_NB when keyed; the file is opened with O_NOFOLLOW|O_CLOEXEC and mode 0600, and is never unlocked explicitly: it is released by closing, so a forked copy can't release it (0006). On Windows it takes LockFileEx on 1 byte at offset 2^31, exclusive or shared, with FAIL_IMMEDIATELY. The Windows file is created with an explicit access list for the user (plus SYSTEM) and a medium label or none, never inheriting from a folder labelled above medium. The name, the Unix modes and the Windows offset are frozen. Dropping a Claim or Owner keeps the guard until exit, like the runtime lock (0006/0007), and release() frees both.

## R27. Linux bases: the five-step rule with a fixed root folder

*on-disk; Linux. Source: 0015 For 0.1 bullet 8, call 5; notes 'On disk' (bases); sketch 'Removed' (root's /run/user/0, /tmp/<id>-0) and 'Frozen on disk' (line 476).*

The Linux rule (sys/unix.rs:123-157) becomes: Flatpak `$XDG_RUNTIME_DIR/app/$FLATPAK_ID/<id>`; snap `$XDG_RUNTIME_DIR/<id>`; root (in-namespace euid 0) `/run/instance-handoff/<id>`, whether or not root is logged in, with /run/instance-handoff created root-only and checked as a real folder not writable by others; another user with systemd `/run/user/<uid>/<id>` when that folder exists and is theirs, otherwise NoSession; without systemd `/tmp/<id>-<uid>`. Root never uses /run/user/0 or /tmp/<id>-0. Call 5 adds nothing beyond the fixed folder: a raised windowed launch is not refused a root owner. The /run/instance-handoff name is pinned by a frozen test.

## R28. BSD root base /var/run/instance-handoff

*on-disk; FreeBSD, NetBSD, OpenBSD, DragonFly. Source: notes 'On disk' (BSD root); sketch 'Removed' and 'Frozen on disk'.*

BSD root uses `/var/run/instance-handoff/<id>`, created root-only, and root never uses /tmp/<id>-0 or /tmp/ih-0. Other BSD and illumos users keep `/tmp/<id>-<uid>`. The non-Linux branch of default_place (sys/unix.rs:201-208) changes accordingly. The root base for illumos (and Android) is unspecified. The name is pinned by a frozen test.

## R29. macOS base resolved with realpath; socket address rule

*on-disk; macOS. Source: notes 'On disk' (macOS); sketch 'Removed' (line 452), Builder::dir (lines 151-158), 'Frozen on disk' (line 476).*

macOS uses realpath(confstr(_CS_DARWIN_USER_TEMP_DIR))/<id>, resolved before it is checked (sys/unix.rs:190-198, 211-227). The sketch also removes the macOS socket fallback folder (short_base, sys/unix.rs:603-619) and binds paths up to SOCK_MAXADDRLEN-1 with a larger sockaddr, giving RuntimeDir beyond that. That part is sketch-only and changes the address contract: confirm it (see conflicts). long_folders_still_get_a_socket runs on macOS CI and must stay green.

## R30. Linux user id from the raw syscall, in the namespace's own view

*on-disk; Linux (raw syscall); Unix (/tmp/ih-0). Source: notes 'On disk' (Linux user), plan step 3; sketch 'Removed' (/tmp/ih-0).*

euid() (sys/unix.rs:33-36) reads the effective uid with the raw syscall (SYS_geteuid, or SYS_geteuid32 on 32-bit ABIs), so fakeroot's LD_PRELOAD can't fake it, and never maps it through uid_map. It is used for folder names, ownership checks (check_trusted, check_private) and the peer-uid comparison. Root's `/tmp/ih-0` short socket base goes; other users keep `/tmp/ih-<uid>` where /proc/self/fd can't shorten the path. fakeroot probably also fakes stat ownership, so the ownership checks may need raw stat too (see conflicts).

## R31. Windows layout: one key folder shared by every level; lock bytes; per-level address folders

*on-disk; Windows. Source: 0015 Decision 1, For 0.1 bullet 2, call 2, Consequences 7-8; notes 'On disk' (Windows layout); sketch 'Removed' (line 450), 'Frozen on disk' (line 479); 0015-windows-measurements.md; 0016 Consequences last bullet.*

The base is `<LocalAppData>\<id>`, refused when it resolves into another user's profile. Inside it is one key folder per profile, state and scope, `i-<hex16>`, created with an explicit access list (user and SYSTEM) and an explicit ME NWNR label, and shared by every integrity level. It holds `instance.lock`, created with an explicit access list and a medium label or none: an exclusive LockFileEx on byte 0 means ownership, and the owner also exclusively locks one byte at offset = its level's RID, the level marker. Each level keeps an address folder labelled at its level NWNR (`run`, `run-high`, `run-low`, `run-system`, `run-<hex rid>`; naming::level_folder and level_folders_are_frozen stay) that holds only `instance.pipe`. 0016's rule applies there: the owner holds the file open, sharing only reads. This replaces per-level folders as lock holders: default_place's level subfolder (windows.rs:301-328), `Place.shared` and the level checks in check_dir, check_pipe_owner and check_client.

## R32. Windows marker probe

*behaviour; Windows. Source: notes 'On disk' (marker probe); 0015 For 0.1 bullet 2; 0015-windows-measurements.md (cross-level lock rows).*

A launch that finds byte 0 of instance.lock held learns the owner's level from kernel lock state, not from a file it must trust. It probes the marker with a shared LockFileEx and FAIL_IMMEDIATELY at each known RID offset, and a lock violation at offset RID means the owner runs at that level; it undoes each successful probe at once. Byte 0 held with no marker yet means an owner still starting: retry until the deadline. The probe gives OwnerInfo::level, and drives the rights decision (R34) and probe across levels (R42). The set of RIDs probed and the order in which an owner takes byte 0 and its marker must be fixed (see conflicts).

## R33. Admission order for start, hand_off and probe

*behaviour; all. Source: notes 'Who may own' (admission); 0015 Decision 2-3, call 9.*

Admission runs in order. 1: app, kind and versions (HELLO id and kind, wire version, payload version, and STATE equality against collisions). 2: the user (Unix peer uid; Windows pipe owner SID and client SID). 3: rights, never up and down only with hand_down (Windows level only in 0.1). 4: person and screen, for a windowed start only, which is 0.2 and not built, so until then a launch hands off to the owner wherever it is. start runs all built checks, hand_off the first three, probe the first two.

## R34. Rights across Windows levels: MoreRights, OwnerHasMoreRights, hand_down

*behaviour; Windows. Source: 0015 Decision 2, For 0.1 bullet 3, call 3; 0011 controls 6-7; sketch Builder::hand_down, probe, Reason::MoreRights/OwnerHasMoreRights.*

From the marker level (R32), a launch below the owner's level gets OwnerHasMoreRights at once, naming the owner (level, pid None) and the Rights::Level, without connecting; it can't read run-high anyway. A launch above the owner without hand_down gets MoreRights at once, with nothing sent. A launch above the owner with hand_down connects through the owner's level address folder and sends HAND_DOWN. The client accepts a pipe labelled at the owner's marker level instead of requiring its own level (check_pipe_owner, windows.rs:737-768). The owner admits a higher client only with HAND_DOWN and refuses a lower one with PRIVILEGE (check_client, windows.rs:804-829). It delivers with Request::handed_down = Some(Rights::Level { launch, owner }), and the launch's OwnerInfo::handed_down matches. AllowSetForegroundWindow still names the owner's pid. On Unix in 0.1 no rights differ within a uid: capabilities aren't compared.

## R35. Who may own: MayNotOwn

*behaviour; all. Source: 0015 Decision 2, call 4, call 6; notes 'Who may own'; sketch ElevatedOwner, Reason::MayNotOwn.*

A start that may not own never takes the runtime lock. It hands off where it may (to an owner at its own level, or down with hand_down) and otherwise runs alone at once with MayNotOwn. The cases: a windowed app's launch that can't show windows gives Ineligible::Headless (call 6); a raised launch under NotRaised gives Raised; under NotAboveNormal any Windows token above medium, except UIAccess, gives AboveNormal; Allow lets any eligible launch own. A headless app's launch may always own. hand_off and probe are unaffected, since they never own.

## R36. Detecting a raised launch

*behaviour; Unix, Windows. Source: 0015 Decision 2, call 4; 0013 'Deferred' (adopted for owning); notes plan step 3; sketch ElevatedOwner::NotRaised doc.*

On Windows a launch is raised when its TokenElevationType is TokenElevationTypeFull. RID 500, UAC off and an elevated OpenSSH logon (TokenElevationTypeDefault) are not raised. On Unix it is euid 0, by the raw syscall, with a known person who isn't root: SUDO_UID, PKEXEC_UID, DOAS_USER (a name resolved to a uid) and, on Linux, /proc/self/loginuid when it isn't the unset value 4294967295. Root's own login is not raised. This only restricts owning; it never admits. A pure function over gathered facts (like linux_rule) makes it table-testable.

## R37. Detecting whether a launch can show windows (windowed kind)

*behaviour; all. Source: 0015 call 6, Consequences 5; notes 'Who may own'.*

An internal check decides whether this process can show windows, gating ownership of a windowed app. Context::can_show_windows is 0.2, so 0.1 needs its own rule per platform; candidates are a non-empty WAYLAND_DISPLAY or DISPLAY on Linux and the BSDs, session graphic access on macOS, and on Windows not session 0 and a visible window station. The rule is undecided (see conflicts). A pure, table-tested function.

## R38. Exclusions: set-id and sandboxed tokens

*behaviour; Unix, Windows. Source: 0015 For 0.1 bullet 6; notes 'Who may own' (Excluded); sketch Excluded.*

Excluded { why: SetId } covers a Unix process whose real and effective uid or gid differ (and AT_SECURE on Linux). Excluded { why: Sandboxed } covers a Windows token at Low integrity (below medium), in an AppContainer, or with restricting SIDs (IsTokenRestricted). Such a process can't take part at all. This replaces 0012's 'below medium runs alone with RuntimeDir' (lib.rs:181-183). The SAFER Basic User token that test-at-medium.ps1 and levels.rs children use must not count as Sandboxed.

## R39. ForeignState before anything is created

*behaviour; all. Source: sketch Builder::new doc (lines 78-84), Reason::ForeignState; notes plan step 2.*

Before any folder or file is created, a State::dir folder, or the nearest existing ancestor it would be created in, that belongs to another user gives ForeignState. That catches root given the user's HOME (macOS sudo, sudo -E, su -m) and an SMAA given the user's %APPDATA%. On Windows a folder owned by Administrators counts as the user's, because UAC makes high's files owned by Administrators (measured). There is no check for State::none.

## R40. Guard admission in start; StateInUse; network volumes

*behaviour; all. Source: 0015 Decision 1, For 0.1 bullets 1 and 5; notes plan step 2; sketch Builder::new doc, Guard, Reason::StateInUse.*

start takes the runtime lock first, which decides the owner among launches of one instance, then the guard. If the guard is held, it releases the runtime lock without binding an address and returns StateInUse at once: another container, an exclusive run, or an owner whose address is being re-created. Under Guard::Local the guard is skipped, and guarded() is false, on a network volume (Linux statfs f_type NFS, SMB, SMB2, CIFS, 9p and the like; macOS and BSD statfs without MNT_LOCAL; Windows GetDriveTypeW DRIVE_REMOTE or a UNC path) and where locks are unsupported (ENOLCK, EOPNOTSUPP). Guard::Off and State::none take no guard. A keyed owner takes it shared, so a keyed start against an unkeyed owner, or the reverse, gives StateInUse.

## R41. hand_off without a runtime folder checks the guard

*behaviour; all. Source: sketch Builder::hand_off doc (lines 167-171), 'Changed' NoSession (line 436).*

hand_off never returns NoSession. Without a runtime folder (no /run/user/<uid>, say), it reports NoOwner when the guard is free and StateInUse when it is held. Today `b.place()?` returns NoSession (launch.rs:239). This is sketch-only (see conflicts).

## R42. probe is never refused for rights

*behaviour; Windows (others unchanged). Source: sketch Builder::probe (lines 172-176); notes 'Who may own' (probe runs the first two).*

A probe of an owner at another level returns Ok(info) with info.level() set to the owner's level (for example Some(Level::HIGH)) and confirmed() false, without connecting. A probe at the same level is as today. probe runs only admission checks 1 and 2.

## R43. Owner upkeep: the guard is the authority; LostState

*behaviour; all. Source: notes 'On disk' (Guard: 'an owner that still holds it re-creates a lost address'), plan step 2; sketch End (line 441); 0008 Decision.*

While the owner holds the guard, its once-a-minute check (sys/unix.rs:1231-1317 check_lock; windows.rs:1629-1663 check_address) re-creates a lost runtime folder, lock and address. It retries while a passing launch briefly holds the runtime lock in the re-made folder, since that launch then gets StateInUse and lets go. It ends with End::LostState when the guard path or the state folder no longer names what it holds (device and inode, or the Windows file id), and LostLock is reported only under Guard::Off or a skipped guard. On Unix the hourly touch doesn't extend to the state folder. On Windows the guard is held open; whether that handle shares delete is open.

## R44. Refusals return at once

*behaviour; all. Source: 0015 For 0.1 bullet 7; notes 'On the wire'; sketch Builder::start doc (line 165).*

Every refusal the design defines (MoreRights, OwnerHasMoreRights, MayNotOwn, Excluded, StateInUse, ForeignState, OtherApp for a kind mismatch, the STATE collision, PRIVILEGE and PEER from the owner) returns at once and never waits out the timeout to Unresponsive. That rests on R22 (no silent close) and R32/R34 (rights decided from the marker before connecting). The Guarantees bullet 'failures that waiting can't fix return at once' (lib.rs:69-71) then holds across levels.

## R45. Crate docs rewritten for 0015

*docs; all. Source: notes plan step 7; 0015 calls 9 and 11, Consequences 2-5; sketch Usage.*

Rewrite Guarantees: at most one owner per (app and kind, user, canonical state, scope) on a host, whatever the integrity level, session, display or namespace; Alone, MoreRights and the rest must not write the state; LostState. Rewrite 'Where the lock lives' (bases including root, i-<hash>, the guard, the Windows key folder) and Privileges (never up, down only with hand_down, NotRaised, Excluded; capabilities still not compared, call 11). Add a State section with recipes: admin terminal, ask then hand_down; batch, exclusive; CI, where a windowed app's tests need a display such as Xvfb, and env-isolated tests. Update 'Daemons, services and cron' (root's fixed folder; hand_off reports NoOwner or StateInUse), 'Containers and sandboxes' (the guard; Flatpak pids), 'The contract between builds' (i-<hash>, guard, Windows bytes 0 and RID, address folders, new records), and 'Not covered' (screens: a launch hands off to the owner wherever it is, call 9; completion, call 10). Update the top example (Builder::new(APP, state), AppId::windowed) and every doctest. Per-item docs come with R01-R16.

## R46. README update

*docs; all. Source: notes plan step 7; README.md.*

Update the code example (AppId::windowed or headless, Builder::new(APP, State::dir(..)), and the Alone(MoreRights) handling), the 'How it works' bullets ('Only the same user, at the same privilege level' and 'One right folder' become one owner per state, rights and hand_down, the guard, the fixed root folder), and the Status section, whose 'no test has run on Windows' (README.md:33) has been stale since Windows CI passed.

## R47. CHANGELOG Unreleased entry

*docs; all. Source: CHANGELOG.md; task rules (docs per change).*

Revise these bullets. API: Builder::new(app, state), AppId kinds, exclusive in place of mode, hand_down, ElevatedOwner, Guard. Privileges: becomes one owner per state, MoreRights and OwnerHasMoreRights, raised launches don't own. Folders: i-<hash>, root's fixed folder, the guard. Windows: one lock per state shared by every level, and drop 'Not yet run on Windows'. The opening sentence that this release meets sheaf-instance builds on the same lock becomes false with i-<hash> and the Windows key folder (see conflicts).

## R48. Examples moved to the new API

*docs; all. Source: sketch 'Usage' (lines 508-516); 0015-windows-measurements.md (cli example).*

examples/cli.rs (`com.example.notes`, the one the measurements used) and examples/tokio.rs move to AppId::headless, Builder::new(APP, State::..), and LostState handling alongside LostLock. cli.rs's `status` and `stop` follow the sketch's daemon pattern: probe, and hand_down(true) for commands that need no rights. Optionally an exclusive() batch command. The state folder an example uses, with no `dirs` dependency, is open.

## R49. Frozen on-disk test vectors

*tests; all. Source: notes plan step 1; 0009; sketch 'Frozen on disk'.*

Add tests pinning instance-folder names (`i-` plus hex16) for several (state, scope) pairs, including State::none and no scope; this replaces scope_folders_are_frozen. Pin the guard name `.instance-handoff.lock`, the Windows guard offset 2^31, instance.lock byte 0 and the marker-at-RID rule, and the root bases /run/instance-handoff and /var/run/instance-handoff. Keep level_folders_are_frozen. Each lands in the commit that defines the name.

## R50. Frozen wire bytes for every message

*tests; all. Source: 0009 Decision ('The other messages have no such test yet'); notes 'Follow-ups'.*

Update hello_bytes_are_frozen for the kind byte and the LEVEL, STATE and FEATURES records. Add frozen-byte tests for REQUEST (with and without HAND_DOWN), READY, COMMIT and REPLY (taken, busy, declined, gave-up, REFUSED with a cause and the owner's LEVEL). 0009 notes that only HELLO is pinned today; request_and_reply_round_trip (wire.rs:466-492) pins one REPLY.

## R51. Unit tables for the new rules

*tests; all. Source: notes plan step 6 ('Unit tables for the folder rules').*

Extend the_linux_folder_rule (sys/unix.rs:1440) with root, an in-namespace euid 0, sudo -E and a snap. Add tables for raised detection (env vars, loginuid, Windows elevation types), owning eligibility (kind × can-show-windows × raised × ElevatedOwner), network-volume classification, the refusal-code mapping (unknown becomes Declined), the Session refused path and HAND_DOWN admission (server.rs tests), and STATE collision refusal.

## R52. Integration tests migrated, plus guard and state tests

*tests; all. Source: notes plan step 6; 0015 Consequences 4.*

Port tests/handoff.rs and process.rs to Builder::new(APP, state) with AppId::headless and a per-test state folder. `owner.dir() == dir.path` (handoff.rs:65) and scopes_make_separate_owners change. Replace the Separate test with exclusive(): StateInUse beside an owner, owners refused beside an exclusive run. Add: keyed against unkeyed guards; Guard::Off; ForeignState (a state whose nearest ancestor belongs to root); LostState when the state folder is replaced; an owner re-registering after its runtime folder is deleted while it holds the guard (adapting a_deleted_folder_is_re_created and an_owner_whose_lock_was_taken_ends_with_lost_lock, Unix 391-441); hand_off with no runtime folder; a kind mismatch giving OtherApp; Request and OwnerInfo handed_down being None at one level. Update the Windows a_live_owners_folder_and_address_stay_put paths (handoff.rs:445-462).

## R53. Cross-process tests that refusals arrive at once

*tests; all. Source: notes plan step 6 ('Cross-process tests that refusals arrive at once').*

In tests/process.rs, add owner-process cases where a refused launch returns within a short bound rather than its timeout: a kind mismatch, the payload version, StateInUse from a guard held by another process, an exclusive run in another process, and on Windows the levels.rs cases in R55. Optionally an owner refusing a raw connection with REFUSED (PEER) instead of a silent close.

## R54. bwrap and fakeroot tests (Linux)

*tests; Linux. Source: notes plan step 6 (bwrap tests).*

Linux tests that skip, with a message, when bwrap, fakeroot or unprivileged user namespaces are missing, so `just ci` stays green anywhere. They cover: container root meets the host; a distrobox-style split (different /run, shared state) gives StateInUse; fakeroot hands off to the user's owner. (Re-registering after a folder delete and LostState for a replaced state folder are covered in R52 without bwrap.)

## R55. tests/levels.rs flipped from 0012 to 0015 behaviour

*tests; Windows. Source: 0015 calls 2-4; 0015-windows-measurements.md; task ('levels.rs flipping'); notes plan step 8.*

On the runner, high is RID 500 and not raised, so it owns. a_medium_launch_never_hands_off_to_a_high_owner (98-126) becomes: the medium child gets OwnerHasMoreRights at once, and its probe returns Ok with level HIGH and confirmed false. a_high_launch_never_hands_off_to_a_medium_owner (128-157) becomes: high's start and hand_off give MoreRights at once, not their own owner or NoOwner, and with hand_down(true) high hands off while the child reports the request handed down. a_folder_made_at_one_level_is_refused_at_the_other (159-203) becomes: a Builder::dir base made at either level is shared, so the result is OwnerHasMoreRights or MoreRights, not RuntimeDir. The children (child_owner, child_launch, child_builder) take a kind and state from env vars. Assertions on `run-high` and `\run` paths change. Optionally extend the ignored probe to check the crate-built layout (key folder, instance.lock, guard). Windows unit tests windows.rs:1670-1748 change too: the_default_folder_passes_the_check, folders_this_crate_makes_are_private_and_labelled, and a_folder_made_for_another_integrity_level_is_refused for the base. test-at-medium stays green.

## R56. 0006 follow-up: fork test

*tests; Unix. Source: 0006 Consequences 2; notes 'Follow-ups'.*

A Unix test that starts, forks, and has the child drop its copy of the Claim (and of the guard) and _exit. The parent must still own: another launch hands off to the parent, and the lock and guard stay held. 0006 says 'No test covers this yet'.

## R57. 0004 follow-up: owners that die after the commit point

*tests; all (kill-based). Source: notes 'Follow-ups' (0004); 0004 Consequences 2.*

Add to an_owner_killed_after_the_commit_leaves_the_launch_to_take_over (process.rs:284-301), which covers start taking the lock: a new owner (another nonce) appearing after the death, so the launch hands off to it (after_commit, launch.rs:290-328), and the hand_off path (may_own false) reporting an unconfirmed HandedOff.

## R58. CI keeps every job green; optional tools

*ci; Linux, macOS, Windows. Source: task rules; notes plan step 8 and 'Still to verify'.*

just ci, the Linux, macOS and Windows jobs (high, medium and the levels probe) and MSRV 1.85 stay green after each slice. If R54 runs in CI, the Linux job installs bubblewrap and fakeroot, and possibly relaxes Ubuntu's restriction on unprivileged user namespaces; otherwise those tests skip. New windows-sys APIs (TokenElevationType, IsTokenRestricted, TokenIsAppContainer, GetFinalPathNameByHandleW, GetDriveTypeW, and window-station calls if used) may need features added to Cargo.toml. Plan step 8's 'medium against high through a second admin' job is open.

## R59. Records 0015 and the design index

*records; all. Source: task rules; docs/design/README.md; 0015 status.*

When 0015's items land, update its status line from 'Accepted with changes, not built' to built, with commits and CI evidence, and the docs/design/README.md table row. Update 0015-windows-measurements.md, whose 'Not measured: 0015's layout itself, which isn't built' changes once levels.rs exercises the built layout.

## R60. Records 0002, 0008 and 0009 brought to 0015's details

*records; all. Source: 0002, 0008, 0009 status lines ('details follow 0015'); task rules.*

0002: the Builder's arguments are now (app, state), and mode is replaced by exclusive (Decision bullet 1). 0008: the folder per platform, including root and the Windows key folder; consequence 2 ('a root launch under sudo usually gets NoSession') is no longer true; LostLock against LostState. 0009: the frozen list becomes i-<hash> in place of the scope subfolder, the guard, Windows byte 0 plus the RID marker and the address-only run* folders; it names the new frozen tests; consequence 2 about meeting sheaf-instance builds changes. Each status line notes it is built. Update the README index statuses.

## R61. Records 0011, 0016, 0010, 0014, 0006, 0004 and 0001 touched as behaviour lands

*records; all. Source: 0011 status ('Control 7 follows 0012 and 0015'); 0016 Consequences last bullet; 0010; 0014; 0006; 0001; task rules.*

0011: control 6 (the client checks the pipe's label against the owner's marker level) and control 7 (never up, down only with hand_down, refused at once). 0016: its last consequence names run*\instance.pipe in the key folder. 0010: the guard adds LOCK_SH and a shared LockFileEx at 2^31; restate 'never write to the lock file' if guard text comes. 0014: the launcher_pid wording if it is removed. 0006: the fork test now exists. 0004: the after-commit tests. 0001: its in-scope definition (same user, same privilege level, same runtime folder) is stale after 0015, and needs a correction or a pointer.

## Out of scope

- **Screens enum, Builder::screens, Reason::OtherScreen, Placement, OwnerInfo::placement, REPLY refusal 9 SCREEN**: Call 9: staged for 0.2. Until then a launch hands off to the owner wherever it is, and the docs say so (covered in R45).
- **Context with its ~20 accessors (current, named, headless, wayland, x11, same_screen, screen_key, ...), Builder::context, Owner::set_context, OwnerInfo::context, HELLO 8 CONTEXT, REQUEST 7 CONTEXT**: Placement is 0.2 (0015 Decision 3, call 9; notes cut row 'Placement'). Level is pulled out on its own because 0.1 needs it (R10).
- **Request::origin (the replacement for launcher_pid)**: Notes cut row 'Placement' stages it for 0.2. See the launcher_pid conflict.
- **Reason::OtherPerson, REPLY refusal 12 PERSON, person comparison, refusing a raised windowed launch a root owner**: Call 5 kept only the fixed root folder: a raised windowed launch is not refused a root owner, and whether it should be waits for placement in 0.2.
- **Completion: Builder::wait, wait_timeout, Completion, Finish, OwnerInfo::finish, Request::completion, REQUEST 0x8B WAIT, FEATURES bit 1, message kind 6 FINISH, Ineligible::Wait, Busy covering a held-wait cap**: Call 10: 0.2, with 0005 (Deferred).
- **Linux capabilities: Builder::privileged_owner, Rights::Capabilities, Ineligible::Capable, Context::capabilities**: Call 11: 0.2. The docs keep saying capabilities aren't compared.
- **runas /netonly: Rights::NetworkCredentials, Logon, HELLO 12 LOGON**: Call 12: when an app asks.
- **Claim::others and Sibling**: Call 12: diagnostics, when an app asks.
- **Public canonical_path()**: Call 12: when an app asks. Internal canonicalization of the state path is still needed (R25).
- **Guard::Always**: Call 12: when an app asks. Guard is #[non_exhaustive], so it can be added later.
- **Root handing down to the user's owner**: Call 12 and 0015 'When an app asks'.
- **NoSession { hidden: Option<bool> } via sd_uid_get_state, and linger advice only for Some(false)**: Notes cut row 'Diagnostics and helpers': 0.2 or when asked.
- **Request::same_files, REQUEST 8 CWD_FINAL and 9 MNT_NS, resolve() using the final-path cwd**: Notes cut row 'Diagnostics and helpers': 0.2 or when asked.
- **HELLO 10 EXE (Context::exe)**: Part of Context: 0.2.
- **Builder::any_screen removal**: It doesn't exist in this code; the sketch's 'Removed' entry refers to a review draft.
- **Multi-session AVD placement test (two users on a host; one user with two sessions)**: 0015 Consequences: beyond 0.1's scope.
- **Porting sheaf to the new API**: Plan step 9: a separate repository.
- **Checking the Unix lock more often, or watching it with inotify or kqueue**: 0008: the maintainer kept the check at once a minute; nothing to build.
- **Field verification of toolbox, distrobox, rootless podman and LXD; the guard on NFS, CIFS, FAT, exFAT, Samba, WebDAV, vboxsf and \\wsl$; RDS session APIs; macOS GUI sessions; macOS sudo audit uid**: Verification from 'Still to verify', not code. They inform the docs and the network-volume list but aren't build items. The 0.2-specific ones are staged.
