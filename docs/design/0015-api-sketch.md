# 0015 appendix: the review's API sketch

This is the API the identity review proposed on 2026-10-18 for [0015](0015-state-keyed-identity.md), kept word for word from the review's output. It is a sketch, not the accepted API. Its decisions await the maintainer, and the recommendation in 0015 holds several parts back until 0.2: placement (`Screens`, `Context`, `OtherScreen`, `OtherPerson`), completion (`wait`, `Completion`, `Finish`), capabilities and credentials (`privileged_owner`, `Logon`), and the diagnostics (`Claim::others`, `canonical_path`, `Guard::Always`). Line references point into the code as of commit f19d695.

## Re-exports (src/lib.rs)

```rust
pub use builder::{Builder, ElevatedOwner, Guard, Screens, State};   // `Mode` removed
pub use context::{Context, Level, Logon};                            // new src/context.rs
pub use id::{AppId, Kind};
pub use outcome::{End, Excluded, Exclusive, Finish, Holder, Ineligible,
                  OwnerInfo, Placement, Reason, Rights, Started};
pub use owner::{Claim, Owner, Sibling};
pub use request::{Activation, Answer, Completion, IntoAnswer, Request};

/// The path as the owner should see it. Symlinks are resolved. On Windows,
/// SUBST becomes the real path and a mapped drive becomes UNC
/// (GetFinalPathNameByHandleW). Launches call it on absolute path arguments
/// before building the payload, because the crate can't see inside a
/// payload. The nearest existing ancestor is resolved and the rest is
/// appended.
pub fn canonical_path(path: &Path) -> io::Result<PathBuf>;
```

## AppId (src/id.rs): the kind is part of the app

```rust
impl AppId {
    /// An app whose owner shows windows (any toolkit). Its owner must be
    /// able to show them, and `start` places requests by screen.
    pub const fn windowed(id: &'static str) -> AppId;
    /// An app whose owner shows nothing: a daemon, a CLI back end, a service.
    pub const fn headless(id: &'static str) -> AppId;
    pub fn parse(id: impl Into<String>, kind: Kind) -> Result<AppId, InvalidAppId>;
    pub fn kind(&self) -> Kind;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind { Windowed, Headless }
```

Every binary of an app uses the same `const APP: AppId`. HELLO compares the
kind, so a subcommand can't own a windowed app's state as a headless owner.
A mismatch is `Reason::OtherApp`. `AppId::new` is removed.

## State (src/builder.rs)

```rust
/// The folder only the owner writes. It names the instance and carries the
/// guard.
pub struct State { /* private */ }
impl State {
    /// The anchor folder. Pass the folder the app's storage layer actually
    /// writes, computed by the same function. If that function follows the
    /// environment (`dirs::config_dir()` follows HOME and XDG_CONFIG_HOME on
    /// Unix), env-isolated tests get their own instance. If it follows the
    /// account (Windows known folders ignore %APPDATA%), tests must pass
    /// their folder through the app's own option. Apps with several folders
    /// pass the one the others are derived from. The folder must never be
    /// replaced or renamed; files inside it may be.
    pub fn dir(path: impl Into<PathBuf>) -> State;
    /// No files to guard: identity is (user, app id, scope). There is no
    /// guard and no ForeignState check, and env-isolated tests don't
    /// isolate.
    pub fn none() -> State;
}
impl From<PathBuf> for State {}
impl From<&Path> for State {}
```

## Builder

```rust
impl Builder {
    /// Launches of `app` by one user that name the same `state` (and scope)
    /// meet one owner. That owner also holds `.instance-handoff.lock` inside
    /// the folder for its whole life (see [`Guard`]).
    ///
    /// Before anything is created:
    /// - A folder, or the nearest existing ancestor it would be created in,
    ///   that belongs to another user gives [`Reason::ForeignState`]. That
    ///   catches root given the user's HOME by macOS sudo, sudo -E or su -m,
    ///   and the SMAA given the user's %APPDATA%.
    /// - A guard held by a process this launch can't reach gives
    ///   [`Reason::StateInUse`].
    pub fn new(app: AppId, state: impl Into<State>) -> Builder;

    /// One owner per (state, key) instead of per state: per display
    /// (`Context::current().screen_key()`), per Windows session, per
    /// project. Keyed owners take the guard in shared mode, so they coexist
    /// with one another but not with an unkeyed owner or `exclusive()`. The
    /// app must make concurrent writes to the shared state safe. The key
    /// names a runtime rendezvous only. Never derive a state folder from a
    /// session id, which is recycled (Windows) or changes at every login
    /// (macOS asid).
    pub fn scope(self, key: impl AsRef<OsStr>) -> Builder;

    /// How far the state guard reaches. Default [`Guard::Local`].
    pub fn guard(self, guard: Guard) -> Builder;

    /// Whether a launch holding rights the owner lacks gives them up and
    /// hands its request down. Such rights ([`Rights`]) are:
    /// - a higher Windows integrity level (admin terminal, Windows sudo,
    ///   Run as administrator, an elevated SSH or WinRM logon, UIAccess);
    /// - `runas /netonly` network credentials;
    /// - Linux effective capabilities (`run0 --empower`, file capabilities).
    ///
    /// Default `false`: the launch gets [`Reason::MoreRights`] at once,
    /// which names the owner and the rights, and must not write the state.
    /// No token property tells deliberate elevation from incidental, so the
    /// crate never decides this itself. Set it per call, on a clone, for the
    /// commands that need no rights, and leave it off for the rest. The
    /// owner sees [`Request::handed_down`]. A request is never handed up and
    /// never crosses users: Unix sudo, su, doas, pkexec and run0 reach
    /// root's instance. Applies to `start` and `hand_off`; `probe` carries
    /// no rights.
    pub fn hand_down(self, allow: bool) -> Builder;

    /// Which launches with raised rights may become the owner when nobody
    /// is. Default [`ElevatedOwner::NotRaised`].
    pub fn elevated_owner(self, policy: ElevatedOwner) -> Builder;

    /// Let a Linux-capable process (non-root, with effective capabilities
    /// beyond CAP_WAKE_ALARM and CAP_BLOCK_SUSPEND) own. No capability
    /// comparison is made: any process of the same uid can then steer the
    /// owner. Needed where a session grants every app ambient capabilities.
    /// Default `false`. Builder::dir no longer implies it. Set-id processes
    /// never take part ([`Excluded::SetId`]).
    pub fn privileged_owner(self, allow: bool) -> Builder;

    /// Windowed apps: where `start` may deliver. Default [`Screens::Same`].
    pub fn screens(self, screens: Screens) -> Builder;

    /// Use `context` instead of detecting this process's. For tests and for
    /// CI without a display: `Context::named("test")` can show windows,
    /// equals only the same name, and differs from every real screen, so it
    /// never reaches a developer's running app. Not for production.
    pub fn context(self, context: Context) -> Builder;

    /// Hand off only to an owner that reports when the request is done, and
    /// block until it does ([`OwnerInfo::finish`]). For `--wait`, $EDITOR,
    /// $GIT_EDITOR and sudoedit. A waiting launch never owns: with no owner
    /// it gets `MayNotOwn { why: Ineligible::Wait }` and should edit in a
    /// stateless window that exits when closed. An owner over its cap of
    /// held waits refuses with [`Reason::Busy`] at once.
    pub fn wait(self, wait: bool) -> Builder;
    /// The longest a waiting launch blocks after the owner took the request.
    /// `None` (default) waits until finish, Completion drop or connection
    /// loss. Ctrl-C ends the wait as usual.
    pub fn wait_timeout(self, timeout: Option<Duration>) -> Builder;

    /// (Changed) Replaces the default base; the instance folder is still
    /// added inside it. [`Reason::RuntimeDir`] for:
    /// - network volumes;
    /// - for root, a folder inside another user's tree;
    /// - a socket path the OS can't bind (macOS binds up to
    ///   SOCK_MAXADDRLEN - 1 with a larger sockaddr).
    ///
    /// There is no fallback that depends on the caller.
    pub fn dir(self, dir: impl Into<PathBuf>) -> Builder;

    pub fn timeout(self, timeout: Duration) -> Builder;     // unchanged
    pub fn payload_version(self, version: u32) -> Builder;  // unchanged
    pub fn runtime_dir(&self) -> Option<PathBuf>;           // now ends in i-<hash>

    /// Own, hand off, or run alone. Every refusal returns at once.
    pub fn start<T: Payload>(&self, payload: &T) -> Started<T>;
    /// Hand `payload` to the owner wherever its windows are. Never owns.
    /// Compares app, principal and rights, not screen or person. Never
    /// returns NoSession: without a runtime folder it reports
    /// `NoOwner` (guard free) or `StateInUse` (guard held).
    pub fn hand_off<T: Payload>(&self, payload: &T) -> Result<OwnerInfo, Reason>;
    /// Whether an owner holds the state, at any level. Never refused for
    /// rights: a medium probe of a high owner is
    /// `Ok(info)` with `info.level() == Some(Level::HIGH)` and
    /// `confirmed() == false`.
    pub fn probe(&self) -> Result<OwnerInfo, Reason>;
    /// Hold the state for this process's own work without being reachable:
    /// batch subcommands, migrations, cron, CI steps, `--new-instance`. Takes
    /// the guard exclusive, so it needs no runtime folder and behaves the
    /// same whoever is logged in. `StateInUse` when any owner (keyed or not)
    /// or another exclusive run holds it. Never waits; creates no thread.
    pub fn exclusive(&self) -> Result<Exclusive, Reason>;
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Guard {
    /// Lock the guard on local volumes. On network volumes (NFS, CIFS, SMB,
    /// 9p; macOS without MNT_LOCAL; Windows DRIVE_REMOTE) it is skipped and
    /// [`Claim::guarded`] is false: each host has its own owner, as on NFS
    /// homes today. Never locks a user out of their state after another
    /// host crashed.
    #[default]
    Local,
    /// Lock it on network volumes too: one owner across hosts, as far as the
    /// server enforces locks (Chromium-style 'profile in use on another
    /// computer'). After a client crash, the lock can persist until the
    /// client's lock recovery or lease ends. NFS `local_lock=` makes it
    /// host-local again.
    Always,
    /// No guard: read-only or shared config, folders under sync tools.
    Off,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ElevatedOwner {
    /// A launch whose rights were raised from a login doesn't own: Windows
    /// TokenElevationTypeFull (admin terminal, sudo, Run as administrator,
    /// an installer's finish page, a task with highest privileges), and Unix
    /// root whose person is known and isn't root (sudo, su, doas, pkexec,
    /// run0, macOS sudo). It hands off where it may, or runs alone with
    /// `MayNotOwn { why: Ineligible::Raised }`. Accounts that only ever run
    /// elevated (RID 500, UAC off, an elevated OpenSSH logon) and root's own
    /// login still own.
    #[default]
    NotRaised,
    /// Also no owner above medium: every Windows token at HIGH or SYSTEM
    /// (elevated SSH or WinRM daemons, RID 500, UAC off). UIAccess (0x2010)
    /// may own. Those accounts then never keep state.
    NotAboveNormal,
    /// Any eligible launch owns (VS Code). Later normal launches get
    /// `OwnerHasMoreRights` until it quits.
    Allow,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Screens {
    /// To an owner whose windows appear where this launch's would. A launch
    /// with no screen (SSH, cron, session 0) also hands off and is told
    /// where ([`OwnerInfo::placement`]).
    #[default]
    Same,
    /// Only to an owner on this launch's own screen. Launches with no screen
    /// get `OtherScreen`. For shared accounts, kiosks and lab machines, where
    /// a headless launch may be another person.
    Strict,
    /// Any X11 or Wayland display, or any desktop of this launch's Windows
    /// session, for owners that open windows on [`Request::origin`]'s
    /// display. Never across Windows sessions or macOS GUI sessions, where
    /// no process can create a window.
    Any,
}
```

## Context, Level, Logon (src/context.rs)

```rust
/// What the crate knows of a process at either end of a handoff.
/// [`Context::current`] is this process, [`Request::origin`] the launch,
/// [`OwnerInfo::context`] the owner.
///
/// Attested facts come from the kernel through the connection: the pid, the
/// Windows level, session and logon LUID, the macOS auid and asid on the
/// owner's side, and SO_PEERCRED. Reported facts come from the process's own
/// environment: display variables, `remote_login`, the person's invoker
/// variables, `exe`. Rights admission never uses reported facts to admit.
/// Placement uses them both ways, because within one account placement is
/// not a rights boundary.
#[derive(Debug, Clone)]
pub struct Context { /* private */ }
impl Context {
    pub fn current() -> Context;
    pub fn named(name: &str) -> Context;          // tests and CI; see Builder::context
    pub fn headless() -> Context;                 // an owner that lost its display
    /// For Owner::set_context once the toolkit has connected (GTK falls
    /// back to wayland-0).
    pub fn wayland(socket: &Path) -> io::Result<Context>;
    pub fn x11(display: &OsStr) -> Context;
    pub fn pid(&self) -> Option<u32>;
    pub fn level(&self) -> Option<Level>;          // Windows only
    pub fn logon(&self) -> Option<Logon>;          // Windows only
    pub fn capabilities(&self) -> Option<u64>;     // Linux CapEff, own process only
    pub fn can_show_windows(&self) -> Option<bool>;
    /// Some(true) same screen; Some(false) a confident difference (same
    /// protocol and different identity, or forwarded against local); None
    /// otherwise.
    pub fn same_screen(&self, other: &Context) -> Option<bool>;
    /// A stable string for this screen while it exists ('wayland@<dev>:<ino>',
    /// 'x11@<dev>:<ino>', 'win-session-4-Default', 'macos-gui'), for
    /// Builder::scope. None without a screen.
    pub fn screen_key(&self) -> Option<String>;
    pub fn windows_session(&self) -> Option<u32>;
    pub fn windows_desktop(&self) -> Option<&str>;
    pub fn disconnected(&self) -> Option<bool>;    // WTSConnectState
    pub fn audit_session(&self) -> Option<u32>;    // macOS asid, changes every login
    pub fn display(&self) -> Option<&OsStr>;       // Unix, as the environment named it
    /// A hint: SSH_CONNECTION, macOS AU_SESSION_FLAG_IS_REMOTE, or a Windows
    /// network logon. Not `Request::is_remote`, which means 'sent by
    /// another process'.
    pub fn remote_login(&self) -> Option<bool>;
    /// Unix: the person (see the identity model). None on Windows.
    pub fn person(&self) -> Option<u32>;
    pub fn exe(&self) -> Option<&Path>;
}
impl fmt::Display for Context {}
// e.g. "session 4 (disconnected)", "wayland-0 (:0)", "localhost:10.0 (from 192.0.2.4)", "no display"

/// A Windows integrity level, ordered by its RID: a total order that new
/// constants can't change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Level(u32);
impl Level {
    pub const LOW: Level; pub const MEDIUM: Level; pub const UI_ACCESS: Level;
    pub const MEDIUM_PLUS: Level; pub const HIGH: Level; pub const SYSTEM: Level;
    pub const fn rid(self) -> u32;
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Logon { Interactive, RemoteInteractive, Network, Batch, Service, NewCredentials, Other(u32) }
```

## Outcomes (src/outcome.rs)

```rust
/// Rights one side has that the other lacks.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rights {
    Level { launch: Level, owner: Level },
    NetworkCredentials,               // a runas /netonly logon
    Capabilities { launch: u64, owner: u64 },
}

#[non_exhaustive] #[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ineligible { Headless, Raised, AboveNormal, Capable, Wait }
#[non_exhaustive] #[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Excluded { SetId, Sandboxed }

/// Who holds a state guard, from its advisory text; `stale` when the pid is
/// on this host and no longer exists.
#[derive(Debug, Clone)]
pub struct Holder { pub pid: Option<u32>, pub host: Option<String>, pub exclusive: bool, pub stale: bool }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement { Same, Elsewhere, Unknown }

/// How a waited-for request ended. Map Code(c) to c, Done to 0, and Lost or
/// TimedOut to 1, so git and sudoedit (sudo-rs writes back only on 0) don't
/// keep edits that weren't finished.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finish { Code(i32), Done, Lost, TimedOut }

impl OwnerInfo {
    pub fn pid(&self) -> Option<u32>;            // unchanged
    pub fn confirmed(&self) -> bool;             // unchanged
    pub fn level(&self) -> Option<Level>;        // Windows: from the lock marker
    pub fn context(&self) -> Option<&Context>;
    /// Same when same_screen is Some(true); Elsewhere when it is Some(false)
    /// or this launch had no screen; Unknown otherwise.
    pub fn placement(&self) -> Placement;
    pub fn handed_down(&self) -> Option<&Rights>;
    pub fn finish(&self) -> Option<Finish>;       // with Builder::wait
}
impl fmt::Display for OwnerInfo {}               // "pid 4242, high, session 1"

/// The state, held for this process's own work. Dropping it, or exiting,
/// releases it.
#[must_use = "dropping an Exclusive releases the state at once"]
pub struct Exclusive { /* guard */ }
impl Exclusive { pub fn state_dir(&self) -> Option<&Path>; pub fn release(self); }
```

## Claim, Owner, Request

```rust
impl<T> Claim<T> {
    /// The canonical state folder. Write state through this, and only when
    /// a Claim or an Exclusive exists: Alone never yields one.
    pub fn state_dir(&self) -> Option<&Path>;
    /// Whether the guard is held: false under Guard::Off, on a network
    /// volume under Guard::Local, or where locks are unsupported.
    pub fn guarded(&self) -> bool;
    /// Live owners of the same app id and user over other state folders
    /// (environment drift: XDG_CONFIG_HOME set only in a shell rc). For a
    /// warning; at most 32 folders are scanned.
    pub fn others(&self) -> &[Sibling];
}
pub struct Sibling { pub pid: Option<u32>, pub state: PathBuf }
impl Owner {
    pub fn state_dir(&self) -> Option<&Path>;
    pub fn set_context(&self, context: Context);
}

impl<T> Request<T> {
    pub fn origin(&self) -> &Context;               // replaces launcher_pid
    /// What the launch gave up to hand off. Don't do what needed it; say so.
    pub fn handed_down(&self) -> Option<&Rights>;
    /// Whether the launch's paths name the same files here: Some(false)
    /// across Windows logon sessions (attested LUID) or Linux mount
    /// namespaces.
    pub fn same_files(&self) -> Option<bool>;
    pub fn completion(&mut self) -> Option<Completion>;
    // resolve(): uses the launch's final-path cwd when same_files() is Some(false).
    // is_remote(): unchanged ('sent by another process').
}
#[must_use = "a waiting launch blocks until this is finished or dropped"]
pub struct Completion { /* private */ }
impl Completion { pub fn finish(self, code: i32); }   // drop = Finish::Done
```

## Reason: new and changed variants (each #[non_exhaustive])

```rust
/// This launch has rights the owner lacks, and hand_down is off; nothing was
/// sent. Must not write the state.
MoreRights { owner: OwnerInfo, rights: Rights },
/// The owner has rights this launch lacks (a higher level, UIAccess, a
/// /netonly realm). It never takes this launch's requests. start, hand_off.
OwnerHasMoreRights { owner: OwnerInfo, rights: Rights },
/// A windowed app's owner shows its windows where this launch's wouldn't
/// appear, or this launch has no screen under Screens::Strict or an unknown
/// person. hand_off delivers anyway.
OtherScreen { owner: OwnerInfo },
/// A windowed app's owner was started by another person (loginuid, audit
/// auid or invoker differ): another admin's root window, or alice's app
/// from greg's `su - alice`. hand_off still delivers; don't suggest it.
OtherPerson { owner: OwnerInfo },
/// Nobody this launch may hand to is running, and it may not own.
MayNotOwn { why: Ineligible },
/// This process can't take part at all.
Excluded { why: Excluded },
/// A process this launch can't reach holds the state guard: another
/// container, an exclusive run, an owner whose address is being re-created,
/// or another host under Guard::Always.
StateInUse { path: PathBuf, holder: Option<Holder> },
/// The state folder, or the folder it would be created in, belongs to
/// another user. Nothing was created.
ForeignState { path: PathBuf },
```

Changed:
- `NoSession { hidden: Option<bool> }` comes from sd_uid_get_state. It is never returned to root, and never from hand_off or probe. Linger advice is given only for `Some(false)`.
- `Peer` now means only another user's socket or pipe at this user's address.
- `Busy` also covers the owner's cap on held waits.
- `RuntimeDir` and `NoRuntimeDir` gain the cases above.

End: `LostLock` remains only for Guard::Off or skipped guards. New `End::LostState`: the guard or the state folder was replaced or removed, so stop writing. An owner that only lost its runtime folder is not ended: it re-creates its address.

## Removed

- `AppId::new`. Use `AppId::windowed` or `AppId::headless`.
- `Builder::mode`, `Mode`, `Reason::OwnerRunning`. Use `exclusive`.
- `Builder::any_screen`. Use `screens(Screens::Any)`.
- The `XDG_SESSION_ID` advice on scope.
- `Request::launcher_pid`. Use `origin().pid()`.
- Windows per-level folders as lock holders. `run*` now holds only the address.
- Root's use of `/run/user/0`, `/tmp/<id>-0` and `/tmp/ih-0`.
- The macOS socket fallback folder.

## Wire (protocol 1, redefined; nothing is published)

- APP record: gains the kind byte.
- HELLO, new non-critical records:
  - 7 LEVEL: the RID;
  - 8 CONTEXT: session, desktop, Wayland (dev, ino), local X (dev, ino), forwarded X (display, client address), named, unknown-screen flag, can-show flag, person, user-ns inode, disconnected flag;
  - 9 STATE: canonical path plus scope;
  - 10 EXE;
  - 11 FEATURES: bit 0 means it sends REFUSED with a cause; bit 1 means it can WAIT;
  - 12 LOGON: type and the NewCredentials flag.
- REQUEST, new records:
  - 7 CONTEXT;
  - 8 CWD_FINAL;
  - 9 MNT_NS;
  - 0x8A HAND_DOWN (critical, carries the Rights);
  - 0x8B WAIT (critical).
- REPLY, new refusal codes: 8 PRIVILEGE, 9 SCREEN, 10 PEER, 11 STATE, 12 PERSON, each with the owner's LEVEL or CONTEXT. Unknown codes map to `Declined`; today they map to `WireVersion` (src/launch.rs:484-487).
- Message kind 6 FINISH: an i32, or empty for Done. If the connection closes before FINISH, the result is Finish::Lost.
- An owner never closes a refused connection silently. Today it does (src/sys/windows.rs:1491-1497, src/sys/unix.rs:1331-1344).

## Frozen on disk

- The Linux five-step base rule, /run/instance-handoff, BSD /var/run/instance-handoff, and the realpath'd macOS confstr rule.
- `i-<hex16>` instance folders.
- The guard: `.instance-handoff.lock`, flock LOCK_EX/LOCK_SH; on Windows, LockFileEx on 1 byte at 2^31 with its text at 0.
- Windows: explicit ME NWNR labels in the key folder; instance.lock byte 0 for ownership plus the marker at offset = RID; per-level `run*` address folders.

Comparison rules (screen, person, credential realm) are table-tested behaviour carried in non-critical records, not contract.

## Usage

```rust
const APP: AppId = AppId::windowed("org.example.Sheaf");
// The same function the storage layer uses.
let b = Builder::new(APP, State::dir(app::config_dir()));
let claim = match b.start(&files) {
    Started::Owner(c) => c,
    Started::HandedOff(info) => {
        if info.placement() != Placement::Same { eprintln!("opened in the running app ({info})"); }
        return;
    }
    Started::Alone(Reason::MoreRights { owner, rights, .. }) => {
        // admin terminal, Windows sudo, elevated SSH
        if ask(&format!("Open in the running window ({owner})? It will lack {rights}."))
            && b.clone().hand_down(true).hand_off(&files).is_ok() { return; }
        return run_stateless(files);
    }
    Started::Alone(Reason::OwnerHasMoreRights { owner, .. }) => { eprintln!("already running as administrator ({owner})"); return; }
    Started::Alone(Reason::OtherScreen { owner, .. }) => { eprintln!("open in {owner}; `app --remote FILE` sends it there"); return run_stateless(files); }
    Started::Alone(Reason::OtherPerson { owner, .. }) => { eprintln!("open for another person ({owner})"); return run_stateless(files); }
    Started::Alone(reason) => { eprintln!("{reason}"); return run_stateless(files); }
};
write_state(claim.state_dir());

// daemon + control CLI
const D: AppId = AppId::headless("org.example.syncd");
let b = Builder::new(D, State::dir(state));
match cmd {
    Cmd::Status => b.probe().map(|i| println!("running: {i}")),
    Cmd::Stop | Cmd::Reload => b.clone().hand_down(true).hand_off(&cmd).map(drop), // needs no rights
    Cmd::Install(_) => b.hand_off(&cmd).map(drop),  // keeps MoreRights: do it here instead
    Cmd::Migrate => { let held = b.exclusive()?; migrate(held.state_dir()) }
}
```
