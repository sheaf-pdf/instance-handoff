use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::server::Upkeep;
use crate::{AppId, OwnerInfo, Payload, Reason, Started, launch, naming, state, sys};

/// The folder an app keeps its state in: the files only the owner writes.
/// [`Builder::new`] takes it, and the owner reports it, with its links
/// resolved, as [`Claim::state_dir`] and [`Owner::state_dir`]. Launches
/// that name one state folder and one scope meet one owner: the two name
/// their runtime folder ([`Builder::runtime_dir`]).
///
/// A `PathBuf` or a `&Path` converts to a `State::dir`.
///
/// [`Claim::state_dir`]: crate::Claim::state_dir
/// [`Owner::state_dir`]: crate::Owner::state_dir
#[derive(Debug, Clone)]
pub struct State {
    dir: Option<PathBuf>,
}

impl State {
    /// The folder the app's storage layer writes, computed by the same
    /// function. An app with several folders passes the one the others are
    /// derived from. It needn't exist.
    ///
    /// Its links are resolved when a launch decides, not here. A relative
    /// path is made absolute against the working directory. Then the
    /// nearest folder on it that exists is resolved: with `realpath` on
    /// Unix, and on Windows to its final path (`GetFinalPathNameByHandleW`),
    /// where a `SUBST` letter becomes the real drive and a mapped drive
    /// becomes `\\server\share`. The part that doesn't exist is appended as
    /// given, except that a `..` in it drops the part before it, as it will
    /// once those folders exist.
    ///
    /// A path that can't be resolved, such as one through a folder this user
    /// can't search, is kept as given, made absolute. One that can't be made
    /// absolute, such as an empty path, is kept as given too, so it stays
    /// relative. Either way the launch goes on, with a warning in the log.
    pub fn dir(path: impl Into<PathBuf>) -> State {
        State {
            dir: Some(path.into()),
        }
    }

    /// No state folder: the app keeps no files of its own.
    /// [`Claim::state_dir`] is then `None`, and nothing gives
    /// [`Reason::ForeignState`]. Launches that pass it, with one scope,
    /// meet one another, never the owner of a state folder.
    ///
    /// [`Claim::state_dir`]: crate::Claim::state_dir
    pub fn none() -> State {
        State { dir: None }
    }
}

impl From<PathBuf> for State {
    fn from(dir: PathBuf) -> State {
        State::dir(dir)
    }
}

impl From<&Path> for State {
    fn from(dir: &Path) -> State {
        State::dir(dir)
    }
}

/// What a launch does when another process owns the app.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Mode {
    /// Become the owner, or hand the payload to the owner.
    #[default]
    Join,
    /// Become the owner if nobody is; otherwise run alone
    /// ([`Reason::OwnerRunning`]) without contacting the owner. For
    /// `--new-instance` flags, self-tests, scripted runs and debug builds.
    ///
    /// A separate launch that finds nobody becomes the owner. Serve it with
    /// [`Claim::decline_all`] if it must not receive the user's launches.
    /// One that may not own runs alone at once with [`Reason::MayNotOwn`],
    /// and one that takes the lock but finds the state folder's
    /// [guard](Guard) held by an owner it can't share it with runs alone
    /// with [`Reason::StateInUse`].
    ///
    /// [`Claim::decline_all`]: crate::Claim::decline_all
    Separate,
}

/// Whether the owner takes the state folder's guard: see
/// [`Builder::guard`].
///
/// The guard is a lock on `.instance-handoff.lock` in the state folder,
/// which the owner takes after the lock in its runtime folder and holds as
/// long. Launches that name one state folder can still end up in two
/// runtime folders: in two containers, say, given two [`Builder::dir`]
/// folders, or as two app ids that share the folder. The one that takes
/// its lock second finds the guard held, lets go of its lock and runs alone
/// at once with [`Reason::StateInUse`], rather than own the state folder
/// beside the first.
///
/// An owner with a [scope](Builder::scope) takes the guard shared. Owners
/// with scopes then hold it side by side, whatever their scopes and
/// runtime folders, but never beside an owner without one: whichever of
/// the two comes second runs alone with [`Reason::StateInUse`].
///
/// `start` makes the guard file (mode 0600) in the state folder, which it
/// has created if it was missing (see [`Builder::new`]). The file is never
/// written. Like the lock, the guard is held until the process exits, or
/// until [`Owner::release`] or [`Claim::release`] gives both up, and a
/// child forked from the owner holds it too until it exits.
///
/// No guard is taken, and no guard file made, under [`Guard::Off`], for
/// [`State::none`], and on Windows. Nor is one held on a network file
/// system, or where the file system can't lock files: see [`Guard::Local`].
/// An owner that holds none doesn't keep out launches in other runtime
/// folders, with a scope or without. [`Claim::guarded`] says
/// whether the owner holds it.
///
/// [`Owner::release`]: crate::Owner::release
/// [`Claim::release`]: crate::Claim::release
/// [`Claim::guarded`]: crate::Claim::guarded
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Guard {
    /// Take the guard on a local disk. One that can't be made or opened
    /// gives [`Reason::Lock`]: the state folder is read-only, say, or the
    /// guard file is another user's.
    ///
    /// On a network file system the owner takes no guard and makes no
    /// guard file. A lock there would reach every host that mounts it, and
    /// one held by a host that crashed can stay held. So each host keeps an
    /// owner of its own. On Linux that means NFS, SMB and CIFS, 9p (as WSL
    /// 2 mounts the Windows drives), AFS, Ceph, Coda, NCP, Lustre, GFS2,
    /// OCFS2 and VirtualBox shared folders, but not FUSE, whatever serves
    /// it. On macOS and the BSDs it means a file system not marked
    /// `MNT_LOCAL`, and on illumos NFS and SMB.
    ///
    /// Where the file system can't lock files (`ENOLCK` or `EOPNOTSUPP`),
    /// the owner holds no guard either. Either way [`Claim::guarded`] is
    /// false.
    ///
    /// [`Claim::guarded`]: crate::Claim::guarded
    #[default]
    Local,
    /// Take no guard, and make no guard file. A missing state folder is
    /// still made. Owners of the folder in two runtime folders then run
    /// side by side. For config that is read-only or shared, and for a
    /// folder that a sync tool copies between machines.
    Off,
}

/// Which launches with raised rights may become the owner when nobody is:
/// see [`Builder::elevated_owner`].
///
/// A launch that may not own never takes the lock. It hands off to the
/// owner if one is running, and otherwise runs alone at once with
/// [`Reason::MayNotOwn`]. This only keeps launches from owning: it never
/// lets one hand off where it otherwise couldn't.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ElevatedOwner {
    /// A launch whose rights were raised from a login doesn't own
    /// ([`Ineligible::Raised`]). On Unix that is root whose person is
    /// known and isn't root: `sudo`, `run0`, `pkexec`, `doas`, and on Linux
    /// `su`. Root's own login and systemd's services still own. On Windows
    /// no launch counts as raised. See the crate docs on privileges, which
    /// also cover containers.
    ///
    /// [`Ineligible::Raised`]: crate::Ineligible::Raised
    #[default]
    NotRaised,
    /// Also no owner with more rights than a normal process
    /// ([`Ineligible::AboveNormal`]): on Unix, no root launch owns, so
    /// root never keeps the state. On Windows this is the same as
    /// `NotRaised`.
    ///
    /// [`Ineligible::AboveNormal`]: crate::Ineligible::AboveNormal
    NotAboveNormal,
    /// A launch's rights never keep it from owning. A launch under `sudo`
    /// becomes root's owner when root has none, and root's later launches
    /// hand off to it.
    Allow,
}

/// Configures and runs the decision: own, hand off, or run alone.
///
/// ```
/// use std::path::Path;
/// use std::time::Duration;
/// use instance_handoff::{AppId, Builder, Mode};
///
/// const APP: AppId = AppId::windowed("org.example.Viewer");
///
/// // `data` is the folder the viewer keeps its state in.
/// fn builder(data: &Path) -> Builder {
///     Builder::new(APP, data).mode(Mode::Separate).timeout(Duration::from_secs(1))
/// }
/// # let _ = builder;
/// ```
#[must_use = "a Builder does nothing until `start`, `hand_off` or `probe`"]
#[derive(Debug, Clone)]
pub struct Builder {
    pub(crate) app_id: AppId,
    state: State,
    pub(crate) scope: Option<OsString>,
    dir: Option<PathBuf>,
    pub(crate) guard: Guard,
    pub(crate) mode: Mode,
    pub(crate) elevated_owner: ElevatedOwner,
    pub(crate) timeout: Duration,
    pub(crate) payload_version: u32,
    pub(crate) upkeep: Upkeep,
}

impl Builder {
    /// A builder for `app_id`, whose state is in `state` ([`State::dir`]),
    /// or which keeps none ([`State::none`]). The defaults: the default
    /// runtime folder, [`Guard::Local`], [`Mode::Join`],
    /// [`ElevatedOwner::NotRaised`], a 5 second timeout and payload version
    /// 0.
    ///
    /// Launches of `app_id` that name one state folder, through whatever
    /// links, and one [scope](Builder::scope) meet one owner. Launches that
    /// name two folders get two owners. Each user, and on Windows each
    /// integrity level, has owners of its own: see the crate docs on where
    /// the lock lives. On Unix the owner also holds a lock in the state
    /// folder, the [guard](Guard), so a launch that finds another runtime
    /// folder, as in another container, runs alone with
    /// [`Reason::StateInUse`] rather than become a second owner of that
    /// state folder. Owners with a scope share the guard with one another,
    /// never with an owner without one.
    ///
    /// Before [`start`](Builder::start) creates anything, it checks whose
    /// the state folder is, or, while it is missing, whose the nearest
    /// folder above it is. If that folder belongs to another user, the
    /// launch runs alone with [`Reason::ForeignState`]. That catches root
    /// given the user's home by macOS `sudo`, `sudo -E` or `su -m`, and the
    /// separate account that Windows administrator protection elevates to,
    /// given the user's `%APPDATA%`.
    ///
    /// - On Unix, a folder of the launch's user or of root passes. Root's
    ///   launches pass only root's. In a user namespace, host root's
    ///   folders show as the overflow user (`nobody`), and don't pass.
    /// - On Windows, a folder of the launch's user, SYSTEM, Administrators
    ///   or TrustedInstaller passes, and so does any folder on a volume
    ///   that keeps no owners, such as FAT.
    /// - A folder whose owner can't be read passes, with a warning in the
    ///   log.
    ///
    /// [`hand_off`](Builder::hand_off) and [`probe`](Builder::probe) write
    /// nothing there, and don't check.
    ///
    /// On Unix, once it holds the lock, `start` creates the state folder if
    /// it is missing, with the folders above it, the last one private (mode
    /// 0700), whatever the [guard](Guard). One that can't be made gives
    /// [`Reason::Lock`]. On Windows `start` makes nothing there.
    pub fn new(app_id: AppId, state: impl Into<State>) -> Builder {
        Builder {
            app_id,
            state: state.into(),
            scope: None,
            dir: None,
            guard: Guard::Local,
            mode: Mode::Join,
            elevated_owner: ElevatedOwner::NotRaised,
            timeout: Duration::from_secs(5),
            payload_version: 0,
            upkeep: Upkeep::default(),
        }
    }

    /// One owner per state folder and `scope`, rather than one per state
    /// folder: per container, say, or per project. The scope is hashed with
    /// the state folder into the runtime folder's name, so launches meet
    /// only when both match. Owners of one state folder under two scopes
    /// run side by side, so the app must keep their writes to it safe.
    ///
    /// On Unix, owners with a scope take the state folder's [guard](Guard)
    /// shared, so they hold it side by side, whatever their scopes. An owner
    /// without one holds it alone: while it runs, a launch with a scope that
    /// would own runs alone with [`Reason::StateInUse`], and while owners
    /// with scopes run, so does a launch without one. So pass a scope to
    /// every launch of a state folder, or to none.
    ///
    /// The scope is a key, compared byte for byte, not a path: `cfg`,
    /// `./cfg/` and a symlink to it are three scopes, and a relative path
    /// means one scope for every folder of that name. To key on a folder,
    /// create it and pass [`std::fs::canonicalize`] of it.
    ///
    /// A scope only names where launches meet. Never derive a state folder
    /// from a session id: Windows reuses session ids, and macOS gives a new
    /// one at every login.
    pub fn scope(mut self, scope: impl AsRef<OsStr>) -> Builder {
        self.scope = Some(scope.as_ref().to_os_string());
        self
    }

    /// Use `dir` in place of the app's default folder. The runtime folder is
    /// still the instance folder inside it, which the state folder and the
    /// scope name ([`Builder::runtime_dir`]). It must be on a local disk.
    /// It is created private when missing, and so is the instance folder. A
    /// folder that isn't the user's alone (on Unix: a symlink, another
    /// user's, or open to group or others; on Windows: a link, or one that
    /// others may change or read) is refused with [`Reason::RuntimeDir`].
    ///
    /// Every launch that should meet must pass the same folder: one given
    /// another folder, with the same state folder, runs alone with
    /// [`Reason::StateInUse`] while this owner holds the [guard](Guard),
    /// unless both have a [scope](Builder::scope), since owners with scopes
    /// share the guard. A folder serves one privilege level: on Windows,
    /// one made at another integrity level is refused with
    /// [`Reason::RuntimeDir`], so elevated and normal launches given the
    /// same folder don't share it. For tests, a fresh temporary folder and
    /// state folder per test keep a panicking test's lock and guard from
    /// blocking the next.
    pub fn dir(mut self, dir: impl Into<PathBuf>) -> Builder {
        self.dir = Some(dir.into());
        self
    }

    /// Whether the owner takes the state folder's guard: see [`Guard`].
    /// Defaults to [`Guard::Local`]. Only `start` takes the guard, so
    /// `hand_off` and `probe` don't look at it.
    pub fn guard(mut self, guard: Guard) -> Builder {
        self.guard = guard;
        self
    }

    /// See [`Mode`]. Defaults to [`Mode::Join`].
    pub fn mode(mut self, mode: Mode) -> Builder {
        self.mode = mode;
        self
    }

    /// Which launches with raised rights may become the owner when nobody
    /// is: see [`ElevatedOwner`]. Defaults to [`ElevatedOwner::NotRaised`].
    /// Only `start` can own, so `hand_off` and `probe` don't look at it.
    pub fn elevated_owner(mut self, policy: ElevatedOwner) -> Builder {
        self.elevated_owner = policy;
        self
    }

    /// How long a launch keeps trying an owner that holds the lock but
    /// doesn't take the request (still starting, busy or quitting) before
    /// it runs alone with [`Reason::Busy`] or [`Reason::Unresponsive`].
    /// Defaults to 5 seconds. `Duration::MAX` means "as long as it takes";
    /// anything under 100 ms counts as 100 ms, the least a handoff to a
    /// healthy owner needs.
    ///
    /// A launch that has committed its request waits for the owner's reply
    /// for up to this long again (at least a second) before it reports an
    /// unconfirmed handoff. So `start` and `hand_off` block for at most the
    /// timeout plus the greater of the timeout and one second.
    pub fn timeout(mut self, timeout: Duration) -> Builder {
        self.timeout = timeout;
        self
    }

    /// The version of your payload's meaning. An owner refuses a launch
    /// whose version differs from its own ([`Reason::PayloadVersion`]), so
    /// bump it when older builds would misread the payload. Changes a
    /// decoder tolerates (a field with a default) need no bump. Defaults to
    /// 0. The crate's own wire format is versioned separately and never
    /// refuses a handoff between two builds that agree on this number.
    pub fn payload_version(mut self, version: u32) -> Builder {
        self.payload_version = version;
        self
    }

    /// How often the owner checks its lock file and touches its files. For
    /// this crate's own tests.
    #[doc(hidden)]
    pub fn __upkeep(mut self, check: Duration, touch: Duration) -> Builder {
        let floor = Duration::from_millis(10);
        self.upkeep = Upkeep {
            check: check.max(floor),
            touch: touch.max(floor),
        };
        self
    }

    /// The runtime folder `start` would use, without creating anything: the
    /// instance folder that the state folder and the [scope](Builder::scope)
    /// name (`i-` and 16 hex digits), in the app's folder or in
    /// [`Builder::dir`]. In Local AppData on Windows, it is the folder of
    /// this process's integrity level inside the instance folder. The state
    /// folder's links are resolved as `start` resolves them. For diagnostics
    /// and tests. `None` when there is none to use: see
    /// [`Reason::NoSession`], [`Reason::NoRuntimeDir`] and
    /// [`Reason::Unsupported`].
    pub fn runtime_dir(&self) -> Option<PathBuf> {
        if !sys::SUPPORTED {
            return None;
        }
        self.place(self.canonical_state().as_deref())
            .ok()
            .map(|p| p.path())
    }

    /// The state folder, canonical. Resolved as the launch decides, not in
    /// `new`: the working directory and the links may change in between.
    pub(crate) fn canonical_state(&self) -> Option<PathBuf> {
        self.state.dir.as_deref().map(state::canonical)
    }

    /// What the instance folder's name is hashed from, for the canonical
    /// `state` and the scope. The owner sends it in HELLO, and a launch
    /// compares it with its own.
    pub(crate) fn instance_key(&self, state: Option<&Path>) -> Vec<u8> {
        naming::instance_key(state, self.scope.as_deref())
    }

    /// The runtime folder for the canonical `state`: the base, and in it
    /// the instance folder that `state` and the scope name.
    pub(crate) fn place(&self, state: Option<&Path>) -> Result<sys::Place, Reason> {
        let mut place = match &self.dir {
            // Absolute now: a later change of working directory must not
            // move the owner's folder.
            Some(dir) => {
                sys::Place::dir(std::path::absolute(dir).map_err(|e| Reason::runtime_dir(dir, e))?)
            }
            None => sys::default_place(&self.app_id)?,
        };
        place.push(naming::instance_folder(state, self.scope.as_deref()));
        Ok(place)
    }

    /// Take the lock, or hand `payload` to the process holding it. A
    /// launch that may not own never takes the lock: with nobody to hand
    /// off to, it runs alone with [`Reason::MayNotOwn`]. That is a
    /// [windowed](crate::Kind::Windowed) app's launch that can't show
    /// windows, or one with raised rights ([`Builder::elevated_owner`]).
    ///
    /// Blocks for at most the [timeout](Builder::timeout) plus the greater
    /// of the timeout and one second, and usually for a few milliseconds. `payload` is encoded only if it is
    /// handed off. On the hand-off path this reads `XDG_ACTIVATION_TOKEN`
    /// and `DESKTOP_STARTUP_ID` (and never unsets them); on Windows it lets
    /// the owner's process take the foreground. Creates no thread. Never
    /// panics.
    pub fn start<T: Payload>(&self, payload: &T) -> Started<T> {
        launch::start(self, payload)
    }

    /// Hand `payload` to the owner, and never become one: with nobody
    /// running, fail at once with [`Reason::NoOwner`]. For command-line
    /// front ends (`app --remote open x`, `appctl reload`) that only make
    /// sense against a running app. Creates no folder and no lock. Ignores
    /// [`Builder::mode`].
    pub fn hand_off<T: Payload>(&self, payload: &T) -> Result<OwnerInfo, Reason> {
        launch::hand_off(self, Some(payload))
    }

    /// Whether an owner is serving, without handing anything over or
    /// becoming one: `Ok` when it would pass a request to its handler now.
    /// The owner's handler isn't called. For status commands and for tests
    /// that wait for an owner to be ready.
    ///
    /// Fails as [`Builder::hand_off`] would: at once with
    /// [`Reason::NoOwner`] when nobody holds the lock, with
    /// [`Reason::Declined`] for an owner that turns launches away, and with
    /// [`Reason::Busy`] or [`Reason::Unresponsive`] when the owner hasn't
    /// served (or has stopped) by the [timeout](Builder::timeout). Creates
    /// no folder and no lock. Ignores [`Builder::mode`].
    pub fn probe(&self) -> Result<OwnerInfo, Reason> {
        launch::hand_off::<()>(self, None)
    }
}
