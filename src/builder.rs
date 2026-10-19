use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::server::Upkeep;
use crate::{AppId, OwnerInfo, Payload, Reason, Started, launch, naming, state, sys};

/// The folder an app keeps its state in: the files only the owner writes.
/// [`Builder::new`] takes it, and the owner reports it, with its links
/// resolved, as [`Claim::state_dir`] and [`Owner::state_dir`].
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
    /// [`Reason::ForeignState`].
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
    ///
    /// [`Claim::decline_all`]: crate::Claim::decline_all
    Separate,
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
    scope: Option<OsString>,
    dir: Option<PathBuf>,
    pub(crate) mode: Mode,
    pub(crate) timeout: Duration,
    pub(crate) payload_version: u32,
    pub(crate) upkeep: Upkeep,
}

impl Builder {
    /// A builder for `app_id`, whose state is in `state` ([`State::dir`]),
    /// or which keeps none ([`State::none`]). The defaults: the default
    /// runtime folder, [`Mode::Join`], a 5 second timeout and payload
    /// version 0.
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
    ///   launches pass only root's.
    /// - On Windows, a folder of the launch's user, SYSTEM, Administrators
    ///   or TrustedInstaller passes, and so does any folder on a volume
    ///   that keeps no owners, such as FAT.
    /// - A folder whose owner can't be read passes, with a warning in the
    ///   log.
    ///
    /// [`hand_off`](Builder::hand_off) and [`probe`](Builder::probe) write
    /// nothing there, and don't check.
    pub fn new(app_id: AppId, state: impl Into<State>) -> Builder {
        Builder {
            app_id,
            state: state.into(),
            scope: None,
            dir: None,
            mode: Mode::Join,
            timeout: Duration::from_secs(5),
            payload_version: 0,
            upkeep: Upkeep::default(),
        }
    }

    /// One owner per `scope` rather than one per user: per login session
    /// (`XDG_SESSION_ID`), per profile, per container, per scratch
    /// configuration. The scope names a subfolder of the runtime folder:
    /// 16 hex digits of the FNV-1a 64 hash of its bytes.
    ///
    /// The scope is a key, compared byte for byte, not a path: `cfg`,
    /// `./cfg/` and a symlink to it are three scopes, and a relative path
    /// means one scope for every folder of that name. To key on a folder,
    /// create it and pass [`std::fs::canonicalize`] of it.
    pub fn scope(mut self, scope: impl AsRef<OsStr>) -> Builder {
        self.scope = Some(scope.as_ref().to_os_string());
        self
    }

    /// Use `dir` instead of the default runtime folder ([`Builder::scope`]
    /// still adds its subfolder). It must be on a local disk. It is created
    /// private when missing. A folder that isn't the user's alone (on Unix:
    /// a symlink, another user's, or open to group or others; on Windows: a
    /// link, or one that others may change or read) is refused with
    /// [`Reason::RuntimeDir`].
    ///
    /// Every launch that should meet must pass the same folder. A folder
    /// serves one privilege level: on Windows, one made at another
    /// integrity level is refused with [`Reason::RuntimeDir`], so elevated
    /// and normal launches given the same folder don't share it. For tests,
    /// a fresh temporary folder per test keeps a panicking test's lock from
    /// blocking the next.
    pub fn dir(mut self, dir: impl Into<PathBuf>) -> Builder {
        self.dir = Some(dir.into());
        self
    }

    /// See [`Mode`]. Defaults to [`Mode::Join`].
    pub fn mode(mut self, mode: Mode) -> Builder {
        self.mode = mode;
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

    /// The runtime folder `start` would use, without creating anything. For
    /// diagnostics and tests. `None` when there is none to use: see
    /// [`Reason::NoSession`], [`Reason::NoRuntimeDir`] and
    /// [`Reason::Unsupported`].
    pub fn runtime_dir(&self) -> Option<PathBuf> {
        if !sys::SUPPORTED {
            return None;
        }
        self.place().ok().map(|p| p.path())
    }

    /// The state folder, canonical. Resolved as the launch decides, not in
    /// `new`: the working directory and the links may change in between.
    pub(crate) fn canonical_state(&self) -> Option<PathBuf> {
        self.state.dir.as_deref().map(state::canonical)
    }

    pub(crate) fn place(&self) -> Result<sys::Place, Reason> {
        let mut place = match &self.dir {
            // Absolute now: a later change of working directory must not
            // move the owner's folder.
            Some(dir) => {
                sys::Place::dir(std::path::absolute(dir).map_err(|e| Reason::runtime_dir(dir, e))?)
            }
            None => sys::default_place(&self.app_id)?,
        };
        if let Some(scope) = &self.scope {
            place.push(naming::scope_folder(scope));
        }
        Ok(place)
    }

    /// Take the lock, or hand `payload` to the process holding it.
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
