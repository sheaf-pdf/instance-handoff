use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::server::Upkeep;
use crate::{AppId, Exclusive, OwnerInfo, Payload, Reason, Started, launch, naming, state, sys};

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
    /// derived from. It needn't exist. The app must never replace or rename
    /// it, though it may replace the files in it. On Unix an owner that
    /// holds its [guard](Guard) ends with [`End::LostState`] when it is
    /// replaced; on Windows, replacing or renaming it fails while the owner
    /// holds the guard. See the crate docs on the state.
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
    ///
    /// [`End::LostState`]: crate::End::LostState
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

/// Whether the owner takes the state folder's guard: see
/// [`Builder::guard`].
///
/// The guard is a lock on `.instance-handoff.lock` in the state folder,
/// which the owner takes after the lock in its runtime folder and holds as
/// long. Launches that name one state folder can still end up in two
/// runtime folders: in two containers, say, given two [`Builder::dir`]
/// folders, or as two app ids that share the folder. The one that takes
/// its lock second finds the guard held, lets go of its lock and runs
/// alone at once with [`Reason::StateInUse`], rather than own the state
/// folder beside the first.
///
/// An owner with a [scope](Builder::scope) takes the guard shared. Owners
/// with scopes then hold it side by side, whatever their scopes and
/// runtime folders, but never beside an owner without one: whichever of
/// the two comes second runs alone with [`Reason::StateInUse`].
///
/// [`Builder::exclusive`] takes the guard alone, with a scope or without,
/// and no lock in a runtime folder. So it keeps out every owner and every
/// other exclusive run that takes the guard, wherever their runtime
/// folders are.
///
/// `start`, `try_own` and `exclusive` make the guard file in the state folder, which
/// they have created if it was missing (see [`Builder::new`]): on Unix with
/// mode 0600, and on Windows with an access list for the user and SYSTEM
/// and a medium label, so that every integrity level can lock it. The file
/// is never written.
/// Like the lock, the guard is held until the process exits, or until
/// [`Owner::release`] or [`Claim::release`] gives both up, and a child
/// forked from the owner holds it too until it exits. An exclusive run
/// holds it only until its [`Exclusive`] is dropped. On Windows, while
/// the guard is held, the file can't be removed, nor the state folder
/// renamed or removed. On Unix they can, and every minute the owner checks
/// that their paths still name the folder and the file it holds. It makes
/// and locks a removed guard file again, unless another process holds the
/// new one. A state folder removed or replaced, or a new guard file that
/// another process holds, ends the owner with [`End::LostState`]. An
/// exclusive run never checks: see [`Exclusive`].
///
/// No guard is taken, and no guard file made, under [`Guard::Off`] and for
/// [`State::none`]. Nor is one held on a network file system, or where the
/// file system can't lock files: see [`Guard::Local`].
/// An owner that holds none doesn't keep out launches in other runtime
/// folders, with a scope or without, nor an exclusive run that takes the
/// guard. [`Claim::guarded`] says whether the owner holds it. An exclusive
/// run that can't take the guard takes the lock in its runtime folder
/// instead.
///
/// [`Owner::release`]: crate::Owner::release
/// [`Claim::release`]: crate::Claim::release
/// [`Claim::guarded`]: crate::Claim::guarded
/// [`End::LostState`]: crate::End::LostState
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Guard {
    /// Take the guard on a local disk. One that can't be made or opened
    /// gives [`Reason::Lock`]: the state folder is read-only, say, or the
    /// guard file is another user's, or on Windows the state folder is
    /// labelled above medium integrity, where a launch at medium couldn't
    /// lock the guard.
    ///
    /// On a network file system the owner takes no guard and makes no
    /// guard file. A lock there would reach every host that mounts it, and
    /// one held by a host that crashed can stay held. So each host keeps an
    /// owner of its own. On Linux that means NFS, SMB and CIFS, 9p (as WSL
    /// 2 mounts the Windows drives), AFS, Ceph, Coda, NCP, Lustre, GFS2,
    /// OCFS2 and VirtualBox shared folders, but not FUSE, whatever serves
    /// it. On macOS and the BSDs it means a file system not marked
    /// `MNT_LOCAL`, and on illumos NFS and SMB. On Windows it means a share
    /// (`\\server\share`, which a mapped drive resolves to), or a drive
    /// that Windows says is remote.
    ///
    /// Where the file system can't lock files (`ENOLCK` or `EOPNOTSUPP`,
    /// and on Windows `ERROR_NOT_SUPPORTED` or `ERROR_INVALID_FUNCTION`),
    /// the owner holds no guard either. Either way [`Claim::guarded`] is
    /// false.
    ///
    /// [`Claim::guarded`]: crate::Claim::guarded
    #[default]
    Local,
    /// Take no guard, and make no guard file. A missing state folder is
    /// still made. Owners of the folder in two runtime folders then run
    /// side by side. An [exclusive](Builder::exclusive) run takes the lock
    /// in its runtime folder instead, so only an owner, or another
    /// exclusive run, there keeps it out. For config that is read-only or
    /// shared, and for a folder that a sync tool copies between machines.
    Off,
}

/// Which launches with raised rights may become the owner when nobody is:
/// see [`Builder::elevated_owner`].
///
/// A launch that may not own never takes the lock. It hands off as
/// [`Builder::hand_off`] does, and where that finds no owner, it runs alone
/// at once with [`Reason::MayNotOwn`]. This only keeps launches from
/// owning: it never lets one hand off where it otherwise couldn't. It also
/// says who may hold the state with [`Builder::exclusive`], which otherwise
/// fails at once with [`Reason::MayNotOwn`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ElevatedOwner {
    /// A launch whose rights were raised from a login doesn't own
    /// ([`Ineligible::Raised`]). On Unix that is root whose person is
    /// known and isn't root: `sudo`, `run0`, `pkexec`, `doas`, and on Linux
    /// `su`. Root's own login and systemd's services still own. On Windows
    /// it is a launch with the full half of a token that UAC split, above
    /// medium integrity: Run as administrator, or Windows `sudo`, with UAC
    /// on. A medium token made from that half with SAFER isn't raised, as
    /// on Unix a launch that is no longer root isn't; but
    /// `runas /trustlevel:0x20000` from an elevated shell keeps high
    /// integrity, so its launches are. An
    /// administrator with UAC off has no split token, and nor has the
    /// built-in Administrator unless Admin Approval Mode covers it, so
    /// their elevated launches still own. An elevated OpenSSH logon owns
    /// too if, as expected, its token isn't split. See the crate docs on
    /// privileges, which also cover containers.
    ///
    /// [`Ineligible::Raised`]: crate::Ineligible::Raised
    #[default]
    NotRaised,
    /// Also no owner with more rights than a normal process
    /// ([`Ineligible::AboveNormal`]): on Unix, no root launch owns, so
    /// root never keeps the state. On Windows no launch above medium
    /// integrity owns, raised or not, though one at the UIAccess level
    /// ([`Level::UI_ACCESS`], medium with UIAccess), as accessibility tools
    /// run, still does. Medium plus counts as above medium, and so does
    /// high with UIAccess.
    ///
    /// [`Ineligible::AboveNormal`]: crate::Ineligible::AboveNormal
    /// [`Level::UI_ACCESS`]: crate::Level::UI_ACCESS
    NotAboveNormal,
    /// A launch's rights never keep it from owning. A launch under `sudo`
    /// becomes root's owner when root has none, and root's later launches
    /// hand off to it. On Windows a launch run as administrator becomes
    /// the owner when nobody is, and normal launches then run alone with
    /// [`Reason::OwnerHasMoreRights`].
    Allow,
}

/// Configures and runs the decision: own, hand off, or run alone.
///
/// ```
/// use std::path::Path;
/// use std::time::Duration;
/// use instance_handoff::{AppId, Builder};
///
/// const APP: AppId = AppId::windowed("org.example.Viewer");
///
/// // `data` is the folder the viewer keeps its state in.
/// fn builder(data: &Path) -> Builder {
///     Builder::new(APP, data).timeout(Duration::from_secs(1))
/// }
/// # let _ = builder;
/// ```
#[must_use = "a Builder does nothing until `start`, `try_own`, `hand_off`, `probe` or `exclusive`"]
#[derive(Debug, Clone)]
pub struct Builder {
    pub(crate) app_id: AppId,
    state: State,
    pub(crate) scope: Option<OsString>,
    dir: Option<PathBuf>,
    pub(crate) guard: Guard,
    pub(crate) elevated_owner: ElevatedOwner,
    pub(crate) hand_down: bool,
    pub(crate) timeout: Duration,
    pub(crate) payload_version: u32,
    pub(crate) upkeep: Upkeep,
}

impl Builder {
    /// A builder for `app_id`, whose state is in `state` ([`State::dir`]),
    /// or which keeps none ([`State::none`]). The defaults: the default
    /// runtime folder, [`Guard::Local`], [`ElevatedOwner::NotRaised`],
    /// [`hand_down`](Builder::hand_down) off, a 5 second timeout and payload
    /// version 0.
    ///
    /// Launches of `app_id` that name one state folder, through whatever
    /// links, and one [scope](Builder::scope) meet one owner. Launches that
    /// name two folders get two owners. Each user has owners of its own:
    /// see the crate docs on where the lock lives. On Windows every
    /// integrity level meets the one owner, and a launch at another level
    /// than the owner's runs alone at once, unless it is above the owner
    /// and hands its request down ([`hand_down`](Builder::hand_down); see
    /// the crate docs on privileges). The owner also holds a lock in the
    /// state folder, the [guard](Guard), so a launch that finds another
    /// runtime folder, as in another container, runs alone with
    /// [`Reason::StateInUse`] rather than become a second owner of that
    /// state folder. Owners with a scope share the guard with one another,
    /// never with an owner without one.
    ///
    /// Before [`start`](Builder::start), [`try_own`](Builder::try_own) or
    /// [`exclusive`](Builder::exclusive) creates anything, it checks whose
    /// the state folder is, or, while it is missing, whose the nearest
    /// folder above it is. If that folder belongs to another user, the
    /// launch runs alone, or `try_own` and `exclusive` fail, with
    /// [`Reason::ForeignState`]. That catches root
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
    /// Once they hold the lock, `start` and `try_own` create the state
    /// folder if it is missing, with the folders above it, whatever the
    /// [guard](Guard).
    /// `exclusive` does so before it takes the guard. The last one is
    /// private: mode 0700 on Unix, and on Windows an access list for the
    /// user and SYSTEM alone, which what is made in it inherits. One that
    /// can't be made gives [`Reason::Lock`].
    pub fn new(app_id: AppId, state: impl Into<State>) -> Builder {
        Builder {
            app_id,
            state: state.into(),
            scope: None,
            dir: None,
            guard: Guard::Local,
            elevated_owner: ElevatedOwner::NotRaised,
            hand_down: false,
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
    /// Owners with a scope take the state folder's [guard](Guard) shared,
    /// so they hold it side by side, whatever their scopes. An owner
    /// without one holds it alone: while it runs, a launch with a scope that
    /// would own runs alone with [`Reason::StateInUse`], and while owners
    /// with scopes run, so does a launch without one. So pass a scope to
    /// every launch of a state folder, or to none. An
    /// [exclusive](Builder::exclusive) run holds the guard alone, whatever
    /// its scope.
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
    /// share the guard. On Windows every integrity level shares it, as it
    /// does Local AppData: it is made with no label, whatever level makes
    /// it, and elevated and normal launches given it meet one owner. One
    /// labelled above medium integrity, where a launch at medium couldn't
    /// make the instance folder, is refused with [`Reason::RuntimeDir`].
    ///
    /// For tests, a fresh temporary folder and state folder per test, side
    /// by side, keep a panicking test's lock and guard from blocking the
    /// next.
    pub fn dir(mut self, dir: impl Into<PathBuf>) -> Builder {
        self.dir = Some(dir.into());
        self
    }

    /// Whether the owner takes the state folder's guard: see [`Guard`].
    /// Defaults to [`Guard::Local`]. Only `start`, `try_own` and `exclusive`
    /// take the guard. `hand_off` and `probe` look at it only under `Guard::Local`,
    /// and only where they have no runtime folder to look in: see
    /// [`Builder::hand_off`].
    pub fn guard(mut self, guard: Guard) -> Builder {
        self.guard = guard;
        self
    }

    /// Which launches with raised rights may become the owner when nobody
    /// is, or hold the state with `exclusive`: see [`ElevatedOwner`].
    /// Defaults to [`ElevatedOwner::NotRaised`]. `hand_off` and `probe`
    /// never own, so they don't look at it.
    pub fn elevated_owner(mut self, policy: ElevatedOwner) -> Builder {
        self.elevated_owner = policy;
        self
    }

    /// Whether a launch with rights the owner lacks gives them up and hands
    /// its request down, rather than fail with [`Reason::MoreRights`]
    /// (`start` then runs alone). Defaults to `false`. The only such right
    /// compared is a higher Windows integrity level, as a launch has from
    /// an administrator terminal, Windows `sudo`, Run as administrator, an
    /// elevated SSH or WinRM logon, or UIAccess.
    ///
    /// No property of a token tells deliberate elevation from incidental,
    /// so the crate never decides this itself. Set it per call, on a clone,
    /// for the commands that need no rights (`b.clone().hand_down(true)`),
    /// and leave it off for the rest. The owner admits a launch above its
    /// level only when it hands down, and tells its handler what was given
    /// up, as [`Request::handed_down`]; the launch sees the same in
    /// [`OwnerInfo::handed_down`]. Both come from the levels Windows
    /// reports, never from what the launch says.
    ///
    /// A request is never handed up, and never goes to another user. On
    /// Unix, `sudo`, `su`, `doas`, `pkexec` and `run0` launch as root, whose
    /// launches meet root's owner, so this changes nothing there. Applies
    /// to `start` and `hand_off`: `probe`, [`try_own`](Builder::try_own) and
    /// [`exclusive`](Builder::exclusive) hand nothing over, and ignore it.
    /// On Windows a launch that hands down reaches the owner through the
    /// folder of the owner's level, and checks that the folder and the
    /// owner's pipe are labelled at the level the owner's lock shows (see
    /// the crate docs on privileges).
    ///
    /// [`Request::handed_down`]: crate::Request::handed_down
    pub fn hand_down(mut self, allow: bool) -> Builder {
        self.hand_down = allow;
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
    /// [`Builder::dir`]. On Windows every integrity level shares it. The
    /// state folder's links are resolved as `start` resolves them. For
    /// diagnostics and tests. `None` when there is none to use: see
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
    /// launch that may not own never takes the lock: it hands off as
    /// [`Builder::hand_off`] does, and where that finds no owner, it runs
    /// alone with [`Reason::MayNotOwn`]. That is a
    /// [windowed](crate::Kind::Windowed) app's launch that can't show
    /// windows, or one with raised rights ([`Builder::elevated_owner`]). A
    /// process that may take no part at all, as a setuid or setgid program
    /// that runs with its rights, or on Windows one in a sandbox, does
    /// neither, and runs alone at once with [`Reason::Excluded`].
    ///
    /// Blocks for at most the [timeout](Builder::timeout) plus the greater
    /// of the timeout and one second, and usually for a few milliseconds.
    /// `payload` is encoded only if it is handed off. On the hand-off path
    /// this reads `XDG_ACTIVATION_TOKEN` and `DESKTOP_STARTUP_ID` (and never
    /// unsets them); on Windows it lets the owner's process take the
    /// foreground. Creates no thread. Never panics.
    pub fn start<T: Payload>(&self, payload: &T) -> Started<T> {
        launch::start(self, payload)
    }

    /// Take the lock, or run alone: like [`Builder::start`], but a launch
    /// that finds the lock held never hands off. For `--new-instance`
    /// flags, and for developer and debug builds, that run beside a running
    /// app but should own when nothing else does. Taking the lock is the
    /// decision, so two launches never both own, and nothing is handed to
    /// an owner that took the lock first.
    ///
    /// ```no_run
    /// use std::sync::mpsc::Receiver;
    /// use instance_handoff::{AppId, Args, Builder, Owner, Request};
    ///
    /// const APP: AppId = AppId::windowed("org.example.Viewer");
    /// # fn data_dir() -> std::path::PathBuf { unimplemented!() }
    /// # fn view(_: Args, _: Owner, _: Receiver<Request<Args>>) {}
    /// # fn view_alone(_: Args) {}
    ///
    /// // `--new-instance`: a window of its own, whatever else runs.
    /// let args = Args::from_env();
    /// match Builder::new(APP, data_dir()).try_own::<Args>() {
    ///     // Nothing else runs: own, and take later launches' requests.
    ///     Ok(claim) => {
    ///         let (tx, rx) = std::sync::mpsc::channel();
    ///         view(args, claim.serve(move |r| tx.send(r).is_ok()), rx);
    ///     }
    ///     // Another process holds the state, or this launch may not own:
    ///     // run beside it, without writing the state.
    ///     Err(reason) => {
    ///         eprintln!("{reason}");
    ///         view_alone(args);
    ///     }
    /// }
    /// ```
    ///
    /// With the lock free, it owns as `start` does: it takes the state
    /// folder's [guard](Guard) too, and returns the [`Claim`] to serve. The
    /// `Claim`'s payload type is named (`try_own::<Args>()`) unless the
    /// handler given to [`Claim::serve`] lets the compiler infer it. With
    /// the lock held, by an owner at any integrity level, one still
    /// starting, or an [exclusive](Builder::exclusive) run that takes no
    /// guard, it fails with [`Reason::StateInUse`], naming the lock file.
    /// With the lock free and the guard held, by an owner in another
    /// runtime folder or an exclusive run, it fails with `StateInUse` too,
    /// naming the guard file. It never connects to an owner.
    ///
    /// It checks first what `start` checks before it takes the lock. A
    /// process that may take no part at all, as a setuid or setgid program
    /// that runs with its rights, or on Windows one in a sandbox, fails at
    /// once with [`Reason::Excluded`]. A launch that may not own fails at
    /// once with [`Reason::MayNotOwn`]: a
    /// [windowed](crate::Kind::Windowed) app's launch that can't show
    /// windows, or one with raised rights ([`Builder::elevated_owner`]).
    /// Then it checks whose the state folder is ([`Reason::ForeignState`]),
    /// and once it holds the lock, creates it if it is missing (see
    /// [`Builder::new`]).
    ///
    /// Never waits for an owner, whatever the [timeout](Builder::timeout):
    /// it looks again at a held lock, and at a held guard, for 50 ms each,
    /// so that a `hand_off` or `probe` testing the lock, or an owner that is
    /// exiting, isn't taken for one that runs. Creates no thread. Never
    /// panics.
    ///
    /// [`Claim`]: crate::Claim
    /// [`Claim::serve`]: crate::Claim::serve
    pub fn try_own<T: Payload>(&self) -> Result<crate::Claim<T>, Reason> {
        launch::try_own(self)
    }

    /// Hand `payload` to the owner, and never become one: with nobody
    /// running, fail at once with [`Reason::NoOwner`]. For command-line
    /// front ends (`app --remote open x`, `appctl reload`) that only make
    /// sense against a running app. Creates no folder and no lock.
    ///
    /// Without a runtime folder to look in (on Linux without a login
    /// session, say, or where no launch has made it yet), it can reach no
    /// owner, and looks at the state folder's [guard](Guard) instead, as
    /// `start` would take it: shared with a [scope](Builder::scope), and
    /// alone without one. While another process holds it so that `start`
    /// couldn't own, as an owner in another runtime folder or an exclusive
    /// run may, it fails at once with [`Reason::StateInUse`], and otherwise
    /// with [`Reason::NoOwner`]. So with a scope, owners with scopes, which
    /// `start` would own beside, give `NoOwner`, while an owner without one
    /// or an exclusive run gives `StateInUse`. It never fails with
    /// [`Reason::NoSession`] or [`Reason::NoRuntimeDir`].
    pub fn hand_off<T: Payload>(&self, payload: &T) -> Result<OwnerInfo, Reason> {
        launch::hand_off(self, Some(payload))
    }

    /// Whether an owner is serving, without handing anything over or
    /// becoming one: `Ok` when it would pass a request to its handler now.
    /// The owner's handler isn't called. For status commands and for tests
    /// that wait for an owner to be ready.
    ///
    /// Fails as [`Builder::hand_off`] would: at once with
    /// [`Reason::NoOwner`] when nobody holds the lock, or, without a
    /// runtime folder to look in, with [`Reason::StateInUse`] while another
    /// process holds the state folder's [guard](Guard) so that `start`
    /// couldn't own; with
    /// [`Reason::Declined`] for an owner that turns launches away, and with
    /// [`Reason::Busy`] or [`Reason::Unresponsive`] when the owner hasn't
    /// served (or has stopped) by the [timeout](Builder::timeout). A probe
    /// never hands anything down, so an owner at another integrity level,
    /// as the marker in its lock or its greeting shows, is `Ok` at once,
    /// with its [level](OwnerInfo::level) and [`OwnerInfo::confirmed`]
    /// false. That doesn't mean `start` and `hand_off` fail: an owner below
    /// still takes their requests from a builder with
    /// [`hand_down`](Builder::hand_down), though one above takes none. Read
    /// from the marker, before connecting, that answer can't check the
    /// owner's app, kind or state folder, as the greeting does. Creates no
    /// folder and no lock.
    pub fn probe(&self) -> Result<OwnerInfo, Reason> {
        launch::hand_off::<()>(self, None)
    }

    /// Hold the state folder for this process's own work, without becoming
    /// the owner: for batch subcommands, migrations, cron jobs and CI steps.
    /// Nothing is handed off, and no launch can reach this process. For a
    /// `--new-instance` flag, which should own when nothing else runs, see
    /// [`Builder::try_own`]. Write the state through
    /// [`Exclusive::state_dir`], and only while the `Exclusive` is held.
    /// Dropping it releases the state folder at once, unlike a
    /// [`Claim`](crate::Claim) or an [`Owner`](crate::Owner), which keep
    /// the lock until the process exits.
    ///
    /// ```no_run
    /// use std::path::Path;
    /// use instance_handoff::{AppId, Builder, Reason};
    ///
    /// const APP: AppId = AppId::windowed("org.example.Viewer");
    /// # fn rewrite_library(_: &Path) {}
    ///
    /// fn migrate(data: &Path) -> Result<(), Reason> {
    ///     let held = Builder::new(APP, data).exclusive()?;
    ///     if let Some(dir) = held.state_dir() {
    ///         rewrite_library(dir);
    ///     }
    ///     held.release();
    ///     Ok(())
    /// }
    /// # let _ = migrate;
    /// ```
    ///
    /// It takes the state folder's [guard](Guard) alone, with a
    /// [scope](Builder::scope) or without, and no lock in a runtime folder,
    /// so it behaves the same whoever is logged in. It fails at once with
    /// [`Reason::StateInUse`] while an owner of the state folder, with a
    /// scope or without, or another exclusive run holds the guard, and
    /// while it holds the guard, a `start` that would own runs alone, and a
    /// `try_own` fails, with [`Reason::StateInUse`]. Like `start`, it checks whose the state
    /// folder is first ([`Reason::ForeignState`]), and creates it if it is
    /// missing (see [`Builder::new`]).
    ///
    /// An owner that holds no guard, as under [`Guard::Off`], doesn't keep
    /// out an exclusive run that holds one. Where `exclusive` takes no
    /// guard itself, for [`State::none`], under [`Guard::Off`], on a network
    /// file system or where the file system can't lock files (see
    /// [`Guard::Local`]), it takes the lock in the runtime folder instead,
    /// as an owner would, but serves nothing. Then it fails with
    /// [`Reason::StateInUse`] while an owner, or another exclusive run, of
    /// that runtime folder holds the lock, on Windows at any integrity
    /// level. While it holds the lock, launches there find nobody serving,
    /// and run alone, or fail, with [`Reason::Unresponsive`] at their
    /// timeout. On Windows only those at its integrity level wait, and
    /// those above it that hand their request down
    /// ([`hand_down`](Builder::hand_down)). Any other launch at another
    /// level reads this run's level from the lock, as it would an owner's,
    /// and is answered at once (see the crate docs on privileges).
    ///
    /// A process that may take no part at all, as a setuid or setgid
    /// program that runs with its rights, or on Windows one in a sandbox,
    /// fails at once with [`Reason::Excluded`], before anything else is
    /// checked. A launch that may not own under [`Builder::elevated_owner`]
    /// fails at once with [`Reason::MayNotOwn`]. A
    /// [windowed](crate::Kind::Windowed) app's exclusive run needs no
    /// windows, since it serves no launches.
    ///
    /// Never waits for the state folder to come free, whatever the
    /// [timeout](Builder::timeout). Creates no thread. Never panics.
    pub fn exclusive(&self) -> Result<Exclusive, Reason> {
        launch::exclusive(self)
    }
}
