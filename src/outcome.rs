use std::error::Error;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::{BoxError, Claim, Level, Rights, sys};

/// What [`Builder::start`] decided. Exactly one of three things.
///
/// [`Builder::start`]: crate::Builder::start
#[must_use = "if this process became the owner, it must serve the Claim, or later launches are turned away"]
pub enum Started<T> {
    /// This process holds the lock and owns the app's state. Serve the
    /// [`Claim`] once there's somewhere to put requests; until then, later
    /// launches wait.
    Owner(Claim<T>),
    /// The owner has the payload, or will: this process should exit. See
    /// [`OwnerInfo::confirmed`].
    HandedOff(OwnerInfo),
    /// This process doesn't hold the lock, and handed nothing off. It may
    /// run anyway, or exit, but must not write the state the owner owns.
    Alone(Reason),
}

impl<T> fmt::Debug for Started<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Started::Owner(c) => f.debug_tuple("Owner").field(c).finish(),
            Started::HandedOff(h) => f.debug_tuple("HandedOff").field(h).finish(),
            Started::Alone(r) => f.debug_tuple("Alone").field(r).finish(),
        }
    }
}

/// The owner a launch reached: from [`Started::HandedOff`],
/// [`Builder::hand_off`] and [`Builder::probe`].
///
/// It displays as its pid and level, for messages: `pid 4242, high`. An
/// unknown pid shows as `pid unknown`, and an unknown level is left out.
///
/// [`Builder::hand_off`]: crate::Builder::hand_off
/// [`Builder::probe`]: crate::Builder::probe
#[derive(Debug, Clone)]
pub struct OwnerInfo {
    pub(crate) pid: Option<u32>,
    pub(crate) confirmed: bool,
    pub(crate) level: Option<Level>,
    pub(crate) handed_down: Option<Rights>,
}

impl OwnerInfo {
    /// The owner's process id, as the OS reported it for the connection.
    /// `None` where the platform doesn't say, across PID namespaces (every
    /// Flatpak instance has its own), and for an owner at another integrity
    /// level that won't take this launch's requests.
    pub fn pid(&self) -> Option<u32> {
        self.pid
    }

    /// Whether the owner said its handler took the request, or, from
    /// [`Builder::probe`], that it serves. It is `false` when this launch
    /// committed its request and then got no answer: the owner stopped,
    /// hung, or died with nothing to take its place, or its handler
    /// panicked. The request may be taken late, or not at all, and this
    /// process should still exit. It is also `false` from `probe` for an
    /// owner at another integrity level, which won't serve this launch,
    /// and for an owner this launch reported without talking to it.
    ///
    /// [`Builder::probe`]: crate::Builder::probe
    pub fn confirmed(&self) -> bool {
        self.confirmed
    }

    /// The owner's Windows integrity level, as the owner said it in its
    /// greeting or in its refusal of a launch at another level, or as the
    /// marker in its lock showed it when this launch didn't talk to it.
    /// `None` from owners on other platforms, which have no integrity
    /// levels and name none, and when this launch can't say which owner has
    /// its request, as when the owner it committed to died before it
    /// answered and no other took its place.
    pub fn level(&self) -> Option<Level> {
        self.level
    }

    /// The rights this launch gave up to hand its request to an owner that
    /// lacks them. `None` when it gave up nothing.
    pub fn handed_down(&self) -> Option<&Rights> {
        self.handed_down.as_ref()
    }
}

impl fmt::Display for OwnerInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.pid {
            Some(pid) => write!(f, "pid {pid}")?,
            None => f.write_str("pid unknown")?,
        }
        match self.level {
            Some(level) => write!(f, ", {level}"),
            None => Ok(()),
        }
    }
}

/// The state folder, held for this process's own work: what
/// [`Builder::exclusive`] returns. While it is held, no launch owns the
/// state folder, and no other exclusive run holds it, unless one of them
/// takes no [guard](crate::Guard): see `exclusive`.
///
/// Dropping it releases it at once, as [`Exclusive::release`] does, and so
/// does the process's exit. That is unlike a [`Claim`] or an
/// [`Owner`](crate::Owner), which keep the lock until the process exits.
/// So bind it to a name for as long as the work runs: `let _ = …` drops it
/// at once. A child forked from this process without `exec` holds it too,
/// until the child drops its copy or exits.
///
/// It never checks that the state folder is still in place, as an owner
/// does every minute. On Unix, should the folder be removed or replaced
/// while this is held (renamed aside and made anew, say), nothing tells
/// it, as [`End::LostState`] tells an owner, and a launch may own the
/// folder now at the path. On Windows a held guard keeps the folder in
/// place.
///
/// [`Builder::exclusive`]: crate::Builder::exclusive
#[must_use = "dropping an Exclusive releases the state at once"]
pub struct Exclusive {
    state: Option<PathBuf>,
    held: Holding,
}

/// What an [`Exclusive`] holds, until it is dropped.
#[derive(Debug)]
pub(crate) enum Holding {
    /// The state folder's guard.
    Guard(#[allow(dead_code)] sys::Guard),
    /// Without a guard, the lock in the runtime folder, and the folder.
    Lock(
        #[allow(dead_code)] sys::Folder,
        #[allow(dead_code)] sys::Lock,
    ),
}

impl Exclusive {
    /// For the canonical `state` folder, or none, held by `held`.
    pub(crate) fn new(state: Option<PathBuf>, held: Holding) -> Exclusive {
        Exclusive { state, held }
    }

    /// The state folder given to [`Builder::new`], with its links resolved
    /// as [`State::dir`] says, or `None` for [`State::none`]. Write the
    /// state through this path, and only while this `Exclusive` is held.
    ///
    /// [`Builder::new`]: crate::Builder::new
    /// [`State::dir`]: crate::State::dir
    /// [`State::none`]: crate::State::none
    pub fn state_dir(&self) -> Option<&Path> {
        self.state.as_deref()
    }

    /// Give the state folder up, as dropping this does.
    pub fn release(self) {
        drop(self);
    }
}

impl fmt::Debug for Exclusive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Exclusive")
            .field("state_dir", &self.state_dir())
            .field("guarded", &matches!(self.held, Holding::Guard(_)))
            .finish_non_exhaustive()
    }
}

/// Why an owner stopped serving: what [`Claim::on_end`] is told and
/// [`Owner::ended`] reports.
///
/// [`Owner::ended`]: crate::Owner::ended
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum End {
    /// [`Owner::stop`] or [`Owner::release`] was called, or the `Owner` was
    /// dropped. After `stop`, launches are told the owner is busy; after a
    /// drop or `release`, they find nobody listening. If the lock or the
    /// state folder is lost afterwards, [`End::LostLock`] or
    /// [`End::LostState`] replaces it.
    ///
    /// [`Owner::stop`]: crate::Owner::stop
    /// [`Owner::release`]: crate::Owner::release
    Stopped,
    /// The handler panicked. Later launches are turned away at once
    /// ([`Reason::Declined`]); this process still holds the lock.
    Panicked,
    /// Something deleted the runtime folder under this owner, and another
    /// process took the lock there before this one could re-create it. This
    /// one must stop writing the state. It gives the guard up as it ends, so
    /// a later launch can own the state folder.
    ///
    /// Only an owner that doesn't hold the state folder's
    /// [guard](crate::Guard) alone ends this way: one that holds none, or
    /// one with a [scope](crate::Builder::scope), which holds it shared, so
    /// that a launch of its scope that re-creates the folder takes the guard
    /// too and owns. An owner that holds it alone waits instead: a launch
    /// that took the lock in the re-created folder finds the guard held and
    /// lets go again, and the owner then takes the lock there itself.
    LostLock,
    /// The state folder was removed or replaced under this owner, which held
    /// its [guard](crate::Guard): renamed aside and made anew, say. Or the
    /// guard file was, and another process holds the new one. Another launch
    /// may own what is at the path now, so this one must stop writing the
    /// state. It gives up the guard, its socket and the lock as it ends, so
    /// the next launch can own the folder now at the path. Only an owner
    /// that holds the guard ends this way. A guard file removed from a state
    /// folder that is still in place is made and locked again, if nobody
    /// else holds the new one.
    LostState,
}

impl fmt::Display for End {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            End::Stopped => "stopped",
            End::Panicked => "the handler panicked",
            End::LostLock => "another process took the lock",
            End::LostState => "the state folder or its guard file was removed or replaced",
        })
    }
}

/// Why a launch may not become the owner: what [`Reason::MayNotOwn`]
/// carries. The app's [`Kind`] and [`Builder::elevated_owner`] set who may.
///
/// It displays as the cause, for messages: `its rights were raised from a
/// login`.
///
/// [`Kind`]: crate::Kind
/// [`Builder::elevated_owner`]: crate::Builder::elevated_owner
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ineligible {
    /// It can't show windows, and the app is [windowed]: as from `ssh`,
    /// cron or a system service. No [`ElevatedOwner`] lets it own.
    ///
    /// [windowed]: crate::Kind::Windowed
    /// [`ElevatedOwner`]: crate::ElevatedOwner
    NoWindows,
    /// Its rights were raised from a login, as under `sudo`, and
    /// [`ElevatedOwner::Allow`] wasn't set.
    ///
    /// [`ElevatedOwner::Allow`]: crate::ElevatedOwner::Allow
    Raised,
    /// It has more rights than a normal process (on Unix, it is root), under
    /// [`ElevatedOwner::NotAboveNormal`].
    ///
    /// [`ElevatedOwner::NotAboveNormal`]: crate::ElevatedOwner::NotAboveNormal
    AboveNormal,
}

impl fmt::Display for Ineligible {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Ineligible::NoWindows => "it can't show windows",
            Ineligible::Raised => "its rights were raised from a login",
            Ineligible::AboveNormal => "it has more rights than a normal process",
        })
    }
}

/// Why a launch runs without the lock and handed nothing off.
///
/// Every reason leaves the process able to run, as long as it writes none
/// of the state only the owner writes. An app that must not run twice turns
/// it into an error: `Started::Alone(reason) => return Err(reason.into())`.
///
/// Every variant may gain fields, so match each with `{ .. }`:
///
/// ```
/// # use instance_handoff::Reason;
/// fn exit_code(reason: &Reason) -> u8 {
///     match reason {
///         Reason::NoOwner { .. } => 1,
///         Reason::Busy { waited, .. } if waited.as_secs() > 1 => 3,
///         _ => 2,
///     }
/// }
/// # let _ = exit_code;
/// ```
#[non_exhaustive]
#[derive(Debug)]
pub enum Reason {
    /// [`Builder::hand_off`] or [`Builder::probe`], and no process owns the
    /// app.
    ///
    /// [`Builder::hand_off`]: crate::Builder::hand_off
    /// [`Builder::probe`]: crate::Builder::probe
    #[non_exhaustive]
    NoOwner {},
    /// The owner turned this launch away: [`Answer::Decline`],
    /// [`Claim::decline_all`], a `Claim` dropped unserved, or an owner whose
    /// handler panicked earlier. Or it refused this launch for a reason
    /// this build doesn't know, from a later release of this crate.
    ///
    /// [`Answer::Decline`]: crate::Answer::Decline
    #[non_exhaustive]
    Declined {},
    /// The owner answered "busy" until the timeout: it is quitting, or its
    /// queue stayed full.
    #[non_exhaustive]
    Busy {
        /// How long this launch tried.
        waited: Duration,
    },
    /// An owner holds the lock but didn't take the request before the
    /// timeout: it hasn't served yet, can't listen, or is hung. Or an
    /// [exclusive](crate::Builder::exclusive) run that took the lock
    /// without a guard holds it, and serves nothing. The request was not
    /// delivered, and won't be.
    #[non_exhaustive]
    Unresponsive {
        /// How long this launch tried.
        waited: Duration,
    },
    /// The lock holder is another app: the same id of the other [`Kind`],
    /// another id that shares the folder, or the owner of another state
    /// folder or scope whose instance folder has the same name, which only
    /// a hash collision makes. The owner names its app, kind and state when
    /// a launch connects, so the launch learns this at once and sends
    /// nothing.
    ///
    /// [`Kind`]: crate::Kind
    #[non_exhaustive]
    OtherApp {},
    /// The owner speaks no version of the handoff protocol that this launch
    /// speaks: a much older or newer release of this crate, or not this
    /// crate at all.
    #[non_exhaustive]
    WireVersion {
        /// The newest version this launch speaks.
        ours: u32,
        /// The newest version the owner speaks (0: none at all).
        theirs: u32,
    },
    /// The owner has another [`Builder::payload_version`].
    ///
    /// [`Builder::payload_version`]: crate::Builder::payload_version
    #[non_exhaustive]
    PayloadVersion {
        /// This launch's.
        ours: u32,
        /// The owner's.
        theirs: u32,
    },
    /// The owner couldn't decode the payload ([`Payload::decode`] failed).
    ///
    /// [`Payload::decode`]: crate::Payload::decode
    #[non_exhaustive]
    Undecodable {},
    /// The encoded payload is over the owner's limit. Nothing was sent.
    #[non_exhaustive]
    TooLarge {
        /// The encoded request, in bytes.
        size: usize,
        /// The owner's limit, in bytes.
        limit: usize,
    },
    /// [`Payload::encode`] failed. Nothing was sent.
    ///
    /// [`Payload::encode`]: crate::Payload::encode
    #[non_exhaustive]
    Encode {
        /// Why.
        source: BoxError,
    },
    /// The owner and this launch failed the same-user check: the socket or
    /// pipe at this launch's address is another user's, or on Windows its
    /// address folder or pipe isn't labelled at the integrity level the
    /// owner's lock shows; or the check found something else wrong or
    /// couldn't be made. One user at two levels isn't two users: a launch
    /// at another level than the owner's gets [`Reason::MoreRights`] or
    /// [`Reason::OwnerHasMoreRights`]. Each end checks the other, and an
    /// owner that refuses a launch says so at once. See the crate docs on
    /// privileges.
    #[non_exhaustive]
    Peer {
        /// What the check found.
        source: io::Error,
    },
    /// This launch has rights the owner lacks, such as a higher integrity
    /// level. The request wasn't delivered, since the owner would act on it
    /// without them. It returns at once, whatever the
    /// [timeout](crate::Builder::timeout).
    ///
    /// On Windows a launch usually learns this from the marker in the
    /// owner's lock, before it connects, and then never talks to the owner:
    /// unlike the owner's greeting, the marker can't show its app, kind or
    /// state folder.
    #[non_exhaustive]
    MoreRights {
        /// The owner.
        owner: OwnerInfo,
        /// What this launch has and the owner lacks.
        rights: Rights,
    },
    /// The owner has rights this launch lacks, such as a higher integrity
    /// level. The request wasn't delivered, since the owner would act on it
    /// with rights its launch never had. It returns at once, and like
    /// [`Reason::MoreRights`] can come from the owner's marker alone, which
    /// can't show its app, kind or state folder.
    #[non_exhaustive]
    OwnerHasMoreRights {
        /// The owner.
        owner: OwnerInfo,
        /// What the owner has and this launch lacks.
        rights: Rights,
    },
    /// This launch may not become the owner, and nobody it may hand off
    /// to is running. Or it may not hold the state with
    /// [`Builder::exclusive`], which never hands off. It never took the
    /// lock. Only a launch that can show windows may own a [windowed] app,
    /// though any may hold its state with `exclusive`, and
    /// [`Builder::elevated_owner`] says which launches with raised rights
    /// may do either.
    ///
    /// [windowed]: crate::Kind::Windowed
    /// [`Builder::elevated_owner`]: crate::Builder::elevated_owner
    /// [`Builder::exclusive`]: crate::Builder::exclusive
    #[non_exhaustive]
    MayNotOwn {
        /// Why it may not.
        why: Ineligible,
    },
    /// On Linux with systemd: this process has no login session, so the
    /// user's runtime folder (`/run/user/<uid>`) doesn't exist. Launches
    /// from cron, `@reboot` or a system service land here. Run `loginctl
    /// enable-linger` to keep the folder for good, or see the crate docs on
    /// daemons. Never returned to root, whose folder is fixed.
    #[non_exhaustive]
    NoSession {},
    /// There is no runtime folder to use (Windows without a Local AppData
    /// folder, macOS without a per-user temporary folder, Android without
    /// `TMPDIR`, a Flatpak or snap without `XDG_RUNTIME_DIR`), and
    /// [`Builder::dir`] wasn't given.
    ///
    /// [`Builder::dir`]: crate::Builder::dir
    #[non_exhaustive]
    NoRuntimeDir {},
    /// The runtime folder can't be created, or isn't safe: not the user's,
    /// open to others, a symlink, or on Windows labelled where not every
    /// integrity level can use it (above medium, or an instance folder at
    /// any level but medium) or in the profiles folder outside the user's
    /// own profile. Another user may have created it first.
    #[non_exhaustive]
    RuntimeDir {
        /// The folder.
        path: PathBuf,
        /// What went wrong.
        source: io::Error,
    },
    /// The lock file can't be opened or locked (a file system without
    /// locks, say), the missing state folder can't be made, or the state
    /// folder's [guard](crate::Guard) can't be made, opened or locked (in a
    /// state folder that is read-only or, on Windows, labelled above medium
    /// integrity, or a guard file that is another user's).
    #[non_exhaustive]
    Lock {
        /// The lock file, the state folder or the guard file.
        path: PathBuf,
        /// What went wrong.
        source: io::Error,
    },
    /// Another process holds the state folder. From [`Builder::start`], it
    /// holds the state folder's [guard](crate::Guard), but not the lock in
    /// this launch's runtime folder, so this launch can't reach it: an
    /// owner in another container, one given another [`Builder::dir`], an
    /// owner of another app id given the same state folder, one whose
    /// runtime folder was deleted and isn't made again yet, or an
    /// [exclusive](crate::Builder::exclusive) run. Or one of the two has a
    /// [scope](crate::Builder::scope) and the other hasn't: owners with
    /// scopes share the guard only with one another. This launch let go of
    /// its lock before anyone could connect. Only `start` and `exclusive`
    /// take the guard.
    ///
    /// From `exclusive`, it is any owner of the state folder, or another
    /// exclusive run, that holds the guard. Where `exclusive` takes no
    /// guard, it is an owner or another exclusive run that holds the lock
    /// in its runtime folder, on Windows at any integrity level.
    ///
    /// [`Builder::dir`]: crate::Builder::dir
    /// [`Builder::start`]: crate::Builder::start
    #[non_exhaustive]
    StateInUse {
        /// The guard file, or the lock file for an exclusive run that takes
        /// no guard.
        path: PathBuf,
    },
    /// The state folder, or the folder it would be created in, belongs to
    /// another user: root given the user's home by `sudo -E`, say. Nothing
    /// was created. Only [`Builder::start`] and [`Builder::exclusive`]
    /// check this; see [`Builder::new`].
    ///
    /// [`Builder::start`]: crate::Builder::start
    /// [`Builder::exclusive`]: crate::Builder::exclusive
    /// [`Builder::new`]: crate::Builder::new
    #[non_exhaustive]
    ForeignState {
        /// The folder that belongs to another user: the state folder, or
        /// the nearest folder above it that exists.
        path: PathBuf,
    },
    /// This crate doesn't support the target platform (the web, WASI,
    /// Solaris, iOS and others), so no process can be the owner. An app
    /// that runs one process by design owns its state anyway:
    /// `Started::Alone(Reason::Unsupported { .. }) => /* own it */`.
    #[non_exhaustive]
    Unsupported {},
}

impl Reason {
    pub(crate) fn runtime_dir(path: impl Into<PathBuf>, source: io::Error) -> Reason {
        Reason::RuntimeDir {
            path: path.into(),
            source,
        }
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reason::NoOwner {} => f.write_str("no instance is running"),
            Reason::Declined {} => f.write_str("the running instance turned this launch away"),
            Reason::Busy { waited } => {
                write!(f, "the running instance stayed busy for {waited:?}")
            }
            Reason::Unresponsive { waited } => {
                write!(f, "an instance is running but didn't answer in {waited:?}")
            }
            Reason::OtherApp {} => f.write_str(
                "another app, or this one of the other kind or of another state, holds the \
                 runtime folder",
            ),
            Reason::WireVersion { ours, theirs } => write!(
                f,
                "the running instance speaks handoff protocol {theirs}, this one {ours}"
            ),
            Reason::PayloadVersion { ours, theirs } => write!(
                f,
                "the running instance is another version (payload {theirs}, this one {ours})"
            ),
            Reason::Undecodable {} => f.write_str("the running instance couldn't read the request"),
            Reason::TooLarge { size, limit } => {
                write!(
                    f,
                    "the request is {size} bytes, over the {limit}-byte limit"
                )
            }
            Reason::Encode { source } => write!(f, "couldn't encode the request: {source}"),
            Reason::Peer { source } => write!(f, "the running instance isn't ours: {source}"),
            Reason::MoreRights { owner, rights } => write!(
                f,
                "the running instance ({owner}) lacks this launch's {rights}"
            ),
            Reason::OwnerHasMoreRights { owner, rights } => write!(
                f,
                "the running instance ({owner}) has {rights}, which this launch lacks"
            ),
            Reason::MayNotOwn { why } => {
                write!(f, "this launch may not become the running instance: {why}")
            }
            Reason::NoSession {} => f.write_str(
                "no login session, so no runtime folder (`loginctl enable-linger` keeps one)",
            ),
            Reason::NoRuntimeDir {} => f.write_str("no runtime folder"),
            Reason::RuntimeDir { path, source } => {
                write!(f, "runtime folder {}: {source}", path.display())
            }
            Reason::Lock { path, source } => write!(f, "lock {}: {source}", path.display()),
            Reason::StateInUse { path } => write!(
                f,
                "an instance this launch can't reach holds the state folder: {}",
                path.display()
            ),
            Reason::ForeignState { path } => write!(
                f,
                "the state folder, or the folder it would be created in, belongs to another user: {}",
                path.display()
            ),
            Reason::Unsupported {} => {
                f.write_str("single-instance handoff isn't available on this platform")
            }
        }
    }
}

impl Error for Reason {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Reason::Encode { source } => Some(&**source),
            Reason::Peer { source }
            | Reason::RuntimeDir { source, .. }
            | Reason::Lock { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(pid: Option<u32>, level: Option<Level>) -> OwnerInfo {
        OwnerInfo {
            pid,
            confirmed: true,
            level,
            handed_down: None,
        }
    }

    #[test]
    fn owners_display_their_pid_and_level() {
        assert_eq!(
            owner(Some(4242), Some(Level::HIGH)).to_string(),
            "pid 4242, high"
        );
        assert_eq!(owner(Some(4242), None).to_string(), "pid 4242");
        assert_eq!(
            owner(None, Some(Level::MEDIUM)).to_string(),
            "pid unknown, medium"
        );
        assert_eq!(owner(None, None).to_string(), "pid unknown");
    }

    #[test]
    fn rights_reasons_name_the_owner_and_the_rights() {
        let more = Reason::MoreRights {
            owner: owner(Some(4242), Some(Level::MEDIUM)),
            rights: Rights::Level {
                launch: Level::HIGH,
                owner: Level::MEDIUM,
            },
        };
        assert_eq!(
            more.to_string(),
            "the running instance (pid 4242, medium) lacks this launch's high integrity"
        );
        let fewer = Reason::OwnerHasMoreRights {
            owner: owner(None, Some(Level::HIGH)),
            rights: Rights::Level {
                launch: Level::MEDIUM,
                owner: Level::HIGH,
            },
        };
        assert_eq!(
            fewer.to_string(),
            "the running instance (pid unknown, high) has high integrity, which this launch lacks"
        );
        assert!(more.source().is_none() && fewer.source().is_none());
    }

    #[test]
    fn ends_say_why() {
        assert_eq!(End::LostLock.to_string(), "another process took the lock");
        assert_eq!(
            End::LostState.to_string(),
            "the state folder or its guard file was removed or replaced"
        );
    }

    #[test]
    fn foreign_state_names_the_folder() {
        let reason = Reason::ForeignState {
            path: PathBuf::from("/home/me"),
        };
        assert!(
            reason.to_string().ends_with("another user: /home/me"),
            "{reason}"
        );
        assert!(reason.source().is_none());
    }

    #[test]
    fn state_in_use_names_the_guard() {
        let reason = Reason::StateInUse {
            path: PathBuf::from("/home/me/app/.instance-handoff.lock"),
        };
        assert_eq!(
            reason.to_string(),
            "an instance this launch can't reach holds the state folder: \
             /home/me/app/.instance-handoff.lock"
        );
        assert!(reason.source().is_none());
    }

    #[test]
    fn may_not_own_says_why() {
        let raised = Reason::MayNotOwn {
            why: Ineligible::Raised,
        };
        assert_eq!(
            raised.to_string(),
            "this launch may not become the running instance: its rights were raised from a login"
        );
        let above = Reason::MayNotOwn {
            why: Ineligible::AboveNormal,
        };
        assert_eq!(
            above.to_string(),
            "this launch may not become the running instance: it has more rights than a normal process"
        );
        let no_windows = Reason::MayNotOwn {
            why: Ineligible::NoWindows,
        };
        assert_eq!(
            no_windows.to_string(),
            "this launch may not become the running instance: it can't show windows"
        );
        assert!(raised.source().is_none());
    }
}
