use std::error::Error;
use std::fmt;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use crate::{BoxError, Claim, Level, Rights};

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
    /// `None` where the platform doesn't say, and across PID namespaces
    /// (every Flatpak instance has its own).
    pub fn pid(&self) -> Option<u32> {
        self.pid
    }

    /// Whether the owner said its handler took the request, or, from
    /// [`Builder::probe`], that it serves. It is `false` when this launch
    /// committed its request and then got no answer: the owner stopped,
    /// hung, or died with nothing to take its place, or its handler
    /// panicked. The request may be taken late, or not at all, and this
    /// process should still exit. It is also `false` for an owner this
    /// launch reported without talking to it.
    ///
    /// [`Builder::probe`]: crate::Builder::probe
    pub fn confirmed(&self) -> bool {
        self.confirmed
    }

    /// The owner's Windows integrity level, if this launch learned it.
    /// `None` on other platforms, which have no integrity levels.
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

/// Why an owner stopped serving: what [`Claim::on_end`] is told and
/// [`Owner::ended`] reports.
///
/// [`Owner::ended`]: crate::Owner::ended
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum End {
    /// [`Owner::stop`] or [`Owner::release`] was called, or the `Owner` was
    /// dropped. After `stop`, launches are told the owner is busy; after a
    /// drop or `release`, they find nobody listening. If the lock is lost
    /// afterwards, [`End::LostLock`] replaces it.
    ///
    /// [`Owner::stop`]: crate::Owner::stop
    /// [`Owner::release`]: crate::Owner::release
    Stopped,
    /// The handler panicked. Later launches are turned away at once
    /// ([`Reason::Declined`]); this process still holds the lock.
    Panicked,
    /// Something deleted the runtime folder under this owner, and another
    /// process took the lock there before this one could re-create it. That
    /// process is now the owner: this one must stop writing the state.
    LostLock,
}

impl fmt::Display for End {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            End::Stopped => "stopped",
            End::Panicked => "the handler panicked",
            End::LostLock => "another process took the lock",
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
    /// [`Mode::Separate`], and another process owns the app (this one,
    /// too, if it already holds the lock).
    ///
    /// [`Mode::Separate`]: crate::Mode::Separate
    #[non_exhaustive]
    OwnerRunning {},
    /// [`Builder::hand_off`] or [`Builder::probe`], and no process owns the
    /// app.
    ///
    /// [`Builder::hand_off`]: crate::Builder::hand_off
    /// [`Builder::probe`]: crate::Builder::probe
    #[non_exhaustive]
    NoOwner {},
    /// The owner turned this launch away: [`Answer::Decline`],
    /// [`Claim::decline_all`], a `Claim` dropped unserved, or an owner whose
    /// handler panicked earlier.
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
    /// timeout: it hasn't served yet, can't listen, or is hung. The request
    /// was not delivered, and won't be.
    #[non_exhaustive]
    Unresponsive {
        /// How long this launch tried.
        waited: Duration,
    },
    /// The lock holder is another app: two app ids share a folder.
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
    /// The process at the other end of the owner's socket failed the
    /// same-user check: another user's, or on Windows the same user's at
    /// another integrity level. See the crate docs on privileges.
    #[non_exhaustive]
    Peer {
        /// What the check found.
        source: io::Error,
    },
    /// This launch has rights the owner lacks, such as a higher integrity
    /// level. The request wasn't delivered, since the owner would act on it
    /// without them.
    #[non_exhaustive]
    MoreRights {
        /// The owner.
        owner: OwnerInfo,
        /// What this launch has and the owner lacks.
        rights: Rights,
    },
    /// The owner has rights this launch lacks, such as a higher integrity
    /// level. The request wasn't delivered, since the owner would act on it
    /// with rights its launch never had.
    #[non_exhaustive]
    OwnerHasMoreRights {
        /// The owner.
        owner: OwnerInfo,
        /// What the owner has and this launch lacks.
        rights: Rights,
    },
    /// On Linux with systemd: this process has no login session, so the
    /// user's runtime folder (`/run/user/<uid>`) doesn't exist. Launches
    /// from cron, `@reboot`, `su`, `sudo` or a system service land here. Run
    /// `loginctl enable-linger` to keep the folder for good, or see the
    /// crate docs on daemons.
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
    /// open to others, a symlink, or on Windows made for another integrity
    /// level. Another user may have created it first.
    #[non_exhaustive]
    RuntimeDir {
        /// The folder.
        path: PathBuf,
        /// What went wrong.
        source: io::Error,
    },
    /// The lock file can't be opened or locked (a file system without
    /// locks, say).
    #[non_exhaustive]
    Lock {
        /// The lock file.
        path: PathBuf,
        /// What went wrong.
        source: io::Error,
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
            Reason::OwnerRunning {} => f.write_str("another instance is running"),
            Reason::NoOwner {} => f.write_str("no instance is running"),
            Reason::Declined {} => f.write_str("the running instance turned this launch away"),
            Reason::Busy { waited } => {
                write!(f, "the running instance stayed busy for {waited:?}")
            }
            Reason::Unresponsive { waited } => {
                write!(f, "an instance is running but didn't answer in {waited:?}")
            }
            Reason::OtherApp {} => f.write_str("another app holds the runtime folder"),
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
            Reason::NoSession {} => f.write_str(
                "no login session, so no runtime folder (`loginctl enable-linger` keeps one)",
            ),
            Reason::NoRuntimeDir {} => f.write_str("no runtime folder"),
            Reason::RuntimeDir { path, source } => {
                write!(f, "runtime folder {}: {source}", path.display())
            }
            Reason::Lock { path, source } => write!(f, "lock {}: {source}", path.display()),
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
}
