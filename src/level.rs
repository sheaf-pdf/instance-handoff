//! Integrity levels, and the rights a launch and an owner can differ in.

use std::fmt;

/// A Windows integrity level, ordered by its RID, the last part of its
/// SID: `S-1-16-12288` is high. The order is the RID's, so constants added
/// later can't change it.
///
/// It exists on every platform, so code that names it builds everywhere,
/// but only Windows has integrity levels. Owners elsewhere never name one,
/// so the crate reports none there.
///
/// It displays as its name, such as `high`, or, for a level with no
/// constant here, as its RID in hex, such as `0x3010`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Level(u32);

impl Level {
    /// Low (`0x1000`), below a normal process, as some sandboxes run.
    pub const LOW: Level = Level(0x1000);
    /// Medium (`0x2000`): a normal process.
    pub const MEDIUM: Level = Level(0x2000);
    /// Medium with UIAccess (`0x2010`), as accessibility tools run.
    pub const UI_ACCESS: Level = Level(0x2010);
    /// Medium plus (`0x2100`), above medium and below high.
    pub const MEDIUM_PLUS: Level = Level(0x2100);
    /// High (`0x3000`): a process run as administrator.
    pub const HIGH: Level = Level(0x3000);
    /// System (`0x4000`), as services run.
    pub const SYSTEM: Level = Level(0x4000);

    /// The level's relative identifier (RID), as in `S-1-16-<rid>`.
    pub const fn rid(self) -> u32 {
        self.0
    }

    /// The level with this RID, as a token or a HELLO gives it.
    pub(crate) const fn from_rid(rid: u32) -> Level {
        Level(rid)
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Level::LOW => f.write_str("low"),
            Level::MEDIUM => f.write_str("medium"),
            Level::UI_ACCESS => f.write_str("UIAccess"),
            Level::MEDIUM_PLUS => f.write_str("medium plus"),
            Level::HIGH => f.write_str("high"),
            Level::SYSTEM => f.write_str("system"),
            Level(rid) => write!(f, "{rid:#x}"),
        }
    }
}

/// Rights that one side of a handoff, the launch or the owner, has and the
/// other lacks. [`Reason::MoreRights`] and [`Reason::OwnerHasMoreRights`]
/// carry them, and so does [`OwnerInfo::handed_down`].
///
/// They display as the rights themselves, for a message such as "It will
/// lack {rights}": `high integrity`.
///
/// [`Reason::MoreRights`]: crate::Reason::MoreRights
/// [`Reason::OwnerHasMoreRights`]: crate::Reason::OwnerHasMoreRights
/// [`OwnerInfo::handed_down`]: crate::OwnerInfo::handed_down
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rights {
    /// The two run at different Windows integrity levels, and the higher
    /// one has the rights.
    Level {
        /// The launch's level.
        launch: Level,
        /// The owner's level.
        owner: Level,
    },
}

impl fmt::Display for Rights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Rights::Level { launch, owner } => write!(f, "{} integrity", launch.max(owner)),
        }
    }
}

/// The level of the owner that holds the lock, beside the launch's own, as
/// the marker in its lock shows it. Only Windows owners mark a level, so
/// elsewhere every owner is at the launch's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnerLevel {
    /// The launch's own level, or no level at all.
    Same,
    /// Another level.
    #[cfg_attr(not(windows), allow(dead_code))]
    Other(Level),
    /// No marker yet: the owner is still starting, or a launch is testing
    /// the lock.
    #[cfg_attr(not(windows), allow(dead_code))]
    Starting,
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAMED: [Level; 6] = [
        Level::LOW,
        Level::MEDIUM,
        Level::UI_ACCESS,
        Level::MEDIUM_PLUS,
        Level::HIGH,
        Level::SYSTEM,
    ];

    #[test]
    fn levels_are_ordered_by_rid() {
        for pair in NAMED.windows(2) {
            assert!(pair[0] < pair[1], "{pair:?}");
            assert!(pair[0].rid() < pair[1].rid(), "{pair:?}");
        }
        // A level with no name sorts among the others by its RID too.
        let high_ui_access = Level(0x3010);
        assert!(Level::HIGH < high_ui_access && high_ui_access < Level::SYSTEM);
    }

    #[test]
    fn levels_display_their_name_or_rid() {
        let names = NAMED.map(|l| l.to_string());
        assert_eq!(
            names,
            ["low", "medium", "UIAccess", "medium plus", "high", "system"]
        );
        assert_eq!(Level(0x3010).to_string(), "0x3010");
        assert_eq!(Level(0).to_string(), "0x0");
    }

    // The RIDs Windows defines. UIAccess has no constant of its own: it is
    // medium raised by 0x10.
    #[cfg(windows)]
    #[test]
    fn levels_are_windows_own() {
        use windows_sys::Win32::System::SystemServices::{
            SECURITY_MANDATORY_HIGH_RID, SECURITY_MANDATORY_LOW_RID,
            SECURITY_MANDATORY_MEDIUM_PLUS_RID, SECURITY_MANDATORY_MEDIUM_RID,
            SECURITY_MANDATORY_SYSTEM_RID,
        };
        assert_eq!(Level::LOW.rid(), SECURITY_MANDATORY_LOW_RID as u32);
        assert_eq!(Level::MEDIUM.rid(), SECURITY_MANDATORY_MEDIUM_RID as u32);
        assert_eq!(Level::UI_ACCESS.rid(), Level::MEDIUM.rid() + 0x10);
        assert_eq!(Level::MEDIUM_PLUS.rid(), SECURITY_MANDATORY_MEDIUM_PLUS_RID);
        assert_eq!(Level::HIGH.rid(), SECURITY_MANDATORY_HIGH_RID as u32);
        assert_eq!(Level::SYSTEM.rid(), SECURITY_MANDATORY_SYSTEM_RID as u32);
    }

    #[test]
    fn rights_name_the_higher_level() {
        let up = Rights::Level {
            launch: Level::HIGH,
            owner: Level::MEDIUM,
        };
        let down = Rights::Level {
            launch: Level::MEDIUM,
            owner: Level::HIGH,
        };
        assert_eq!(up.to_string(), "high integrity");
        assert_eq!(down.to_string(), "high integrity");
    }
}
