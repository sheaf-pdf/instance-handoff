use std::borrow::Cow;
use std::error::Error;
use std::fmt;

/// Names an app: its runtime folder, its socket, its thread. An owner
/// refuses a launch that names another app ([`Reason::OtherApp`]).
///
/// An id is 1 to 48 ASCII letters, digits, `.`, `-` and `_`. It starts with
/// a letter or a digit and ends with one, and its part before the first `.`
/// isn't a Windows device name (`con`, `prn`, `aux`, `nul`, `com0` to
/// `com9`, `lpt0` to `lpt9`, in any case), so it is a safe file name on
/// every platform. A reverse-DNS name such as `org.example.Viewer` is a
/// good choice. Keep it the same across releases of your app, or two builds will
/// each become an owner.
///
/// An app id also has a [`Kind`], which says who may become the owner.
/// Two app ids with the same id and different kinds compare unequal, so
/// give every binary of an app the same `const`. For now, launches don't
/// compare kinds with the owner.
///
/// [`AppId::windowed`] and [`AppId::headless`] are `const fn`s, so a bad
/// literal in a `const` is a compile error:
///
/// ```compile_fail,E0080
/// const APP: instance_handoff::AppId = instance_handoff::AppId::windowed("../evil");
/// ```
///
/// [`Reason::OtherApp`]: crate::Reason::OtherApp
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AppId {
    id: Cow<'static, str>,
    kind: Kind,
}

/// Who may become the owner of an app. It doesn't say whether the owner
/// shows windows.
///
/// For now the kind is only recorded: any launch may own an app of either
/// kind, and a launch hands off to an owner of its id whatever the owner's
/// kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    /// Only a launch that can show windows. Most apps with a GUI are
    /// windowed.
    Windowed,
    /// Any launch, including one with no display. Daemons, services and
    /// CLI back ends are headless, and so is a daemon that opens windows
    /// for its clients, as Emacs's does.
    Headless,
}

const MAX_ID: usize = 48;

/// Whether `b` is a valid app id.
pub(crate) const fn valid_id(b: &[u8]) -> bool {
    if b.is_empty() || b.len() > MAX_ID {
        return false;
    }
    // Windows strips a trailing dot, so "app." and "app" would share a
    // folder there.
    if !b[0].is_ascii_alphanumeric() || !b[b.len() - 1].is_ascii_alphanumeric() {
        return false;
    }
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if !(c.is_ascii_alphanumeric() || c == b'.' || c == b'-' || c == b'_') {
            return false;
        }
        i += 1;
    }
    !reserved_on_windows(b)
}

/// `con`, `nul`, `com1` and the rest name devices on Windows, with any
/// extension and in any case.
const fn reserved_on_windows(b: &[u8]) -> bool {
    let mut stem = 0;
    while stem < b.len() && b[stem] != b'.' {
        stem += 1;
    }
    if stem != 3 && stem != 4 {
        return false;
    }
    let head = [
        b[0].to_ascii_lowercase(),
        b[1].to_ascii_lowercase(),
        b[2].to_ascii_lowercase(),
    ];
    if stem == 3 {
        matches!(
            head,
            [b'c', b'o', b'n'] | [b'p', b'r', b'n'] | [b'a', b'u', b'x'] | [b'n', b'u', b'l']
        )
    } else {
        matches!(head, [b'c', b'o', b'm'] | [b'l', b'p', b't']) && b[3].is_ascii_digit()
    }
}

impl AppId {
    /// A [windowed](Kind::Windowed) app id from a literal. Declare it as a
    /// `const` so a bad one is a compile error.
    ///
    /// # Panics
    ///
    /// If `id` isn't valid (see [`AppId`]). Use [`AppId::parse`] for ids
    /// known only at run time.
    pub const fn windowed(id: &'static str) -> AppId {
        AppId::literal(id, Kind::Windowed)
    }

    /// A [headless](Kind::Headless) app id from a literal. Declare it as a
    /// `const` so a bad one is a compile error.
    ///
    /// # Panics
    ///
    /// If `id` isn't valid (see [`AppId`]). Use [`AppId::parse`] for ids
    /// known only at run time.
    pub const fn headless(id: &'static str) -> AppId {
        AppId::literal(id, Kind::Headless)
    }

    const fn literal(id: &'static str, kind: Kind) -> AppId {
        if !valid_id(id.as_bytes()) {
            panic!(
                "invalid app id: use 1-48 ASCII letters, digits, '.', '-' or '_', starting and \
                 ending with a letter or digit, and not a Windows device name such as \"con\""
            );
        }
        AppId {
            id: Cow::Borrowed(id),
            kind,
        }
    }

    /// An app id of `kind` from a run-time string.
    pub fn parse(id: impl Into<String>, kind: Kind) -> Result<AppId, InvalidAppId> {
        let id = id.into();
        if valid_id(id.as_bytes()) {
            Ok(AppId {
                id: Cow::Owned(id),
                kind,
            })
        } else {
            Err(InvalidAppId { id })
        }
    }

    /// The id, as given, without the kind. Folder names, the thread's name
    /// and the address use it.
    pub fn as_str(&self) -> &str {
        &self.id
    }

    /// Who may become the owner.
    pub fn kind(&self) -> Kind {
        self.kind
    }
}

/// The id alone, without the kind.
impl fmt::Display for AppId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for AppId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// A string that isn't a valid [`AppId`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidAppId {
    id: String,
}

impl InvalidAppId {
    /// The string that was refused.
    pub fn as_str(&self) -> &str {
        &self.id
    }
}

impl fmt::Display for InvalidAppId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid app id {:?}: use 1-48 ASCII letters, digits, '.', '-' or '_', \
             starting and ending with a letter or digit, and not a Windows device name \
             such as \"con\"",
            self.id
        )
    }
}

impl Error for InvalidAppId {}

#[cfg(test)]
mod tests {
    use std::hash::{DefaultHasher, Hash, Hasher};

    use super::*;

    #[test]
    fn ids_are_safe_file_names() {
        for kind in [Kind::Windowed, Kind::Headless] {
            for good in [
                "sheaf",
                "org.example.Viewer",
                "a",
                "my_app-2",
                &"x".repeat(48),
            ] {
                assert!(AppId::parse(good, kind).is_ok(), "{good}");
            }
            for bad in [
                "",
                "../evil",
                "a/b",
                ".hidden",
                "app.",
                "-x",
                "x-",
                "with space",
                "naïve",
                &"x".repeat(49),
                "con",
                "NUL",
                "aux.example",
                "com1",
                "LPT9.x",
            ] {
                assert!(AppId::parse(bad, kind).is_err(), "{bad}");
            }
            // Device names only as the whole stem.
            assert!(AppId::parse("console", kind).is_ok());
            assert!(AppId::parse("com", kind).is_ok());
        }
    }

    #[test]
    fn the_kind_is_part_of_the_app_id() {
        const WINDOWED: AppId = AppId::windowed("sheaf");
        const HEADLESS: AppId = AppId::headless("sheaf");
        fn hash(id: &AppId) -> u64 {
            let mut h = DefaultHasher::new();
            id.hash(&mut h);
            h.finish()
        }
        assert_eq!(WINDOWED.kind(), Kind::Windowed);
        assert_eq!(HEADLESS.kind(), Kind::Headless);
        assert_ne!(WINDOWED, HEADLESS);
        assert_ne!(hash(&WINDOWED), hash(&HEADLESS));
        // A literal and a parsed id of one kind are the same app id.
        let parsed = AppId::parse("sheaf", Kind::Windowed).unwrap();
        assert_eq!(parsed, WINDOWED);
        assert_eq!(hash(&parsed), hash(&WINDOWED));
        // Folder names, the thread and the address see the bare id.
        assert_eq!(WINDOWED.to_string(), "sheaf");
        assert_eq!(HEADLESS.as_str(), "sheaf");
    }
}
