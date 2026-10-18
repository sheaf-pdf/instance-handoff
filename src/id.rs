use std::borrow::Cow;
use std::error::Error;
use std::fmt;
use std::str::FromStr;

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
/// [`AppId::new`] is a `const fn`, so a bad literal in a `const` is a
/// compile error:
///
/// ```compile_fail
/// const APP: instance_handoff::AppId = instance_handoff::AppId::new("../evil");
/// ```
///
/// [`Reason::OtherApp`]: crate::Reason::OtherApp
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AppId(Cow<'static, str>);

const MAX_ID: usize = 48;

const fn valid_id(b: &[u8]) -> bool {
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
    /// An app id from a literal. Declare it as a `const` so a bad one is a
    /// compile error.
    ///
    /// # Panics
    ///
    /// If `id` isn't valid (see [`AppId`]). Use [`AppId::parse`] for ids
    /// known only at run time.
    pub const fn new(id: &'static str) -> AppId {
        if !valid_id(id.as_bytes()) {
            panic!(
                "invalid app id: use 1-48 ASCII letters, digits, '.', '-' or '_', starting and \
                 ending with a letter or digit, and not a Windows device name such as \"con\""
            );
        }
        AppId(Cow::Borrowed(id))
    }

    /// An app id from a run-time string.
    pub fn parse(id: impl Into<String>) -> Result<AppId, InvalidAppId> {
        let id = id.into();
        if valid_id(id.as_bytes()) {
            Ok(AppId(Cow::Owned(id)))
        } else {
            Err(InvalidAppId { id })
        }
    }

    /// The id, as given.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AppId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

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

impl FromStr for AppId {
    type Err = InvalidAppId;
    fn from_str(s: &str) -> Result<AppId, InvalidAppId> {
        AppId::parse(s)
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
    use super::*;

    #[test]
    fn ids_are_safe_file_names() {
        for good in [
            "sheaf",
            "org.example.Viewer",
            "a",
            "my_app-2",
            &"x".repeat(48),
        ] {
            assert!(AppId::parse(good).is_ok(), "{good}");
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
            assert!(AppId::parse(bad).is_err(), "{bad}");
        }
        // Device names only as the whole stem.
        assert!(AppId::parse("console").is_ok());
        assert!(AppId::parse("com").is_ok());
        assert_eq!(AppId::new("sheaf").to_string(), "sheaf");
    }
}
