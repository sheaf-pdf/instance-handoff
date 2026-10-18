use std::error::Error;
use std::ffi::OsString;

use crate::wire;

/// The error a [`Payload`] codec returns.
pub type BoxError = Box<dyn Error + Send + Sync + 'static>;

/// What a launch hands over. The crate sends the bytes `encode` makes, and
/// the owner rebuilds the value with `decode`, possibly in another build of
/// the same app: keep the encoding tolerant, and bump
/// [`Builder::payload_version`] when it can't be.
///
/// Implemented for [`Args`] (the usual choice), `Vec<u8>`, `String` and `()`
/// (no payload: just "come forward"), and, with the `serde` feature, for
/// [`Json<T>`]. For your own type, encode it however you like:
///
/// ```
/// use instance_handoff::{BoxError, Payload};
///
/// enum Command { Show, Quit }
///
/// impl Payload for Command {
///     fn encode(&self) -> Result<Vec<u8>, BoxError> {
///         Ok(vec![match self { Command::Show => 0, Command::Quit => 1 }])
///     }
///     fn decode(bytes: &[u8]) -> Result<Command, BoxError> {
///         match bytes {
///             [0] => Ok(Command::Show),
///             [1] => Ok(Command::Quit),
///             _ => Err("unknown command".into()),
///         }
///     }
/// }
/// ```
///
/// The owner gets the payload from another process of the same user. Treat
/// it as you would command-line arguments: check what it asks for before
/// acting on it.
///
/// [`Builder::payload_version`]: crate::Builder::payload_version
/// [`Json<T>`]: crate::Json
pub trait Payload: Send + Sized + 'static {
    /// The bytes to send. An error makes the launch run alone with
    /// [`Reason::Encode`], without contacting the owner.
    ///
    /// [`Reason::Encode`]: crate::Reason::Encode
    fn encode(&self) -> Result<Vec<u8>, BoxError>;

    /// The value from bytes another launch encoded. It runs on the crate's
    /// thread, before the launch commits. An error, or a panic, makes the
    /// owner refuse that launch ([`Reason::Undecodable`]); the handler never
    /// sees it.
    ///
    /// [`Reason::Undecodable`]: crate::Reason::Undecodable
    fn decode(bytes: &[u8]) -> Result<Self, BoxError>;
}

/// A launch's command-line arguments, without the program name, as
/// [`std::env::args_os`] yields them. They travel losslessly, non-UTF-8
/// arguments included.
///
/// They are raw: the owner parses them as it would its own. Relative paths
/// among them mean the launch's working directory, not the owner's: resolve
/// the arguments that are paths with [`Request::resolve`], or make them
/// absolute before handing off (needed for drive-relative paths like
/// `C:file` on Windows).
///
/// [`Request::resolve`]: crate::Request::resolve
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Args(Vec<OsString>);

impl Args {
    /// This process's arguments, without the program name.
    pub fn from_env() -> Args {
        Args(std::env::args_os().skip(1).collect())
    }

    /// Arguments from parts: those your parser chose to hand off, or files
    /// that arrived by another route.
    pub fn new<I>(args: I) -> Args
    where
        I: IntoIterator,
        I::Item: Into<OsString>,
    {
        Args(args.into_iter().map(Into::into).collect())
    }

    /// The arguments.
    pub fn into_vec(self) -> Vec<OsString> {
        self.0
    }
}

impl std::ops::Deref for Args {
    type Target = [OsString];
    fn deref(&self) -> &[OsString] {
        &self.0
    }
}

impl From<Vec<OsString>> for Args {
    fn from(args: Vec<OsString>) -> Args {
        Args(args)
    }
}

impl<S: Into<OsString>> FromIterator<S> for Args {
    fn from_iter<I: IntoIterator<Item = S>>(iter: I) -> Args {
        Args::new(iter)
    }
}

impl IntoIterator for Args {
    type Item = OsString;
    type IntoIter = std::vec::IntoIter<OsString>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Args {
    type Item = &'a OsString;
    type IntoIter = std::slice::Iter<'a, OsString>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// `count u32 LE | (length u32 LE | bytes)*`, each argument in the
/// platform's own form: its bytes on Unix, UTF-16 little-endian on Windows.
impl Payload for Args {
    fn encode(&self) -> Result<Vec<u8>, BoxError> {
        let mut out = Vec::new();
        out.extend_from_slice(&u32::try_from(self.0.len())?.to_le_bytes());
        for arg in &self.0 {
            let bytes = wire::os_to_bytes(arg);
            out.extend_from_slice(&u32::try_from(bytes.len())?.to_le_bytes());
            out.extend_from_slice(&bytes);
        }
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Args, BoxError> {
        fn take<'a>(b: &mut &'a [u8], n: usize) -> Result<&'a [u8], BoxError> {
            if b.len() < n {
                return Err("arguments cut short".into());
            }
            let (head, rest) = b.split_at(n);
            *b = rest;
            Ok(head)
        }
        fn len(b: &mut &[u8]) -> Result<usize, BoxError> {
            let n = take(b, 4)?;
            Ok(u32::from_le_bytes([n[0], n[1], n[2], n[3]]) as usize)
        }
        let mut b = bytes;
        let count = len(&mut b)?;
        // Each argument takes at least its 4-byte length: don't trust a
        // count the bytes can't hold.
        if count > b.len() / 4 {
            return Err("more arguments than bytes".into());
        }
        let mut args = Vec::with_capacity(count);
        for _ in 0..count {
            let n = len(&mut b)?;
            args.push(wire::os_from_bytes(take(&mut b, n)?)?);
        }
        if !b.is_empty() {
            return Err("bytes after the last argument".into());
        }
        Ok(Args(args))
    }
}

impl Payload for Vec<u8> {
    fn encode(&self) -> Result<Vec<u8>, BoxError> {
        Ok(self.clone())
    }
    fn decode(bytes: &[u8]) -> Result<Vec<u8>, BoxError> {
        Ok(bytes.to_vec())
    }
}

impl Payload for String {
    fn encode(&self) -> Result<Vec<u8>, BoxError> {
        Ok(self.as_bytes().to_vec())
    }
    fn decode(bytes: &[u8]) -> Result<String, BoxError> {
        Ok(String::from_utf8(bytes.to_vec())?)
    }
}

impl Payload for () {
    fn encode(&self) -> Result<Vec<u8>, BoxError> {
        Ok(Vec::new())
    }
    fn decode(_: &[u8]) -> Result<(), BoxError> {
        Ok(())
    }
}

/// Any serde type as a payload, encoded as JSON (feature `serde`).
///
/// Evolve it the serde way: add fields with `#[serde(default)]` and older
/// owners ignore them. Prefer `OsString` to `PathBuf` for paths, and only
/// when they're valid Unicode: JSON can't carry the rest. [`Args`] can.
#[cfg(feature = "serde")]
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Json<T>(pub T);

#[cfg(feature = "serde")]
impl<T> Payload for Json<T>
where
    T: serde::Serialize + serde::de::DeserializeOwned + Send + 'static,
{
    fn encode(&self) -> Result<Vec<u8>, BoxError> {
        Ok(serde_json::to_vec(&self.0)?)
    }
    fn decode(bytes: &[u8]) -> Result<Json<T>, BoxError> {
        Ok(Json(serde_json::from_slice(bytes)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_round_trip_byte_for_byte() {
        #[cfg(unix)]
        let odd = {
            use std::os::unix::ffi::OsStrExt;
            std::ffi::OsStr::from_bytes(b"caf\xe9.pdf").to_os_string()
        };
        #[cfg(not(unix))]
        let odd = OsString::from("café.pdf");
        let args = Args::new([OsString::from("--flag"), OsString::new(), odd]);
        let bytes = args.encode().unwrap();
        assert_eq!(Args::decode(&bytes).unwrap(), args);
        assert_eq!(
            Args::decode(&Args::default().encode().unwrap()).unwrap(),
            Args::default()
        );
    }

    #[test]
    fn bad_args_are_errors_not_panics() {
        for bad in [
            &[][..],
            &[1, 0, 0],
            &[1, 0, 0, 0],
            &[1, 0, 0, 0, 9, 0, 0, 0, b'x'],
            &[0xff, 0xff, 0xff, 0xff],
            &[0, 0, 0, 0, b'x'],
        ] {
            assert!(Args::decode(bad).is_err(), "{bad:?}");
        }
    }
}
