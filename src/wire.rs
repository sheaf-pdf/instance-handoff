//! The handoff protocol's bytes. Frozen at 0.1, and only ever extended with
//! records old peers skip; see the crate docs for the exchange itself.
//!
//! Every message is `"IHND" | kind u8 | body length u32 LE | body`, and a
//! body is a sequence of records, `tag u8 | length u32 LE | bytes`. A peer
//! skips a record whose tag it doesn't know, unless the tag's high bit is
//! set: such a record is critical, and a peer that doesn't know it refuses
//! the message. A tag twice in one body is malformed.

use std::ffi::{OsStr, OsString};

use crate::{BoxError, Kind};

pub(crate) const MAGIC: [u8; 4] = *b"IHND";
pub(crate) const HEADER: usize = 9;
/// The wire versions this build speaks.
pub(crate) const WIRE_MIN: u16 = 1;
pub(crate) const WIRE_MAX: u16 = 1;
/// The largest READY, COMMIT or REPLY body, and the room in HELLO beside
/// its STATE record: see [`hello_limit`].
pub(crate) const SMALL: usize = 4096;
/// The largest REQUEST an owner takes.
pub(crate) const MAX_REQUEST: u32 = 4 << 20;
/// Activation values longer than this are left out, or dropped on receipt.
pub(crate) const MAX_TOKEN: usize = 1024;

pub(crate) const HELLO: u8 = 1;
pub(crate) const REQUEST: u8 = 2;
pub(crate) const READY: u8 = 3;
pub(crate) const COMMIT: u8 = 4;
pub(crate) const REPLY: u8 = 5;

const CRITICAL: u8 = 0x80;

/// The largest HELLO body a launch reads, given its own STATE. An owner of
/// the same state folder and scope sends the same STATE, so its HELLO
/// fits. A longer one isn't from this launch's owner, and reads as not
/// this protocol.
pub(crate) fn hello_limit(state: &[u8]) -> usize {
    SMALL.saturating_add(state.len())
}

/// HELLO record tags.
mod hello {
    pub const WIRE: u8 = 1;
    pub const APP: u8 = 2;
    pub const NONCE: u8 = 3;
    pub const PAYLOAD_VERSION: u8 = 4;
    pub const MAX_REQUEST: u8 = 5;
    pub const SERVING: u8 = 6;
    pub const LEVEL: u8 = 7;
    // 8 and 10 are kept for records that come later.
    pub const STATE: u8 = 9;
    pub const FEATURES: u8 = 11;
}

/// Whether the owner serves, in HELLO's SERVING record.
pub(crate) mod serving {
    pub const TAKING: u8 = 0;
    pub const BUSY: u8 = 1;
    pub const DECLINING: u8 = 2;
}

/// An app's [`Kind`], as the first byte of HELLO's APP record.
pub(crate) fn app_kind(kind: Kind) -> u8 {
    match kind {
        Kind::Windowed => 0,
        Kind::Headless => 1,
    }
}

/// The owner's features, in HELLO: what it does that older owners didn't.
pub(crate) mod features {
    /// It answers every launch it refuses with REPLY REFUSED and the cause,
    /// and never just closes the connection.
    pub const REFUSALS: u32 = 1;
}

/// REQUEST record tags.
mod request {
    pub const WIRE: u8 = 1;
    pub const PAYLOAD_VERSION: u8 = 2;
    pub const CWD: u8 = 3;
    pub const XDG_TOKEN: u8 = 4;
    pub const STARTUP_ID: u8 = 5;
    pub const PAYLOAD: u8 = 6;
}

/// REPLY record tags.
mod reply {
    pub const DELIVERED: u8 = 1;
    pub const STATUS: u8 = 2;
    pub const REFUSAL: u8 = 3;
    pub const PAYLOAD_VERSION: u8 = 4;
}

/// REPLY statuses. A launch decides on `delivered` first; a status it
/// doesn't know counts as busy.
pub(crate) mod status {
    pub const TAKEN: u8 = 0;
    pub const BUSY: u8 = 1;
    pub const DECLINED: u8 = 2;
    pub const REFUSED: u8 = 3;
    /// The owner stopped waiting for COMMIT.
    pub const GAVE_UP: u8 = 4;
}

/// Why an owner refused a launch.
pub(crate) mod refusal {
    pub const WIRE: u8 = 1;
    pub const APP: u8 = 2;
    pub const PAYLOAD_VERSION: u8 = 3;
    pub const UNDECODABLE: u8 = 4;
    pub const TOO_LARGE: u8 = 5;
    pub const MALFORMED: u8 = 6;
    pub const UNSUPPORTED: u8 = 7;
    // 8 PRIVILEGE, 9 SCREEN, 11 STATE and 12 PERSON are kept for later.
    /// The launch failed the owner's same-user check.
    pub const PEER: u8 = 10;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    /// Not this protocol at all.
    BadMagic,
    Malformed,
    TooLarge {
        size: usize,
        limit: usize,
    },
    /// A critical record this build doesn't know.
    Unsupported,
}

/// Builds one message.
pub(crate) struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub(crate) fn new(kind: u8) -> Writer {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&MAGIC);
        buf.push(kind);
        buf.extend_from_slice(&[0; 4]);
        Writer { buf }
    }

    pub(crate) fn bytes(mut self, tag: u8, bytes: &[u8]) -> Writer {
        self.buf.push(tag);
        self.buf
            .extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(bytes);
        self
    }

    pub(crate) fn finish(mut self) -> Vec<u8> {
        let len = (self.buf.len() - HEADER) as u32;
        self.buf[5..HEADER].copy_from_slice(&len.to_le_bytes());
        self.buf
    }
}

/// The kind and body length of the message at the start of `buf`, once its
/// header has arrived. A body over `limit` is refused before it is read.
pub(crate) fn header(buf: &[u8], limit: usize) -> Result<Option<(u8, usize)>, Error> {
    if buf.len() < HEADER {
        // Refuse a stranger as soon as its first bytes show it.
        let n = buf.len().min(MAGIC.len());
        if buf[..n] != MAGIC[..n] {
            return Err(Error::BadMagic);
        }
        return Ok(None);
    }
    if buf[..4] != MAGIC {
        return Err(Error::BadMagic);
    }
    let len = u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]) as usize;
    if len > limit {
        return Err(Error::TooLarge { size: len, limit });
    }
    Ok(Some((buf[4], len)))
}

/// A whole message: its kind, its body, and its length in the buffer.
pub(crate) type Frame<'a> = (u8, &'a [u8], usize);

/// The whole message at the start of `buf`, if it has all arrived.
pub(crate) fn split(buf: &[u8], limit: usize) -> Result<Option<Frame<'_>>, Error> {
    match header(buf, limit)? {
        Some((kind, len)) if buf.len() >= HEADER + len => {
            Ok(Some((kind, &buf[HEADER..HEADER + len], HEADER + len)))
        }
        _ => Ok(None),
    }
}

/// A body's records, those with `known` tags kept.
struct Records<'a> {
    items: Vec<(u8, &'a [u8])>,
}

impl<'a> Records<'a> {
    fn parse(mut body: &'a [u8], known: &[u8]) -> Result<Records<'a>, Error> {
        let mut items: Vec<(u8, &[u8])> = Vec::new();
        let mut seen = [false; 256];
        while !body.is_empty() {
            if body.len() < 5 {
                return Err(Error::Malformed);
            }
            let tag = body[0];
            let len = u32::from_le_bytes([body[1], body[2], body[3], body[4]]) as usize;
            let rest = &body[5..];
            if rest.len() < len {
                return Err(Error::Malformed);
            }
            if std::mem::replace(&mut seen[usize::from(tag)], true) {
                return Err(Error::Malformed);
            }
            if known.contains(&tag) {
                items.push((tag, &rest[..len]));
            } else if tag & CRITICAL != 0 {
                return Err(Error::Unsupported);
            }
            body = &rest[len..];
        }
        Ok(Records { items })
    }

    fn get(&self, tag: u8) -> Option<&'a [u8]> {
        self.items.iter().find(|(t, _)| *t == tag).map(|(_, b)| *b)
    }

    fn fixed<const N: usize>(&self, tag: u8) -> Result<Option<[u8; N]>, Error> {
        match self.get(tag) {
            None => Ok(None),
            Some(b) => b.try_into().map(Some).map_err(|_| Error::Malformed),
        }
    }

    fn required<const N: usize>(&self, tag: u8) -> Result<[u8; N], Error> {
        self.fixed(tag)?.ok_or(Error::Malformed)
    }
}

/// The owner's greeting, sent as soon as it accepts a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Hello {
    pub(crate) wire_min: u16,
    pub(crate) wire_max: u16,
    pub(crate) app_id: String,
    /// The app's kind, as [`app_kind`] writes it. A launch compares it as
    /// it does the id.
    pub(crate) app_kind: u8,
    /// Random for each owner, so a launch can tell a new owner from the one
    /// it committed to.
    pub(crate) nonce: u64,
    pub(crate) payload_version: u32,
    pub(crate) max_request: u32,
    /// A [`serving`] value.
    pub(crate) serving: u8,
    /// The RID of the owner's integrity level, sent only where it has one:
    /// by owners on Windows.
    pub(crate) level: Option<u32>,
    /// The state folder and scope the owner's instance folder is named
    /// from, as [`naming::instance_key`] frames them. A launch compares it
    /// with its own, so two whose hashes collide never hand off.
    ///
    /// [`naming::instance_key`]: crate::naming::instance_key
    pub(crate) state: Vec<u8>,
    /// [`features`] bits; none from an owner that predates them.
    pub(crate) features: u32,
}

impl Hello {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut wire = [0; 4];
        wire[..2].copy_from_slice(&self.wire_min.to_le_bytes());
        wire[2..].copy_from_slice(&self.wire_max.to_le_bytes());
        // The app kind byte, then the id.
        let app = [&[self.app_kind], self.app_id.as_bytes()].concat();
        let mut w = Writer::new(HELLO)
            .bytes(hello::WIRE, &wire)
            .bytes(hello::APP, &app)
            .bytes(hello::NONCE, &self.nonce.to_le_bytes())
            .bytes(hello::PAYLOAD_VERSION, &self.payload_version.to_le_bytes())
            .bytes(hello::MAX_REQUEST, &self.max_request.to_le_bytes())
            .bytes(hello::SERVING, &[self.serving]);
        if let Some(level) = self.level {
            w = w.bytes(hello::LEVEL, &level.to_le_bytes());
        }
        w.bytes(hello::STATE, &self.state)
            .bytes(hello::FEATURES, &self.features.to_le_bytes())
            .finish()
    }

    pub(crate) fn decode(body: &[u8]) -> Result<Hello, Error> {
        use hello::*;
        let r = Records::parse(
            body,
            &[
                WIRE,
                APP,
                NONCE,
                PAYLOAD_VERSION,
                MAX_REQUEST,
                SERVING,
                LEVEL,
                STATE,
                FEATURES,
            ],
        )?;
        let wire: [u8; 4] = r.required(WIRE)?;
        // The app kind byte, then the id.
        let (&app_kind, app_id) = r
            .get(APP)
            .and_then(<[u8]>::split_first)
            .ok_or(Error::Malformed)?;
        let app_id = std::str::from_utf8(app_id)
            .map_err(|_| Error::Malformed)?
            .to_owned();
        Ok(Hello {
            wire_min: u16::from_le_bytes([wire[0], wire[1]]),
            wire_max: u16::from_le_bytes([wire[2], wire[3]]),
            app_id,
            app_kind,
            nonce: u64::from_le_bytes(r.required(NONCE)?),
            payload_version: u32::from_le_bytes(r.required(PAYLOAD_VERSION)?),
            max_request: u32::from_le_bytes(r.required(MAX_REQUEST)?),
            serving: r.fixed::<1>(SERVING)?.map_or(serving::TAKING, |[s]| s),
            level: r.fixed(LEVEL)?.map(u32::from_le_bytes),
            state: r.get(STATE).ok_or(Error::Malformed)?.to_vec(),
            features: r.fixed(FEATURES)?.map_or(0, u32::from_le_bytes),
        })
    }
}

/// What a launch hands over.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Request {
    pub(crate) wire: u16,
    pub(crate) payload_version: u32,
    /// The launch's working directory, in [native bytes](os_to_bytes).
    pub(crate) cwd: Option<Vec<u8>>,
    pub(crate) xdg_activation_token: Option<String>,
    pub(crate) startup_id: Option<String>,
    pub(crate) payload: Vec<u8>,
}

impl Request {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new(REQUEST)
            .bytes(request::WIRE, &self.wire.to_le_bytes())
            .bytes(
                request::PAYLOAD_VERSION,
                &self.payload_version.to_le_bytes(),
            );
        if let Some(cwd) = &self.cwd {
            w = w.bytes(request::CWD, cwd);
        }
        for (tag, value) in [
            (request::XDG_TOKEN, &self.xdg_activation_token),
            (request::STARTUP_ID, &self.startup_id),
        ] {
            if let Some(v) = value.as_deref().filter(|v| v.len() <= MAX_TOKEN) {
                w = w.bytes(tag, v.as_bytes());
            }
        }
        w.bytes(request::PAYLOAD, &self.payload).finish()
    }

    pub(crate) fn decode(body: &[u8]) -> Result<Request, Error> {
        use request::*;
        let r = Records::parse(
            body,
            &[WIRE, PAYLOAD_VERSION, CWD, XDG_TOKEN, STARTUP_ID, PAYLOAD],
        )?;
        // Activation values are hints: a bad one is dropped, not refused.
        let token = |tag| {
            r.get(tag)
                .filter(|v| v.len() <= MAX_TOKEN)
                .and_then(|v| std::str::from_utf8(v).ok())
                .map(str::to_owned)
        };
        Ok(Request {
            wire: u16::from_le_bytes(r.required(WIRE)?),
            payload_version: u32::from_le_bytes(r.required(PAYLOAD_VERSION)?),
            cwd: r.get(CWD).map(<[u8]>::to_vec),
            xdg_activation_token: token(XDG_TOKEN),
            startup_id: token(STARTUP_ID),
            payload: r.get(PAYLOAD).ok_or(Error::Malformed)?.to_vec(),
        })
    }
}

/// An empty READY or COMMIT.
pub(crate) fn empty(kind: u8) -> Vec<u8> {
    Writer::new(kind).finish()
}

/// Checks an empty READY or COMMIT body: records are allowed, and skipped.
pub(crate) fn check_empty(body: &[u8]) -> Result<(), Error> {
    Records::parse(body, &[]).map(|_| ())
}

/// The owner's answer to a REQUEST.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Reply {
    /// Whether the handler took the request.
    pub(crate) delivered: bool,
    pub(crate) status: u8,
    pub(crate) refusal: Option<u8>,
    /// The owner's payload version, sent with a payload-version refusal.
    pub(crate) payload_version: Option<u32>,
}

impl Reply {
    pub(crate) fn new(delivered: bool, status: u8) -> Reply {
        Reply {
            delivered,
            status,
            refusal: None,
            payload_version: None,
        }
    }

    pub(crate) fn refused(why: u8) -> Reply {
        Reply {
            refusal: Some(why),
            ..Reply::new(false, status::REFUSED)
        }
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new(REPLY)
            .bytes(reply::DELIVERED, &[u8::from(self.delivered)])
            .bytes(reply::STATUS, &[self.status]);
        if let Some(why) = self.refusal {
            w = w.bytes(reply::REFUSAL, &[why]);
        }
        if let Some(v) = self.payload_version {
            w = w.bytes(reply::PAYLOAD_VERSION, &v.to_le_bytes());
        }
        w.finish()
    }

    pub(crate) fn decode(body: &[u8]) -> Result<Reply, Error> {
        use reply::*;
        let r = Records::parse(body, &[DELIVERED, STATUS, REFUSAL, PAYLOAD_VERSION])?;
        let [delivered] = r.required::<1>(DELIVERED)?;
        let [status] = r.required::<1>(STATUS)?;
        Ok(Reply {
            delivered: delivered != 0,
            status,
            refusal: r.fixed::<1>(REFUSAL)?.map(|[b]| b),
            payload_version: r.fixed(PAYLOAD_VERSION)?.map(u32::from_le_bytes),
        })
    }
}

/// An OS string as it travels: its bytes on Unix, its UTF-16 little-endian
/// on Windows. Lossless both ways.
pub(crate) fn os_to_bytes(s: &OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        s.as_bytes().to_vec()
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        s.encode_wide().flat_map(u16::to_le_bytes).collect()
    }
    #[cfg(not(any(unix, windows)))]
    {
        s.to_string_lossy().into_owned().into_bytes()
    }
}

pub(crate) fn os_from_bytes(b: &[u8]) -> Result<OsString, BoxError> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(OsStr::from_bytes(b).to_os_string())
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        if b.len() % 2 != 0 {
            return Err("an odd number of bytes isn't UTF-16".into());
        }
        let units: Vec<u16> = b
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Ok(OsString::from_wide(&units))
    }
    #[cfg(not(any(unix, windows)))]
    {
        Ok(String::from_utf8(b.to_vec())?.into())
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::{Level, naming};

    // The exact bytes of each message are the contract between builds that
    // use different releases of this crate. These tests write them out as
    // numbers, kinds and codes included, so a changed constant fails too.
    #[test]
    fn hello_bytes_are_frozen() {
        // As an owner on Unix sends it, with no level.
        let unix = Hello {
            wire_min: 1,
            wire_max: 1,
            app_id: "a".into(),
            app_kind: app_kind(Kind::Headless),
            nonce: 0x0102_0304_0506_0708,
            payload_version: 7,
            max_request: MAX_REQUEST,
            serving: serving::BUSY,
            level: None,
            state: naming::instance_key(Some(Path::new("/s")), Some(OsStr::new("k"))),
            features: features::REFUSALS,
        };
        #[rustfmt::skip]
        let unix_bytes = [
            b'I', b'H', b'N', b'D', 1, 80, 0, 0, 0,
            1, 4, 0, 0, 0, 1, 0, 1, 0,
            2, 2, 0, 0, 0, 1, b'a',
            3, 8, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1,
            4, 4, 0, 0, 0, 7, 0, 0, 0,
            5, 4, 0, 0, 0, 0, 0, 0x40, 0,
            6, 1, 0, 0, 0, 1,
            9, 13, 0, 0, 0, 1, 2, 0, 0, 0, b'/', b's', 2, 1, 0, 0, 0, b'k',
            11, 4, 0, 0, 0, 1, 0, 0, 0,
        ];
        // As an owner on Windows sends it, with its level after SERVING:
        // high here.
        let windows = Hello {
            level: Some(Level::HIGH.rid()),
            ..unix.clone()
        };
        #[rustfmt::skip]
        let windows_bytes = [
            b'I', b'H', b'N', b'D', 1, 89, 0, 0, 0,
            1, 4, 0, 0, 0, 1, 0, 1, 0,
            2, 2, 0, 0, 0, 1, b'a',
            3, 8, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1,
            4, 4, 0, 0, 0, 7, 0, 0, 0,
            5, 4, 0, 0, 0, 0, 0, 0x40, 0,
            6, 1, 0, 0, 0, 1,
            7, 4, 0, 0, 0, 0, 0x30, 0, 0,
            9, 13, 0, 0, 0, 1, 2, 0, 0, 0, b'/', b's', 2, 1, 0, 0, 0, b'k',
            11, 4, 0, 0, 0, 1, 0, 0, 0,
        ];
        for (hello, bytes) in [(unix, &unix_bytes[..]), (windows, &windows_bytes[..])] {
            assert_eq!(hello.encode(), bytes);
            let (kind, body, used) = split(bytes, SMALL).unwrap().unwrap();
            assert_eq!((kind, used), (HELLO, bytes.len()));
            assert_eq!(Hello::decode(body).unwrap(), hello);
            // An owner from before FEATURES has none.
            let old = Hello::decode(&body[..body.len() - 9]).unwrap();
            assert_eq!(old.features, 0);
        }
        // The other app kind and serving values, which the bytes above
        // don't show.
        assert_eq!(app_kind(Kind::Windowed), 0);
        assert_eq!((serving::TAKING, serving::DECLINING), (0, 2));
    }

    // A launch reads a HELLO of up to SMALL bytes beside its own STATE, so
    // an owner of the same state is read however long the state is. With
    // the room for an empty STATE alone, the same HELLO is too large.
    #[test]
    fn a_hello_fits_beside_the_launchs_own_state() {
        let hello = Hello {
            wire_min: 1,
            wire_max: 1,
            app_id: "a".into(),
            app_kind: app_kind(Kind::Headless),
            nonce: 1,
            payload_version: 0,
            max_request: MAX_REQUEST,
            serving: serving::TAKING,
            level: None,
            state: vec![b'x'; 5000],
            features: features::REFUSALS,
        };
        let bytes = hello.encode();
        let len = bytes.len() - HEADER;
        assert!(len > SMALL, "{len}");
        let (kind, body, used) = split(&bytes, hello_limit(&hello.state)).unwrap().unwrap();
        assert_eq!((kind, used), (HELLO, bytes.len()));
        assert_eq!(Hello::decode(body).unwrap(), hello);
        assert_eq!(
            split(&bytes, hello_limit(&[])),
            Err(Error::TooLarge {
                size: len,
                limit: SMALL
            })
        );
    }

    #[test]
    fn request_bytes_are_frozen() {
        let full = Request {
            wire: 1,
            payload_version: 3,
            cwd: Some(b"/w".to_vec()),
            xdg_activation_token: Some("tok".into()),
            startup_id: Some("id".into()),
            payload: vec![0, 159, 146, 150],
        };
        #[rustfmt::skip]
        let full_bytes = [
            b'I', b'H', b'N', b'D', 2, 47, 0, 0, 0,
            1, 2, 0, 0, 0, 1, 0,
            2, 4, 0, 0, 0, 3, 0, 0, 0,
            3, 2, 0, 0, 0, b'/', b'w',
            4, 3, 0, 0, 0, b't', b'o', b'k',
            5, 2, 0, 0, 0, b'i', b'd',
            6, 4, 0, 0, 0, 0, 159, 146, 150,
        ];
        // Without the optional records. The payload goes even when empty.
        let bare = Request {
            wire: 1,
            payload_version: 3,
            ..Request::default()
        };
        #[rustfmt::skip]
        let bare_bytes = [
            b'I', b'H', b'N', b'D', 2, 21, 0, 0, 0,
            1, 2, 0, 0, 0, 1, 0,
            2, 4, 0, 0, 0, 3, 0, 0, 0,
            6, 0, 0, 0, 0,
        ];
        for (req, bytes) in [(full, &full_bytes[..]), (bare, &bare_bytes[..])] {
            assert_eq!(req.encode(), bytes);
            let (kind, body, used) = split(bytes, MAX_REQUEST as usize).unwrap().unwrap();
            assert_eq!((kind, used), (REQUEST, bytes.len()));
            assert_eq!(Request::decode(body).unwrap(), req);
        }
    }

    #[test]
    fn ready_and_commit_bytes_are_frozen() {
        for (kind, bytes) in [
            (READY, [b'I', b'H', b'N', b'D', 3, 0, 0, 0, 0]),
            (COMMIT, [b'I', b'H', b'N', b'D', 4, 0, 0, 0, 0]),
        ] {
            assert_eq!(empty(kind), bytes);
            let (k, body, used) = split(&bytes, SMALL).unwrap().unwrap();
            assert_eq!((k, used), (kind, bytes.len()));
            assert_eq!(check_empty(body), Ok(()));
        }
    }

    #[test]
    fn reply_bytes_are_frozen() {
        let check = |reply: Reply, bytes: &[u8]| {
            assert_eq!(reply.encode(), bytes, "{reply:?}");
            let (kind, body, used) = split(bytes, SMALL).unwrap().unwrap();
            assert_eq!((kind, used), (REPLY, bytes.len()));
            assert_eq!(Reply::decode(body).unwrap(), reply);
        };
        for (reply, delivered, code) in [
            (Reply::new(true, status::TAKEN), 1, 0),
            (Reply::new(false, status::BUSY), 0, 1),
            (Reply::new(false, status::DECLINED), 0, 2),
            (Reply::new(false, status::GAVE_UP), 0, 4),
        ] {
            #[rustfmt::skip]
            let bytes = [
                b'I', b'H', b'N', b'D', 5, 12, 0, 0, 0,
                1, 1, 0, 0, 0, delivered,
                2, 1, 0, 0, 0, code,
            ];
            check(reply, &bytes);
        }
        for (why, code) in [
            (refusal::WIRE, 1),
            (refusal::APP, 2),
            (refusal::PAYLOAD_VERSION, 3),
            (refusal::UNDECODABLE, 4),
            (refusal::TOO_LARGE, 5),
            (refusal::MALFORMED, 6),
            (refusal::UNSUPPORTED, 7),
            (refusal::PEER, 10),
        ] {
            #[rustfmt::skip]
            let bytes = [
                b'I', b'H', b'N', b'D', 5, 18, 0, 0, 0,
                1, 1, 0, 0, 0, 0,
                2, 1, 0, 0, 0, 3,
                3, 1, 0, 0, 0, code,
            ];
            check(Reply::refused(why), &bytes);
        }
        // A payload-version refusal carries the owner's version.
        let mut reply = Reply::refused(refusal::PAYLOAD_VERSION);
        reply.payload_version = Some(4);
        #[rustfmt::skip]
        let bytes = [
            b'I', b'H', b'N', b'D', 5, 27, 0, 0, 0,
            1, 1, 0, 0, 0, 0,
            2, 1, 0, 0, 0, 3,
            3, 1, 0, 0, 0, 3,
            4, 4, 0, 0, 0, 4, 0, 0, 0,
        ];
        check(reply, &bytes);
    }

    #[test]
    fn request_and_reply_round_trip() {
        let req = Request {
            wire: 1,
            payload_version: 3,
            cwd: Some(b"/home/u".to_vec()),
            xdg_activation_token: Some("tok".into()),
            startup_id: None,
            payload: vec![0, 159, 146, 150],
        };
        let bytes = req.encode();
        let (kind, body, _) = split(&bytes, MAX_REQUEST as usize).unwrap().unwrap();
        assert_eq!(kind, REQUEST);
        assert_eq!(Request::decode(body).unwrap(), req);

        let mut reply = Reply::refused(refusal::PAYLOAD_VERSION);
        reply.payload_version = Some(4);
        let bytes = reply.encode();
        let (_, body, _) = split(&bytes, SMALL).unwrap().unwrap();
        assert_eq!(Reply::decode(body).unwrap(), reply);
    }

    #[test]
    fn unknown_records_are_skipped_unless_critical() {
        let base = Writer::new(REPLY)
            .bytes(1, &[1])
            .bytes(2, &[0])
            .bytes(0x40, b"later");
        let bytes = base.finish();
        let (_, body, _) = split(&bytes, SMALL).unwrap().unwrap();
        assert!(Reply::decode(body).unwrap().delivered);

        let bytes = Writer::new(REPLY)
            .bytes(1, &[1])
            .bytes(2, &[0])
            .bytes(0xc0, b"must know")
            .finish();
        let (_, body, _) = split(&bytes, SMALL).unwrap().unwrap();
        assert_eq!(Reply::decode(body), Err(Error::Unsupported));
    }

    #[test]
    fn bad_frames_are_refused() {
        // A duplicate record.
        let bytes = Writer::new(REPLY).bytes(1, &[1]).bytes(1, &[0]).finish();
        let (_, body, _) = split(&bytes, SMALL).unwrap().unwrap();
        assert_eq!(Reply::decode(body), Err(Error::Malformed));
        // A HELLO with every record it must have but STATE, and one with an
        // empty STATE too: State::none() and no scope.
        let bare = |app: &[u8]| {
            Writer::new(HELLO)
                .bytes(hello::WIRE, &[1, 0, 1, 0])
                .bytes(hello::APP, app)
                .bytes(hello::NONCE, &[0; 8])
                .bytes(hello::PAYLOAD_VERSION, &[0; 4])
                .bytes(hello::MAX_REQUEST, &[0; 4])
        };
        let with_app = |app: &[u8]| bare(app).bytes(hello::STATE, &[]).finish();
        // Without STATE: an owner that doesn't say what it holds.
        let bytes = bare(&[0]).finish();
        let (_, body, _) = split(&bytes, SMALL).unwrap().unwrap();
        assert_eq!(Hello::decode(body), Err(Error::Malformed));
        // A LEVEL that isn't a u32.
        let bytes = bare(&[0])
            .bytes(hello::LEVEL, &[0, 0x30])
            .bytes(hello::STATE, &[])
            .finish();
        let (_, body, _) = split(&bytes, SMALL).unwrap().unwrap();
        assert_eq!(Hello::decode(body), Err(Error::Malformed));
        // A HELLO whose APP record has no kind byte.
        let bytes = with_app(&[]);
        let (_, body, _) = split(&bytes, SMALL).unwrap().unwrap();
        assert_eq!(Hello::decode(body), Err(Error::Malformed));
        // With the kind byte alone, it decodes, with an empty id.
        let bytes = with_app(&[0]);
        let (_, body, _) = split(&bytes, SMALL).unwrap().unwrap();
        assert_eq!(
            Hello::decode(body).map(|h| (h.app_kind, h.app_id)),
            Ok((0, "".into()))
        );
        // A kind from a later release decodes; the launch reads it as
        // another app.
        let bytes = with_app(&[2, b'a']);
        let (_, body, _) = split(&bytes, SMALL).unwrap().unwrap();
        assert_eq!(
            Hello::decode(body).map(|h| (h.app_kind, h.app_id)),
            Ok((2, "a".into()))
        );
        // A record running past the body.
        assert_eq!(
            Records::parse(&[1, 9, 0, 0, 0, 1], &[1]).err(),
            Some(Error::Malformed)
        );
        // Someone else's protocol, seen from the first byte.
        assert_eq!(header(b"{\"v\"", SMALL), Err(Error::BadMagic));
        // A length over the limit, before the body is read.
        let mut big = Writer::new(REQUEST).finish();
        big[5..9].copy_from_slice(&(SMALL as u32 + 1).to_le_bytes());
        assert_eq!(
            header(&big, SMALL),
            Err(Error::TooLarge {
                size: SMALL + 1,
                limit: SMALL
            })
        );
        // Not all here yet.
        assert_eq!(header(b"IHN", SMALL), Ok(None));
    }

    #[test]
    fn os_strings_travel_losslessly() {
        #[cfg(unix)]
        let s = {
            use std::os::unix::ffi::OsStrExt;
            OsStr::from_bytes(b"caf\xe9.pdf").to_os_string()
        };
        #[cfg(windows)]
        let s = {
            use std::os::windows::ffi::OsStringExt;
            OsString::from_wide(&[0x63, 0xd800, 0x66])
        };
        #[cfg(not(any(unix, windows)))]
        let s = OsString::from("café");
        assert_eq!(os_from_bytes(&os_to_bytes(&s)).unwrap(), s);
    }
}
