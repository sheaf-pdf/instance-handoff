//! The launch's side of the exchange: take the lock, or hand the request
//! to whoever holds it.

use std::io;
use std::time::{Duration, Instant};

use crate::wire::{self, Hello, Reply, refusal, state, status};
use crate::{
    Activation, AppId, Builder, Claim, ElevatedOwner, Ineligible, Kind, Mode, OwnerInfo, Payload,
    Reason, Started, sys,
};

/// Between attempts while the owner starts, is busy or quits.
const RETRY: Duration = Duration::from_millis(50);
/// A `Separate` launch that finds the lock held looks again for this long,
/// so a `hand_off` or `probe` testing the lock isn't taken for an owner.
const SEPARATE_RETRY: Duration = Duration::from_millis(50);
/// The least a committed launch waits for the owner's reply.
const MIN_POST_COMMIT: Duration = Duration::from_secs(1);
/// The least time a handoff to a healthy owner needs: shorter timeouts are
/// raised to this.
const MIN_TIMEOUT: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy)]
enum Waiting {
    Busy,
    Unresponsive,
}

impl Waiting {
    /// What this attempt says, given the last one. An owner that said busy
    /// is still reported busy when the deadline cut the next attempt short.
    fn after(self, last: Option<Waiting>, deadline: Option<Instant>) -> Waiting {
        match (self, last) {
            (Waiting::Unresponsive, Some(Waiting::Busy)) if past(deadline) => Waiting::Busy,
            _ => self,
        }
    }

    fn reason(self, waited: Duration) -> Reason {
        match self {
            Waiting::Busy => Reason::Busy { waited },
            Waiting::Unresponsive => Reason::Unresponsive { waited },
        }
    }
}

/// How one connection to the owner ended.
enum Exchange {
    /// The owner's handler took the request (or, for a probe, it serves).
    Taken(OwnerInfo),
    /// Committed, and the owner went silent: delivered late or never.
    Unconfirmed(OwnerInfo),
    Fail(Reason),
    /// Not delivered; try again until the deadline.
    Retry(Waiting),
    /// Committed, and then the connection closed with no reply: the owner
    /// with this nonce may have died.
    Lost(u64),
    /// After a lost commit: the owner committed to is still there.
    SameOwner,
}

fn past(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|d| Instant::now() >= d)
}

fn pause(deadline: Option<Instant>) {
    let mut wait = RETRY;
    if let Some(d) = deadline {
        wait = wait.min(d.saturating_duration_since(Instant::now()));
    }
    if !wait.is_zero() {
        std::thread::sleep(wait);
    }
}

fn post_commit_wait(timeout: Duration) -> Duration {
    timeout.max(MIN_POST_COMMIT)
}

/// When a launch must stop trying, and when it must return whatever
/// happened: the timeout, then at most one post-commit wait more.
#[derive(Debug, Clone, Copy)]
struct Limits {
    deadline: Option<Instant>,
    hard: Option<Instant>,
    timeout: Duration,
}

impl Limits {
    fn new(began: Instant, timeout: Duration) -> Limits {
        let timeout = timeout.max(MIN_TIMEOUT);
        Limits {
            deadline: began.checked_add(timeout),
            hard: timeout
                .checked_add(post_commit_wait(timeout))
                .and_then(|t| began.checked_add(t)),
            timeout,
        }
    }

    /// How long to wait for a reply after committing now.
    fn after_commit(&self) -> Option<Instant> {
        earliest(
            Instant::now().checked_add(post_commit_wait(self.timeout)),
            self.hard,
        )
    }
}

/// The earlier of two deadlines, where `None` is never.
fn earliest(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, None) => a,
        (None, b) => b,
    }
}

fn not_ours() -> Reason {
    Reason::WireVersion {
        ours: u32::from(wire::WIRE_MAX),
        theirs: 0,
    }
}

fn encode_request<T: Payload>(b: &Builder, payload: &T) -> Result<Vec<u8>, Reason> {
    let payload = payload
        .encode()
        .map_err(|source| Reason::Encode { source })?;
    let activation = Activation::from_env();
    Ok(wire::Request {
        wire: wire::WIRE_MAX,
        payload_version: b.payload_version,
        cwd: std::env::current_dir()
            .ok()
            .map(|d| wire::os_to_bytes(d.as_os_str())),
        xdg_activation_token: activation.xdg_activation_token().map(str::to_owned),
        startup_id: activation.startup_id().map(str::to_owned),
        payload,
    }
    .encode())
}

/// Why a launch of an app of `kind` may not own under `policy`, if it may
/// not. `windows`: whether it can show windows, where that is known.
/// `raised`: its rights were raised from a login. `above_normal`: it has
/// more rights than a normal process.
fn ineligible(
    kind: Kind,
    windows: Option<bool>,
    policy: ElevatedOwner,
    raised: bool,
    above_normal: bool,
) -> Option<Ineligible> {
    // First, since no policy lets it own.
    if kind == Kind::Windowed && windows == Some(false) {
        return Some(Ineligible::NoWindows);
    }
    match policy {
        ElevatedOwner::Allow => None,
        _ if raised => Some(Ineligible::Raised),
        ElevatedOwner::NotAboveNormal if above_normal => Some(Ineligible::AboveNormal),
        _ => None,
    }
}

pub(crate) fn start<T: Payload>(b: &Builder, payload: &T) -> Started<T> {
    if !sys::SUPPORTED {
        return Started::Alone(Reason::Unsupported {});
    }
    let may_not_own = ineligible(
        b.app_id.kind(),
        sys::can_show_windows(),
        b.elevated_owner,
        sys::raised(),
        sys::above_normal(),
    );
    start_as(b, payload, may_not_own)
}

/// `start` for a launch that may own, or that may not, and why.
fn start_as<T: Payload>(b: &Builder, payload: &T, may_not_own: Option<Ineligible>) -> Started<T> {
    if let Some(why) = may_not_own {
        // It never takes the lock, nor creates the folder: it hands off as
        // `hand_off` does, or runs alone at once.
        if b.mode == Mode::Separate {
            return Started::Alone(Reason::MayNotOwn { why });
        }
        return match hand_off(b, Some(payload)) {
            Ok(info) => Started::HandedOff(info),
            Err(Reason::NoOwner {}) => Started::Alone(Reason::MayNotOwn { why }),
            Err(reason) => Started::Alone(reason),
        };
    }
    let state = b.canonical_state();
    // Before anything is created: a launch never makes or owns state in
    // another user's folder. `hand_off` and `probe` write nothing there.
    if let Some(path) = state.as_deref().and_then(crate::state::foreign) {
        return Started::Alone(Reason::ForeignState { path });
    }
    let place = match b.place(state.as_deref()) {
        Ok(place) => place,
        Err(reason) => return Started::Alone(reason),
    };
    let open = |place| match sys::open_folder(place, true) {
        Ok(Some(folder)) => Ok(folder),
        Ok(None) => Err(Reason::NoRuntimeDir {}),
        Err(reason) => Err(reason),
    };
    let mut folder = match open(&place) {
        Ok(folder) => folder,
        Err(reason) => return Started::Alone(reason),
    };
    let began = Instant::now();
    let limits = Limits::new(began, b.timeout);
    let deadline = limits.deadline;
    let mut request: Option<Vec<u8>> = None;
    let mut waiting: Option<Waiting> = None;
    loop {
        match folder.lock() {
            Ok(Some(lock)) => return Started::Owner(Claim::new(b, place, folder, lock, state)),
            Ok(None) => {}
            // The folder was deleted under this launch (a cleaner, `rm`):
            // open it afresh and keep going.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                folder = match open(&place) {
                    Ok(folder) => folder,
                    Err(reason) => return Started::Alone(reason),
                };
                continue;
            }
            Err(source) => {
                return Started::Alone(Reason::Lock {
                    path: folder.lock_path(),
                    source,
                });
            }
        }
        // The lock was the last chance; no new attempt starts past the
        // deadline.
        if let Some(w) = waiting.filter(|_| past(deadline)) {
            return Started::Alone(w.reason(began.elapsed()));
        }
        if b.mode == Mode::Separate {
            let until = Instant::now() + SEPARATE_RETRY;
            while Instant::now() < until {
                std::thread::sleep(Duration::from_millis(5));
                match try_own(&folder) {
                    Ok(Some(lock)) => {
                        return Started::Owner(Claim::new(b, place, folder, lock, state));
                    }
                    Ok(None) => {}
                    Err(reason) => return Started::Alone(reason),
                }
            }
            return Started::Alone(Reason::OwnerRunning {});
        }
        // Encoded only once a handoff is needed, and before connecting, so a
        // payload that can't be encoded never reaches the owner.
        let bytes = match &mut request {
            Some(bytes) => bytes,
            None => match encode_request(b, payload) {
                Ok(bytes) => request.insert(bytes),
                Err(reason) => return Started::Alone(reason),
            },
        };
        match exchange(&folder, b, Some(bytes), &limits, None) {
            Exchange::Taken(info) | Exchange::Unconfirmed(info) => return Started::HandedOff(info),
            Exchange::Fail(reason) => return Started::Alone(reason),
            Exchange::Retry(w) => waiting = Some(w.after(waiting, deadline)),
            Exchange::SameOwner => unreachable!("no commit to compare with"),
            Exchange::Lost(nonce) => {
                return match after_commit(&folder, b, bytes, nonce, true, &limits) {
                    AfterCommit::Own(lock) => {
                        Started::Owner(Claim::new(b, place, folder, lock, state))
                    }
                    AfterCommit::Info(info) => Started::HandedOff(info),
                };
            }
        }
        pause(deadline);
    }
}

fn try_own(folder: &sys::Folder) -> Result<Option<sys::Lock>, Reason> {
    folder.lock().map_err(|source| Reason::Lock {
        path: folder.lock_path(),
        source,
    })
}

/// `hand_off` with a payload, `probe` without one.
pub(crate) fn hand_off<T: Payload>(b: &Builder, payload: Option<&T>) -> Result<OwnerInfo, Reason> {
    if !sys::SUPPORTED {
        return Err(Reason::Unsupported {});
    }
    let place = b.place(b.canonical_state().as_deref())?;
    let Some(folder) = sys::open_folder(&place, false)? else {
        return Err(Reason::NoOwner {});
    };
    let request = payload.map(|p| encode_request(b, p)).transpose()?;
    let began = Instant::now();
    let limits = Limits::new(began, b.timeout);
    let deadline = limits.deadline;
    let mut waiting: Option<Waiting> = None;
    loop {
        match folder.lock_held() {
            Ok(true) => {}
            Ok(false) => return Err(Reason::NoOwner {}),
            Err(source) => {
                return Err(Reason::Lock {
                    path: folder.lock_path(),
                    source,
                });
            }
        }
        if let Some(w) = waiting.filter(|_| past(deadline)) {
            return Err(w.reason(began.elapsed()));
        }
        match exchange(&folder, b, request.as_deref(), &limits, None) {
            Exchange::Taken(info) | Exchange::Unconfirmed(info) => return Ok(info),
            Exchange::Fail(reason) => return Err(reason),
            Exchange::Retry(w) => waiting = Some(w.after(waiting, deadline)),
            Exchange::SameOwner => unreachable!("no commit to compare with"),
            Exchange::Lost(nonce) => {
                let bytes = request.as_deref().expect("only a request commits");
                return match after_commit(&folder, b, bytes, nonce, false, &limits) {
                    AfterCommit::Info(info) => Ok(info),
                    AfterCommit::Own(_) => unreachable!("a handoff never owns"),
                };
            }
        }
        pause(deadline);
    }
}

enum AfterCommit {
    Own(sys::Lock),
    Info(OwnerInfo),
}

/// The connection closed after this launch committed, with no reply. The
/// owner may have died with the request or without it; this launch must
/// not run alone on it. It takes the lock if nobody holds it (`may_own`),
/// or hands the request to the next owner, one with another nonce.
/// Otherwise (no owner in time, or one that won't take it) it is handed
/// off, unconfirmed: the dead owner may have had it.
fn after_commit(
    folder: &sys::Folder,
    b: &Builder,
    bytes: &[u8],
    mut nonce: u64,
    may_own: bool,
    limits: &Limits,
) -> AfterCommit {
    let until = limits.after_commit();
    let inner = Limits {
        deadline: until,
        ..*limits
    };
    let unconfirmed = OwnerInfo {
        pid: None,
        confirmed: false,
        level: None,
        handed_down: None,
    };
    loop {
        if may_own {
            match folder.lock() {
                Ok(Some(lock)) => return AfterCommit::Own(lock),
                Ok(None) => {}
                Err(_) => return AfterCommit::Info(unconfirmed),
            }
        } else if !folder.lock_held().unwrap_or(true) {
            return AfterCommit::Info(unconfirmed);
        }
        match exchange(folder, b, Some(bytes), &inner, Some(nonce)) {
            Exchange::Taken(info) | Exchange::Unconfirmed(info) => return AfterCommit::Info(info),
            Exchange::SameOwner | Exchange::Fail(_) => return AfterCommit::Info(unconfirmed),
            Exchange::Lost(n) => nonce = n,
            Exchange::Retry(_) => {}
        }
        if past(until) {
            return AfterCommit::Info(unconfirmed);
        }
        pause(until);
    }
}

/// Whether `hello` comes from an owner of `app_id`: the same id and kind.
/// The two kinds of an id share its folder, so an owner of the other kind
/// is another app.
fn same_app(hello: &Hello, app_id: &AppId) -> bool {
    hello.app_id == app_id.as_str() && hello.app_kind == wire::app_kind(app_id.kind())
}

/// One connection: HELLO, checks, REQUEST, READY, COMMIT, REPLY. Without a
/// request (a probe), it ends after HELLO. `committed_to` is the nonce of
/// an owner this launch already committed to.
fn exchange(
    folder: &sys::Folder,
    b: &Builder,
    request: Option<&[u8]>,
    limits: &Limits,
    committed_to: Option<u64>,
) -> Exchange {
    let deadline = limits.deadline;
    let mut conn = match folder.connect(deadline) {
        Ok(conn) => conn,
        Err(sys::Connect::Retry(e)) => {
            log::trace!(
                "instance-handoff {}: no owner to connect to yet: {e}",
                b.app_id
            );
            return Exchange::Retry(Waiting::Unresponsive);
        }
        Err(sys::Connect::Peer(source)) => return Exchange::Fail(Reason::Peer { source }),
    };
    let mut reader = Reader::default();
    // The owner speaks first, and only once it serves: until then this
    // waits in its backlog.
    let hello = match reader.frame(&mut conn, wire::SMALL, deadline) {
        Ok((wire::HELLO, body)) => match Hello::decode(&body) {
            Ok(hello) => hello,
            Err(_) => return Exchange::Fail(not_ours()),
        },
        // Refused in place of HELLO: a Unix owner that won't serve this
        // launch's user.
        Ok((wire::REPLY, body)) => {
            return Exchange::Fail(match Reply::decode(&body) {
                Ok(r) if !r.delivered && r.status == status::REFUSED => refused(&r, None, b, &[]),
                _ => not_ours(),
            });
        }
        Ok(_) | Err(ReadError::Bad) => return Exchange::Fail(not_ours()),
        Err(ReadError::Closed | ReadError::TimedOut) => {
            return Exchange::Retry(Waiting::Unresponsive);
        }
    };
    if !same_app(&hello, &b.app_id) {
        return Exchange::Fail(Reason::OtherApp {});
    }
    if hello.wire_max < wire::WIRE_MIN || hello.wire_min > wire::WIRE_MAX {
        return Exchange::Fail(Reason::WireVersion {
            ours: u32::from(wire::WIRE_MAX),
            theirs: u32::from(hello.wire_max),
        });
    }
    if hello.payload_version != b.payload_version {
        return Exchange::Fail(Reason::PayloadVersion {
            ours: b.payload_version,
            theirs: hello.payload_version,
        });
    }
    if committed_to == Some(hello.nonce) {
        return Exchange::SameOwner;
    }
    match hello.state {
        state::TAKING => {}
        state::DECLINING => return Exchange::Fail(Reason::Declined {}),
        // Busy, and states this build doesn't know: a later release that
        // wants old launches to send their request advertises TAKING and
        // lets its REPLY decide.
        _ => return Exchange::Retry(Waiting::Busy),
    }
    let info = OwnerInfo {
        pid: conn.peer_pid(),
        confirmed: true,
        level: None,
        handed_down: None,
    };
    let Some(request) = request else {
        // A probe: the owner serves. Leave without sending anything.
        return Exchange::Taken(info);
    };
    let limit = hello.max_request as usize;
    if request.len() - wire::HEADER > limit {
        return Exchange::Fail(Reason::TooLarge {
            size: request.len(),
            limit,
        });
    }
    sys::before_hand_off(info.pid);
    if conn.write_all(request, deadline).is_err() {
        return Exchange::Retry(Waiting::Unresponsive);
    }
    match reader.frame(&mut conn, wire::SMALL, deadline) {
        Ok((wire::READY, body)) if wire::check_empty(&body).is_ok() => {}
        Ok((wire::REPLY, body)) => return reply(&body, &hello, b, request, info, false),
        Ok(_) | Err(ReadError::Bad) => return Exchange::Fail(not_ours()),
        Err(ReadError::Closed | ReadError::TimedOut) => {
            return Exchange::Retry(Waiting::Unresponsive);
        }
    }
    // Committing is this launch's decision, made only inside its timeout.
    // Past it, it leaves, and the owner never delivers the request.
    if past(deadline) {
        return Exchange::Retry(Waiting::Unresponsive);
    }
    if conn
        .write_all(&wire::empty(wire::COMMIT), deadline)
        .is_err()
    {
        return Exchange::Retry(Waiting::Unresponsive);
    }
    let until = limits.after_commit();
    let unconfirmed = OwnerInfo {
        confirmed: false,
        ..info.clone()
    };
    match reader.frame(&mut conn, wire::SMALL, until) {
        Ok((wire::REPLY, body)) => reply(&body, &hello, b, request, info, true),
        Err(ReadError::Closed) => Exchange::Lost(hello.nonce),
        Ok(_) | Err(ReadError::Bad | ReadError::TimedOut) => Exchange::Unconfirmed(unconfirmed),
    }
}

fn reply(
    body: &[u8],
    hello: &Hello,
    b: &Builder,
    request: &[u8],
    info: OwnerInfo,
    committed: bool,
) -> Exchange {
    let Ok(r) = Reply::decode(body) else {
        return if committed {
            Exchange::Unconfirmed(OwnerInfo {
                confirmed: false,
                ..info
            })
        } else {
            Exchange::Fail(not_ours())
        };
    };
    if r.delivered {
        return Exchange::Taken(info);
    }
    match r.status {
        status::DECLINED => Exchange::Fail(Reason::Declined {}),
        status::REFUSED => Exchange::Fail(refused(&r, Some(hello), b, request)),
        status::GAVE_UP => Exchange::Retry(Waiting::Unresponsive),
        // Busy, and statuses this build doesn't know: not delivered.
        _ => Exchange::Retry(Waiting::Busy),
    }
}

/// Why the owner refused this launch. `hello` is `None` when the refusal
/// came in place of HELLO, before this launch sent anything.
fn refused(r: &Reply, hello: Option<&Hello>, b: &Builder, request: &[u8]) -> Reason {
    let wire_version = Reason::WireVersion {
        ours: u32::from(wire::WIRE_MAX),
        theirs: hello.map_or(0, |h| u32::from(h.wire_max)),
    };
    match (r.refusal, hello) {
        (Some(refusal::PEER), _) => Reason::Peer {
            source: io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the owner refused this launch: another user or level, or a check that failed",
            ),
        },
        (Some(refusal::APP), _) => Reason::OtherApp {},
        (Some(refusal::PAYLOAD_VERSION), Some(hello)) => Reason::PayloadVersion {
            ours: b.payload_version,
            theirs: r.payload_version.unwrap_or(hello.payload_version),
        },
        (Some(refusal::UNDECODABLE), Some(_)) => Reason::Undecodable {},
        (Some(refusal::TOO_LARGE), Some(hello)) => Reason::TooLarge {
            size: request.len(),
            limit: hello.max_request as usize,
        },
        // Before HELLO, those three answer a request that was never sent.
        (Some(refusal::PAYLOAD_VERSION | refusal::UNDECODABLE | refusal::TOO_LARGE), None)
        | (None | Some(refusal::WIRE | refusal::MALFORMED | refusal::UNSUPPORTED), _) => {
            wire_version
        }
        // A cause from a later release.
        (Some(_), _) => Reason::Declined {},
    }
}

enum ReadError {
    Closed,
    TimedOut,
    /// Not this protocol, or broken.
    Bad,
}

#[derive(Default)]
struct Reader {
    buf: Vec<u8>,
}

impl Reader {
    fn frame(
        &mut self,
        conn: &mut sys::Conn,
        limit: usize,
        deadline: Option<Instant>,
    ) -> Result<(u8, Vec<u8>), ReadError> {
        loop {
            match wire::split(&self.buf, limit) {
                Ok(Some((kind, body, used))) => {
                    let body = body.to_vec();
                    self.buf.drain(..used);
                    return Ok((kind, body));
                }
                Ok(None) => {}
                Err(_) => return Err(ReadError::Bad),
            }
            let mut chunk = [0u8; 4096];
            match conn.read(&mut chunk, deadline) {
                Ok(0) => return Err(ReadError::Closed),
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == io::ErrorKind::TimedOut => return Err(ReadError::TimedOut),
                Err(_) => return Err(ReadError::Closed),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use refusal::*;

    const KNOWN: [u8; 8] = [
        WIRE,
        APP,
        PAYLOAD_VERSION,
        UNDECODABLE,
        TOO_LARGE,
        MALFORMED,
        UNSUPPORTED,
        PEER,
    ];

    fn hello() -> Hello {
        Hello {
            wire_min: 1,
            wire_max: 1,
            app_id: "test".into(),
            app_kind: wire::app_kind(Kind::Headless),
            nonce: 7,
            payload_version: 2,
            max_request: 100,
            state: state::TAKING,
            features: wire::features::REFUSALS,
        }
    }

    /// What this launch makes of REPLY REFUSED with `code`, after `hello`
    /// or in place of it.
    fn refused_with(code: Option<u8>, hello: Option<&Hello>) -> Reason {
        let b = Builder::new(AppId::headless("test"), crate::State::none()).payload_version(3);
        let reply = Reply {
            refusal: code,
            ..Reply::new(false, status::REFUSED)
        };
        refused(&reply, hello, &b, &[0; 200])
    }

    // Both ways, and a kind from a later release: the two kinds of an id
    // refuse each other.
    #[test]
    fn an_owner_of_the_other_kind_is_another_app() {
        let app = |kind| AppId::parse("test", kind).unwrap();
        let mut owner = hello();
        for (kind, other) in [
            (Kind::Windowed, Kind::Headless),
            (Kind::Headless, Kind::Windowed),
        ] {
            owner.app_kind = wire::app_kind(kind);
            assert!(same_app(&owner, &app(kind)), "{kind:?}");
            assert!(!same_app(&owner, &app(other)), "{kind:?}");
        }
        owner.app_kind = 2;
        assert!(!same_app(&owner, &app(Kind::Windowed)));
        assert!(!same_app(&owner, &app(Kind::Headless)));
        assert!(!same_app(&hello(), &AppId::headless("other")));
    }

    // Raised: rights raised from a login. Above normal: root, on Unix.
    #[test]
    fn who_may_own() {
        use ElevatedOwner::*;
        use Ineligible::*;
        use Kind::*;
        let rows = [
            // (policy, raised, above normal): why it may not own, where
            // windows don't stop it.
            ((NotRaised, false, false), None),
            ((NotRaised, false, true), None),
            ((NotRaised, true, false), Some(Raised)),
            ((NotRaised, true, true), Some(Raised)),
            ((NotAboveNormal, false, false), None),
            ((NotAboveNormal, false, true), Some(AboveNormal)),
            ((NotAboveNormal, true, false), Some(Raised)),
            ((NotAboveNormal, true, true), Some(Raised)),
            ((Allow, false, false), None),
            ((Allow, false, true), None),
            ((Allow, true, false), None),
            ((Allow, true, true), None),
        ];
        // A headless app's launch, whatever its windows, and a windowed
        // app's that can show them or might: only its rights count.
        let free = [
            (Headless, Some(false)),
            (Headless, None),
            (Headless, Some(true)),
            (Windowed, None),
            (Windowed, Some(true)),
        ];
        for (kind, windows) in free {
            for ((policy, raised, above), why) in rows {
                assert_eq!(
                    ineligible(kind, windows, policy, raised, above),
                    why,
                    "{kind:?} {windows:?} {policy:?} {raised} {above}"
                );
            }
        }
        // A windowed app's launch that can't show windows never owns,
        // whatever its rights and the policy.
        for ((policy, raised, above), _) in rows {
            assert_eq!(
                ineligible(Windowed, Some(false), policy, raised, above),
                Some(NoWindows),
                "{policy:?} {raised} {above}"
            );
        }
    }

    // A launch told it may not own never takes the lock or makes the
    // folder. It hands off to an owner that is running, and otherwise runs
    // alone.
    #[cfg(any(unix, windows))]
    #[test]
    fn a_launch_that_may_not_own_hands_off_or_runs_alone() {
        use crate::Args;
        let tmp = tempfile::tempdir().unwrap();
        let run = tmp.path().join("run");
        let b = Builder::new(AppId::headless("test.gate"), crate::State::none())
            .dir(&run)
            .timeout(Duration::from_secs(3));
        let raised = Some(Ineligible::Raised);
        let may_not_own = |started: Started<Args>| match started {
            Started::Alone(Reason::MayNotOwn { why }) => why,
            other => panic!("expected MayNotOwn: {other:?}"),
        };
        let own = |started: Started<Args>| match started {
            Started::Owner(claim) => claim,
            other => panic!("expected the owner: {other:?}"),
        };

        let why = may_not_own(start_as(&b, &Args::default(), raised));
        assert_eq!(why, Ineligible::Raised);
        assert!(!run.exists());

        let (tx, rx) = std::sync::mpsc::channel();
        let owner = own(start_as(&b, &Args::default(), None)).serve(move |r| tx.send(r).is_ok());
        let sent = Args::new(["raised"]);
        match start_as(&b, &sent, raised) {
            Started::HandedOff(info) => assert!(info.confirmed()),
            other => panic!("expected to hand off: {other:?}"),
        }
        let got = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(got.payload(), &sent);
        // A separate launch never hands off.
        let separate = b.clone().mode(Mode::Separate);
        may_not_own(start_as(&separate, &Args::default(), raised));

        // The folder stays, with nobody holding its lock.
        owner.release();
        may_not_own(start_as(&b, &Args::default(), raised));
        own(start_as(&b, &Args::default(), None)).release();
    }

    #[test]
    fn each_known_cause_has_its_reason() {
        let hello = hello();
        let at = |code| refused_with(Some(code), Some(&hello));
        for code in [None, Some(WIRE), Some(MALFORMED), Some(UNSUPPORTED)] {
            let reason = refused_with(code, Some(&hello));
            assert!(
                matches!(reason, Reason::WireVersion { ours: 1, theirs: 1 }),
                "{code:?}: {reason}"
            );
        }
        let reason = at(APP);
        assert!(matches!(reason, Reason::OtherApp {}), "{reason}");
        let reason = at(PAYLOAD_VERSION);
        assert!(
            matches!(reason, Reason::PayloadVersion { ours: 3, theirs: 2 }),
            "{reason}"
        );
        let reason = at(UNDECODABLE);
        assert!(matches!(reason, Reason::Undecodable {}), "{reason}");
        let reason = at(TOO_LARGE);
        assert!(
            matches!(
                reason,
                Reason::TooLarge {
                    size: 200,
                    limit: 100
                }
            ),
            "{reason}"
        );
        let reason = at(PEER);
        assert!(matches!(reason, Reason::Peer { .. }), "{reason}");
    }

    #[test]
    fn a_cause_this_build_doesnt_know_reads_as_declined() {
        let hello = hello();
        for code in (0..=255).filter(|c| !KNOWN.contains(c)) {
            for hello in [Some(&hello), None] {
                let reason = refused_with(Some(code), hello);
                assert!(matches!(reason, Reason::Declined {}), "{code}: {reason}");
            }
        }
    }

    #[test]
    fn a_refusal_in_place_of_hello_is_about_the_launch() {
        let reason = refused_with(Some(PEER), None);
        assert!(matches!(reason, Reason::Peer { .. }), "{reason}");
        let reason = refused_with(Some(APP), None);
        assert!(matches!(reason, Reason::OtherApp {}), "{reason}");
        // This launch hasn't sent a request: an answer to one isn't this
        // protocol.
        for code in [
            WIRE,
            PAYLOAD_VERSION,
            UNDECODABLE,
            TOO_LARGE,
            MALFORMED,
            UNSUPPORTED,
        ] {
            let reason = refused_with(Some(code), None);
            assert!(
                matches!(reason, Reason::WireVersion { ours: 1, theirs: 0 }),
                "{code}: {reason}"
            );
        }
    }
}
