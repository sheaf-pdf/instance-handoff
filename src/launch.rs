//! The launch's side of the exchange: take the lock, or hand the request
//! to whoever holds it.

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::level::OwnerLevel;
use crate::outcome::Holding;
use crate::wire::{self, Hello, Reply, refusal, serving, status};
use crate::{
    Activation, AppId, Builder, Claim, ElevatedOwner, Exclusive, Guard, Ineligible, Kind, Level,
    OwnerInfo, Payload, Reason, Rights, Started, sys,
};

/// Between attempts while the owner starts, is busy or quits.
const RETRY: Duration = Duration::from_millis(50);
/// An exclusive run that takes no guard, and finds the lock held, looks
/// again for this long, so a `hand_off` or `probe` testing the lock isn't
/// taken for an owner.
const LOCK_RETRY: Duration = Duration::from_millis(50);
/// A launch that holds the lock and finds the guard held looks again for
/// this long. An owner that exits lets go of its lock a moment before its
/// guard, and a launch that takes the lock in between must not take the
/// guard for a live owner's.
const GUARD_RETRY: Duration = Duration::from_millis(50);
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

/// What a launch that found the lock held does about its owner.
#[derive(Debug)]
enum Meet {
    /// Connect, and talk to the owner: its pipe must be labelled at this
    /// level. `None` where there are no levels; on Windows, no label
    /// matches it.
    Talk(Option<Level>),
    /// Look again until the deadline: the owner is still starting.
    Wait,
    /// Return this at once, without connecting.
    Report(Result<OwnerInfo, Reason>),
}

/// What a launch at level `own` does about an owner at `owner`, as its
/// marker shows it, before it connects: see [`rights`]. `probe`: the
/// launch is a probe.
fn meet(own: Option<Level>, owner: OwnerLevel, probe: bool) -> Meet {
    match owner {
        OwnerLevel::Same => Meet::Talk(own),
        OwnerLevel::Starting => Meet::Wait,
        // Windows reads the launch's own level to look for the marker, so
        // here it is known. Were it not, `Talk(None)` matches no pipe's
        // label, so nothing is sent to an owner at another level.
        OwnerLevel::Other(owner) => match own.and_then(|own| rights(own, owner, probe)) {
            Some(answer) => Meet::Report(answer),
            None => Meet::Talk(own),
        },
    }
}

/// What a launch at level `own` is told about an owner at `owner`, without
/// sending anything more: when the levels differ, the owner above has
/// rights the launch lacks, or the owner below lacks the launch's. A probe
/// is told the owner runs instead. The answer names the owner's level, but
/// no pid, and is unconfirmed (call 6.3), however the launch learnt the
/// level: from the owner's marker ([`meet`]), its HELLO ([`exchange`]) or
/// its PRIVILEGE refusal ([`refused`]). `None` when the levels are the
/// same.
fn rights(own: Level, owner: Level, probe: bool) -> Option<Result<OwnerInfo, Reason>> {
    if owner == own {
        return None;
    }
    let info = OwnerInfo {
        pid: None,
        confirmed: false,
        level: Some(owner),
        handed_down: None,
    };
    if probe {
        return Some(Ok(info));
    }
    let rights = Rights::Level { launch: own, owner };
    Some(Err(if owner > own {
        Reason::OwnerHasMoreRights {
            owner: info,
            rights,
        }
    } else {
        Reason::MoreRights {
            owner: info,
            rights,
        }
    }))
}

/// [`meet`], for a launch whose owner died after it committed: it talks
/// to an owner it may talk to, and looks again for one still starting
/// until it is `past` its wait. Anything else, an owner at another level,
/// one that never finished starting or a marker that can't be read, gives
/// `None`: the request is handed off, unconfirmed, since the dead owner
/// may have had it.
fn meet_after_commit(met: Meet, past: bool) -> Option<Meet> {
    match met {
        Meet::Talk(_) => Some(met),
        Meet::Wait if !past => Some(met),
        Meet::Wait | Meet::Report(_) => None,
    }
}

/// [`meet`], for a launch at level `own` and the owner of the lock in
/// `folder`. A marker that can't be read gives [`Reason::Lock`].
fn meet_owner(folder: &sys::Folder, own: Option<Level>, probe: bool) -> Meet {
    match folder.owner_level() {
        Ok(owner) => meet(own, owner, probe),
        Err(source) => Meet::Report(Err(Reason::Lock {
            path: folder.lock_path(),
            source,
        })),
    }
}

/// How one connection to the owner ended.
enum Exchange {
    /// The owner's handler took the request. For a probe: the owner serves,
    /// or runs at another level, unconfirmed.
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
/// happened: the timeout, then at most one post-commit wait more. With the
/// launch's integrity level, which bounds whom it hands off to.
#[derive(Debug, Clone, Copy)]
struct Limits {
    deadline: Option<Instant>,
    hard: Option<Instant>,
    timeout: Duration,
    /// This launch's level: [`sys::level`], or one a test sets.
    level: Option<Level>,
}

impl Limits {
    fn new(began: Instant, timeout: Duration, level: Option<Level>) -> Limits {
        let timeout = timeout.max(MIN_TIMEOUT);
        Limits {
            deadline: began.checked_add(timeout),
            hard: timeout
                .checked_add(post_commit_wait(timeout))
                .and_then(|t| began.checked_add(t)),
            timeout,
            level,
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
    ineligible_rights(policy, raised, above_normal)
}

/// [`ineligible`] for its rights alone: why a launch may not own, or hold
/// the state with `exclusive`, under `policy`, if it may not. An exclusive
/// run serves no launches, so it needs no windows.
fn ineligible_rights(
    policy: ElevatedOwner,
    raised: bool,
    above_normal: bool,
) -> Option<Ineligible> {
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
    let key = b.instance_key(state.as_deref());
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
    let limits = Limits::new(began, b.timeout, sys::level());
    let deadline = limits.deadline;
    let mut request: Option<Vec<u8>> = None;
    let mut waiting: Option<Waiting> = None;
    loop {
        match folder.lock() {
            Ok(Some(lock)) => return own(b, place, folder, lock, state, key),
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
        let at = match meet_owner(&folder, limits.level, false) {
            Meet::Talk(at) => at,
            Meet::Wait => {
                waiting = Some(Waiting::Unresponsive.after(waiting, deadline));
                pause(deadline);
                continue;
            }
            Meet::Report(Err(reason)) => return Started::Alone(reason),
            Meet::Report(Ok(_)) => unreachable!("only a probe is told an owner runs"),
        };
        // Encoded only once a handoff is needed, and before connecting, so a
        // payload that can't be encoded never reaches the owner.
        let bytes = match &mut request {
            Some(bytes) => bytes,
            None => match encode_request(b, payload) {
                Ok(bytes) => request.insert(bytes),
                Err(reason) => return Started::Alone(reason),
            },
        };
        match exchange(&folder, b, &key, Some(bytes), &limits, None, at) {
            Exchange::Taken(info) | Exchange::Unconfirmed(info) => return Started::HandedOff(info),
            Exchange::Fail(reason) => return Started::Alone(reason),
            Exchange::Retry(w) => waiting = Some(w.after(waiting, deadline)),
            Exchange::SameOwner => unreachable!("no commit to compare with"),
            Exchange::Lost(nonce) => {
                let after = after_commit(
                    &folder,
                    b,
                    &key,
                    bytes,
                    nonce,
                    Some(state.as_deref()),
                    &limits,
                );
                return match after {
                    AfterCommit::Own(lock, guard) => {
                        Started::Owner(Claim::new(b, place, folder, lock, guard, state, key))
                    }
                    AfterCommit::Info(info) => Started::HandedOff(info),
                };
            }
        }
        pause(deadline);
    }
}

/// This launch took the `lock`: it owns, once it has the state folder and
/// holds its guard too. If another process holds the guard, the lock is
/// dropped here, before any socket is bound, and the launch runs alone.
fn own<T>(
    b: &Builder,
    place: sys::Place,
    folder: sys::Folder,
    lock: sys::Lock,
    state: Option<PathBuf>,
    key: Vec<u8>,
) -> Started<T> {
    match take_state(b, state.as_deref()) {
        Ok(guard) => Started::Owner(Claim::new(b, place, folder, lock, guard, state, key)),
        Err(reason) => Started::Alone(reason),
    }
}

/// For a launch that holds the lock: creates the canonical `state` folder
/// when it is missing, whatever the guard, then takes its guard, shared
/// for a keyed owner, so keyed owners of one state folder hold it side by
/// side, and otherwise alone. `None` when no guard is taken: see [`Guard`].
fn take_state(b: &Builder, state: Option<&Path>) -> Result<Option<sys::Guard>, Reason> {
    let Some(state) = state else {
        return Ok(None);
    };
    make_state(state)?;
    if b.guard != Guard::Local {
        return Ok(None);
    }
    take_guard(state, b.scope.is_some())
}

/// Creates the canonical `state` folder when it is missing. One that can't
/// be made gives [`Reason::Lock`], naming it.
fn make_state(state: &Path) -> Result<(), Reason> {
    sys::make_state_dir(state).map_err(|source| Reason::Lock {
        path: state.to_owned(),
        source,
    })
}

/// Takes the guard of the canonical `state` folder, which exists: `shared`
/// or alone. `None` where the guard is skipped: see [`Guard::Local`].
/// Still held after [`GUARD_RETRY`], it gives [`Reason::StateInUse`].
fn take_guard(state: &Path, shared: bool) -> Result<Option<sys::Guard>, Reason> {
    let until = Instant::now() + GUARD_RETRY;
    loop {
        match sys::take_guard(state, shared) {
            Err(Reason::StateInUse { .. }) if Instant::now() < until => {
                std::thread::sleep(Duration::from_millis(5));
            }
            taken => return taken,
        }
    }
}

pub(crate) fn exclusive(b: &Builder) -> Result<Exclusive, Reason> {
    if !sys::SUPPORTED {
        return Err(Reason::Unsupported {});
    }
    let may_not_own = ineligible_rights(b.elevated_owner, sys::raised(), sys::above_normal());
    exclusive_as(b, may_not_own)
}

/// `exclusive` for a launch that may hold the state, or that may not, and
/// why. It takes the guard alone, whatever the scope, and nothing else. It
/// takes the lock in the runtime folder instead, with nothing listening,
/// where it takes no guard: for no state folder, under [`Guard::Off`], or
/// where [`Guard::Local`] skips it.
fn exclusive_as(b: &Builder, may_not_own: Option<Ineligible>) -> Result<Exclusive, Reason> {
    if let Some(why) = may_not_own {
        return Err(Reason::MayNotOwn { why });
    }
    let state = b.canonical_state();
    // Before anything is created, as for `start`.
    if let Some(path) = state.as_deref().and_then(crate::state::foreign) {
        return Err(Reason::ForeignState { path });
    }
    if let Some(dir) = state.as_deref().filter(|_| b.guard == Guard::Local) {
        make_state(dir)?;
        if let Some(guard) = take_guard(dir, false)? {
            return Ok(Exclusive::new(state, Holding::Guard(guard)));
        }
    }
    let place = b.place(state.as_deref())?;
    let (folder, lock) = lock_alone(&place)?;
    // As `start` makes it once it holds the lock. Where the guard was
    // skipped, it is made already, and left as it is.
    if let Some(dir) = state.as_deref() {
        make_state(dir)?;
    }
    Ok(Exclusive::new(state, Holding::Lock(folder, lock)))
}

/// Opens the runtime folder at `place`, making it if it is missing, and
/// takes its lock for an exclusive run, looking again for [`LOCK_RETRY`].
/// Still held, it gives [`Reason::StateInUse`], naming the lock file.
fn lock_alone(place: &sys::Place) -> Result<(sys::Folder, sys::Lock), Reason> {
    let open = || sys::open_folder(place, true)?.ok_or(Reason::NoRuntimeDir {});
    let mut folder = open()?;
    let until = Instant::now() + LOCK_RETRY;
    loop {
        match folder.lock() {
            Ok(Some(lock)) => return Ok((folder, lock)),
            Ok(None) if Instant::now() < until => std::thread::sleep(Duration::from_millis(5)),
            Ok(None) => {
                return Err(Reason::StateInUse {
                    path: folder.lock_path(),
                });
            }
            // The folder was deleted under this run (a cleaner, `rm`): open
            // it afresh and keep going, as `start` does.
            Err(e) if e.kind() == io::ErrorKind::NotFound => folder = open()?,
            Err(source) => {
                return Err(Reason::Lock {
                    path: folder.lock_path(),
                    source,
                });
            }
        }
    }
}

/// `hand_off` with a payload, `probe` without one.
pub(crate) fn hand_off<T: Payload>(b: &Builder, payload: Option<&T>) -> Result<OwnerInfo, Reason> {
    hand_off_at(b, payload, sys::level())
}

/// `hand_off` for a launch at integrity level `own`.
fn hand_off_at<T: Payload>(
    b: &Builder,
    payload: Option<&T>,
    own: Option<Level>,
) -> Result<OwnerInfo, Reason> {
    if !sys::SUPPORTED {
        return Err(Reason::Unsupported {});
    }
    let state = b.canonical_state();
    let place = b.place(state.as_deref())?;
    let key = b.instance_key(state.as_deref());
    let Some(folder) = sys::open_folder(&place, false)? else {
        return Err(Reason::NoOwner {});
    };
    let request = payload.map(|p| encode_request(b, p)).transpose()?;
    let began = Instant::now();
    let limits = Limits::new(began, b.timeout, own);
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
        let at = match meet_owner(&folder, own, request.is_none()) {
            Meet::Talk(at) => at,
            Meet::Wait => {
                waiting = Some(Waiting::Unresponsive.after(waiting, deadline));
                pause(deadline);
                continue;
            }
            Meet::Report(answer) => return answer,
        };
        match exchange(&folder, b, &key, request.as_deref(), &limits, None, at) {
            Exchange::Taken(info) | Exchange::Unconfirmed(info) => return Ok(info),
            Exchange::Fail(reason) => return Err(reason),
            Exchange::Retry(w) => waiting = Some(w.after(waiting, deadline)),
            Exchange::SameOwner => unreachable!("no commit to compare with"),
            Exchange::Lost(nonce) => {
                let bytes = request.as_deref().expect("only a request commits");
                return match after_commit(&folder, b, &key, bytes, nonce, None, &limits) {
                    AfterCommit::Info(info) => Ok(info),
                    AfterCommit::Own(..) => unreachable!("a handoff never owns"),
                };
            }
        }
        pause(deadline);
    }
}

enum AfterCommit {
    Own(sys::Lock, Option<sys::Guard>),
    Info(OwnerInfo),
}

/// The connection closed after this launch committed, with no reply. The
/// owner may have died with the request or without it; this launch must
/// not run alone on it. It takes the lock, and the canonical state folder
/// and its guard, if nobody holds them and it may own (`owns` is
/// `Some(state)`; `None` for `hand_off`), or hands the request to
/// the next owner, one with another nonce. Otherwise (no owner in time, one
/// that won't take it or is at another level, or a state folder it can't
/// make or whose guard another process holds) it is handed off,
/// unconfirmed: the dead owner may have had it.
fn after_commit(
    folder: &sys::Folder,
    b: &Builder,
    key: &[u8],
    bytes: &[u8],
    mut nonce: u64,
    owns: Option<Option<&Path>>,
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
        if let Some(state) = owns {
            match folder.lock() {
                // With a guard it can't take, the lock is dropped here.
                Ok(Some(lock)) => {
                    return match take_state(b, state) {
                        Ok(guard) => AfterCommit::Own(lock, guard),
                        Err(_) => AfterCommit::Info(unconfirmed),
                    };
                }
                Ok(None) => {}
                Err(_) => return AfterCommit::Info(unconfirmed),
            }
        } else if !folder.lock_held().unwrap_or(true) {
            return AfterCommit::Info(unconfirmed);
        }
        let at = match meet_after_commit(meet_owner(folder, limits.level, false), past(until)) {
            Some(Meet::Talk(at)) => at,
            Some(Meet::Wait) => {
                pause(until);
                continue;
            }
            Some(Meet::Report(_)) | None => return AfterCommit::Info(unconfirmed),
        };
        match exchange(folder, b, key, Some(bytes), &inner, Some(nonce), at) {
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

/// Whether `hello` comes from an owner of `app_id` and of this launch's
/// state folder and scope (`key`, as [`Builder::instance_key`] makes it):
/// the same id, kind and STATE. The two kinds of an id share its folder,
/// and so do two keys whose hashes collide, so such an owner is another
/// app.
fn same_app(hello: &Hello, app_id: &AppId, key: &[u8]) -> bool {
    hello.app_id == app_id.as_str()
        && hello.app_kind == wire::app_kind(app_id.kind())
        && hello.state == key
}

/// One connection: HELLO, checks, REQUEST, READY, COMMIT, REPLY. Without a
/// request (a probe), it ends after HELLO. `key` is this launch's instance
/// key, which HELLO's STATE must match. `committed_to` is the nonce of an
/// owner this launch already committed to. `at` is the level the owner's
/// pipe must be labelled at: see [`Meet::Talk`].
fn exchange(
    folder: &sys::Folder,
    b: &Builder,
    key: &[u8],
    request: Option<&[u8]>,
    limits: &Limits,
    committed_to: Option<u64>,
    at: Option<Level>,
) -> Exchange {
    let deadline = limits.deadline;
    let own = limits.level;
    let mut conn = match folder.connect(deadline, at) {
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
    let hello = match reader.frame(&mut conn, wire::hello_limit(key), deadline) {
        Ok((wire::HELLO, body)) => match Hello::decode(&body) {
            Ok(hello) => hello,
            Err(_) => return Exchange::Fail(not_ours()),
        },
        // Refused in place of HELLO: a Unix owner that won't serve this
        // launch's user.
        Ok((wire::REPLY, body)) => {
            return Exchange::Fail(match Reply::decode(&body) {
                Ok(r) if !r.delivered && r.status == status::REFUSED => {
                    refused(&r, None, b, &[], own)
                }
                _ => not_ours(),
            });
        }
        Ok(_) | Err(ReadError::Bad) => return Exchange::Fail(not_ours()),
        Err(ReadError::Closed | ReadError::TimedOut) => {
            return Exchange::Retry(Waiting::Unresponsive);
        }
    };
    if !same_app(&hello, &b.app_id, key) {
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
    // A request goes neither up nor down, so at another level this launch
    // decides at once, whether or not the owner serves, and sends nothing.
    // Where either level is unknown, as on Unix, it goes on.
    let theirs = hello.level.map(Level::from_rid);
    match own
        .zip(theirs)
        .and_then(|(own, theirs)| rights(own, theirs, request.is_none()))
    {
        Some(Ok(info)) => return Exchange::Taken(info),
        Some(Err(reason)) => return Exchange::Fail(reason),
        None => {}
    }
    if committed_to == Some(hello.nonce) {
        return Exchange::SameOwner;
    }
    match hello.serving {
        serving::TAKING => {}
        serving::DECLINING => return Exchange::Fail(Reason::Declined {}),
        // Busy, and values this build doesn't know: a later release that
        // wants old launches to send their request advertises TAKING and
        // lets its REPLY decide.
        _ => return Exchange::Retry(Waiting::Busy),
    }
    let info = OwnerInfo {
        pid: conn.peer_pid(),
        confirmed: true,
        level: hello.level.map(crate::Level::from_rid),
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
        Ok((wire::REPLY, body)) => return reply(&body, &hello, b, request, own, info, false),
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
        Ok((wire::REPLY, body)) => reply(&body, &hello, b, request, own, info, true),
        Err(ReadError::Closed) => Exchange::Lost(hello.nonce),
        Ok(_) | Err(ReadError::Bad | ReadError::TimedOut) => Exchange::Unconfirmed(unconfirmed),
    }
}

/// The owner's REPLY to `request`. `own` is this launch's level.
fn reply(
    body: &[u8],
    hello: &Hello,
    b: &Builder,
    request: &[u8],
    own: Option<Level>,
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
        status::REFUSED => Exchange::Fail(refused(&r, Some(hello), b, request, own)),
        status::GAVE_UP => Exchange::Retry(Waiting::Unresponsive),
        // Busy, and statuses this build doesn't know: not delivered.
        _ => Exchange::Retry(Waiting::Busy),
    }
}

/// Why the owner refused this launch. `hello` is `None` when the refusal
/// came in place of HELLO, before this launch sent anything. `own` is this
/// launch's level.
fn refused(
    r: &Reply,
    hello: Option<&Hello>,
    b: &Builder,
    request: &[u8],
    own: Option<Level>,
) -> Reason {
    let wire_version = Reason::WireVersion {
        ours: u32::from(wire::WIRE_MAX),
        theirs: hello.map_or(0, |h| u32::from(h.wire_max)),
    };
    match (r.refusal, hello) {
        (Some(refusal::PEER), _) => Reason::Peer {
            source: io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the owner refused this launch: another user, or a check that failed",
            ),
        },
        (Some(refusal::APP), _) => Reason::OtherApp {},
        // The owner names its level with the refusal. Without one, or
        // with this launch's own, the rights can't be named: a cause this
        // build doesn't know.
        (Some(refusal::PRIVILEGE), _) => own
            .zip(r.level.map(Level::from_rid))
            .and_then(|(own, theirs)| rights(own, theirs, false)?.err())
            .unwrap_or(Reason::Declined {}),
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

    const KNOWN: [u8; 9] = [
        WIRE,
        APP,
        PAYLOAD_VERSION,
        UNDECODABLE,
        TOO_LARGE,
        MALFORMED,
        UNSUPPORTED,
        PRIVILEGE,
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
            serving: serving::TAKING,
            level: None,
            state: Vec::new(),
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
        refused(&reply, hello, &b, &[0; 200], None)
    }

    /// How a launch fares with an owner, by their levels: it has more
    /// rights, the owner has, or neither is known to.
    #[derive(Debug, Clone, Copy, PartialEq)]
    enum Apart {
        Neither,
        More,
        Fewer,
    }

    /// A launch's level, its owner's, and how the launch fares.
    type Row = (Option<Level>, Option<Level>, Apart);

    const LEVELS: [Row; 9] = [
        (None, None, Apart::Neither),
        (None, Some(Level::HIGH), Apart::Neither),
        (Some(Level::MEDIUM), None, Apart::Neither),
        (Some(Level::MEDIUM), Some(Level::MEDIUM), Apart::Neither),
        (Some(Level::HIGH), Some(Level::HIGH), Apart::Neither),
        (Some(Level::HIGH), Some(Level::MEDIUM), Apart::More),
        (Some(Level::MEDIUM), Some(Level::LOW), Apart::More),
        (Some(Level::MEDIUM), Some(Level::HIGH), Apart::Fewer),
        (Some(Level::LOW), Some(Level::UI_ACCESS), Apart::Fewer),
    ];

    /// Whether `reason` is what a launch gets as `row` says, naming the
    /// owner by its level alone, unconfirmed and with no pid.
    fn fares(reason: &Reason, (own, theirs, apart): Row) -> bool {
        let named = |owner: &OwnerInfo, rights: &Rights| {
            let levels = own
                .zip(theirs)
                .map(|(launch, owner)| Rights::Level { launch, owner });
            (owner.pid, owner.confirmed, owner.level) == (None, false, theirs)
                && levels.as_ref() == Some(rights)
        };
        match (reason, apart) {
            (Reason::MoreRights { owner, rights }, Apart::More)
            | (Reason::OwnerHasMoreRights { owner, rights }, Apart::Fewer) => named(owner, rights),
            _ => false,
        }
    }

    // At another level, a launch decides from HELLO with `rights`, as it
    // does from the marker, and sends nothing. With the higher level it
    // has rights the owner lacks; with the lower, the owner has rights it
    // lacks. A probe finds the owner, unconfirmed: it won't serve this
    // launch. Where a level is unknown, as on Unix, the launch goes on.
    #[test]
    fn a_launch_at_another_level_decides_from_hello() {
        for row in LEVELS {
            let (own, theirs, apart) = row;
            // As `exchange` reads HELLO's LEVEL.
            let decide = |probe| {
                own.zip(theirs)
                    .and_then(|(own, theirs)| rights(own, theirs, probe))
            };
            let handoff = decide(false);
            let probe = decide(true);
            if apart == Apart::Neither {
                assert!(handoff.is_none() && probe.is_none(), "{row:?}");
                continue;
            }
            match handoff {
                Some(Err(reason)) => assert!(fares(&reason, row), "{row:?}: {reason:?}"),
                other => panic!("{row:?}: {other:?}"),
            }
            match probe {
                Some(Ok(found)) => assert_eq!(
                    (found.pid, found.confirmed, found.level),
                    (None, false, theirs)
                ),
                other => panic!("{row:?}: {other:?}"),
            }
        }
    }

    // PRIVILEGE comes with the owner's level, which the launch compares
    // with its own, after HELLO or in place of it. Without a level to
    // compare, or with its own, it can't name the rights, and reads the
    // cause as one it doesn't know.
    #[test]
    fn a_privilege_refusal_names_the_rights_from_the_owners_level() {
        let hello = hello();
        let b = Builder::new(AppId::headless("test"), crate::State::none());
        for row in LEVELS {
            let (own, theirs, apart) = row;
            let reply = Reply {
                refusal: Some(PRIVILEGE),
                level: theirs.map(Level::rid),
                ..Reply::new(false, status::REFUSED)
            };
            for hello in [Some(&hello), None] {
                let reason = refused(&reply, hello, &b, &[], own);
                if apart == Apart::Neither {
                    assert!(matches!(reason, Reason::Declined {}), "{row:?}: {reason}");
                } else {
                    assert!(fares(&reason, row), "{row:?}: {reason:?}");
                }
            }
        }
    }

    // A busy owner that names a level in HELLO, to launches at other
    // levels: each decides from HELLO alone, before it looks at whether the
    // owner serves, and sends nothing. `hand_off` fails at once, and a
    // probe finds the owner, unconfirmed, with no pid, though the
    // connection gives one. Owners on Unix name no level and launches there
    // have none, so the test plays a high owner and sets the launch's level.
    #[cfg(unix)]
    #[test]
    fn a_launch_at_another_level_sends_nothing_whether_or_not_the_owner_serves() {
        use std::io::{Read, Write};
        let tmp = tempfile::tempdir().unwrap();
        let b = Builder::new(AppId::headless("test.levels"), crate::State::none())
            .dir(tmp.path().join("run"))
            .timeout(Duration::from_secs(3));
        let folder = sys::open_folder(&b.place(None).unwrap(), true)
            .unwrap()
            .unwrap();
        let _lock = folder.lock().unwrap().unwrap();
        let socket = b.runtime_dir().unwrap().join("instance.sock");
        let listener = std::os::unix::net::UnixListener::bind(socket).unwrap();
        let hello = Hello {
            app_id: "test.levels".into(),
            payload_version: b.payload_version,
            serving: serving::BUSY,
            level: Some(Level::HIGH.rid()),
            state: b.instance_key(None),
            ..hello()
        }
        .encode();
        let owner = std::thread::spawn(move || {
            for stream in listener.incoming().take(3) {
                let mut stream = stream.unwrap();
                stream.write_all(&hello).unwrap();
                let mut got = Vec::new();
                stream.read_to_end(&mut got).unwrap();
                assert!(got.is_empty(), "the launch sent {got:?}");
            }
        });
        let payload = crate::Args::new(["x"]);
        let at = |launch, owner| Rights::Level { launch, owner };
        let t = Instant::now();
        match hand_off_at(&b, Some(&payload), Some(Level::MEDIUM)) {
            Err(Reason::OwnerHasMoreRights { owner, rights }) => {
                assert_eq!(rights, at(Level::MEDIUM, Level::HIGH));
                assert_eq!(owner.to_string(), "pid unknown, high");
                assert!(!owner.confirmed());
            }
            other => panic!("{other:?}"),
        }
        match hand_off_at(&b, Some(&payload), Some(Level::SYSTEM)) {
            Err(Reason::MoreRights { rights, .. }) => {
                assert_eq!(rights, at(Level::SYSTEM, Level::HIGH));
            }
            other => panic!("{other:?}"),
        }
        let found = hand_off_at::<()>(&b, None, Some(Level::MEDIUM)).unwrap();
        assert_eq!(
            (found.pid(), found.confirmed(), found.level()),
            (None, false, Some(Level::HIGH))
        );
        assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
        owner.join().unwrap();
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
            assert!(same_app(&owner, &app(kind), &[]), "{kind:?}");
            assert!(!same_app(&owner, &app(other), &[]), "{kind:?}");
        }
        owner.app_kind = 2;
        assert!(!same_app(&owner, &app(Kind::Windowed), &[]));
        assert!(!same_app(&owner, &app(Kind::Headless), &[]));
        assert!(!same_app(&hello(), &AppId::headless("other"), &[]));
    }

    // Two state folders or scopes whose instance folders share a name, as
    // a hash collision would make them: the owner of one is another app to
    // a launch of the other. STATE is compared byte for byte.
    #[test]
    fn an_owner_of_another_state_is_another_app() {
        use std::path::Path;
        let app = AppId::headless("test");
        let b = Builder::new(app.clone(), crate::State::none());
        let key = b.instance_key(Some(Path::new("/a")));
        let owner = Hello {
            state: key.clone(),
            ..hello()
        };
        assert!(same_app(&owner, &app, &key));
        for other in [
            b.instance_key(None),
            b.instance_key(Some(Path::new("/b"))),
            b.instance_key(Some(Path::new("/a/"))),
            b.clone().scope("").instance_key(Some(Path::new("/a"))),
            b.clone().scope("/a").instance_key(None),
            key[..key.len() - 1].to_vec(),
            [&key[..], b"\0"].concat(),
        ] {
            assert!(!same_app(&owner, &app, &other), "{other:?}");
        }
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
        // An exclusive run serves no launches, so only its rights count,
        // whatever the app's kind and its windows.
        for ((policy, raised, above), why) in rows {
            assert_eq!(
                ineligible_rights(policy, raised, above),
                why,
                "{policy:?} {raised} {above}"
            );
        }
    }

    // What a launch does about the owner, by the level the owner's marker
    // shows, before it connects. A launch answers an owner at another
    // level at once, from its marker: start and hand_off are refused, a
    // probe is told it runs, unconfirmed, and a committed launch whose
    // owner died is handed off, unconfirmed. Nothing is sent. On Windows,
    // an_owner_at_another_level_is_answered_at_once tries each call
    // against owners forged below and above.
    #[test]
    fn a_launch_meets_the_owner_by_its_marker() {
        use OwnerLevel::*;
        /// What a meeting comes to. An answer at once names the owner's
        /// level, from its marker.
        #[derive(Debug, PartialEq)]
        enum Is {
            Talk(Option<Level>),
            Wait,
            Runs(Option<Level>),
            MoreRights(Option<Level>, Rights),
            OwnerHasMoreRights(Option<Level>, Rights),
            /// After a commit: handed off, unconfirmed.
            Unconfirmed,
        }
        let is = |met: Meet| {
            let (info, is) = match met {
                Meet::Talk(at) => return Is::Talk(at),
                Meet::Wait => return Is::Wait,
                Meet::Report(Ok(info)) => (info.clone(), Is::Runs(info.level())),
                Meet::Report(Err(Reason::MoreRights { owner, rights })) => {
                    let is = Is::MoreRights(owner.level(), rights);
                    (owner, is)
                }
                Meet::Report(Err(Reason::OwnerHasMoreRights { owner, rights })) => {
                    let is = Is::OwnerHasMoreRights(owner.level(), rights);
                    (owner, is)
                }
                Meet::Report(Err(other)) => panic!("{other}"),
            };
            // Nobody talked to the owner.
            assert_eq!((info.pid(), info.confirmed()), (None, false));
            assert!(info.handed_down().is_none());
            is
        };
        let (low, medium, high) = (Some(Level::LOW), Some(Level::MEDIUM), Some(Level::HIGH));
        let rights = |owner: Option<Level>| Rights::Level {
            launch: Level::MEDIUM,
            owner: owner.unwrap(),
        };
        let talk = |at| [Is::Talk(at), Is::Talk(at), Is::Talk(at), Is::Talk(at)];
        let wait = || [Is::Wait, Is::Wait, Is::Wait, Is::Unconfirmed];
        let rows = [
            // (launch, owner): start and hand_off, probe, then a committed
            // launch whose owner died, before its wait is past and after.
            ((medium, Same), talk(medium)),
            ((None, Same), talk(None)),
            // Never found: owner_level gives Same for the launch's own
            // level's marker.
            ((medium, Other(Level::MEDIUM)), talk(medium)),
            (
                (medium, Other(Level::HIGH)),
                [
                    Is::OwnerHasMoreRights(high, rights(high)),
                    Is::Runs(high),
                    Is::Unconfirmed,
                    Is::Unconfirmed,
                ],
            ),
            (
                (medium, Other(Level::LOW)),
                [
                    Is::MoreRights(low, rights(low)),
                    Is::Runs(low),
                    Is::Unconfirmed,
                    Is::Unconfirmed,
                ],
            ),
            ((medium, Starting), wait()),
            ((None, Starting), wait()),
            // A launch that doesn't know its own level can't compare, so
            // it fails closed: `None` matches no pipe's label.
            ((None, Other(Level::HIGH)), talk(None)),
        ];
        for ((own, owner), [hand_off, probe, committed, past]) in rows {
            let after = |is_past| {
                meet_after_commit(meet(own, owner, false), is_past).map_or(Is::Unconfirmed, is)
            };
            assert_eq!(is(meet(own, owner, false)), hand_off, "{own:?} {owner:?}");
            assert_eq!(is(meet(own, owner, true)), probe, "{own:?} {owner:?}");
            assert_eq!(after(false), committed, "{own:?} {owner:?}");
            assert_eq!(after(true), past, "{own:?} {owner:?}");
        }
    }

    // A launch told it may not own never takes the lock or makes the
    // folder. It hands off to an owner that is running, and otherwise runs
    // alone. An exclusive run told so fails at once, beside an owner or
    // not, and makes nothing either.
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
        let state = tmp.path().join("state");
        let held = Builder::new(AppId::headless("test.gate"), state.as_path()).dir(&run);
        for b in [&b, &held] {
            match exclusive_as(b, raised) {
                Err(Reason::MayNotOwn { why }) => assert_eq!(why, Ineligible::Raised),
                other => panic!("expected MayNotOwn: {other:?}"),
            }
        }
        assert!(!run.exists() && !state.exists());

        let (tx, rx) = std::sync::mpsc::channel();
        let owner = own(start_as(&b, &Args::default(), None)).serve(move |r| tx.send(r).is_ok());
        let sent = Args::new(["raised"]);
        match start_as(&b, &sent, raised) {
            Started::HandedOff(info) => assert!(info.confirmed()),
            other => panic!("expected to hand off: {other:?}"),
        }
        let got = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(got.payload(), &sent);
        // An exclusive run never hands off.
        assert!(matches!(
            exclusive_as(&b, raised),
            Err(Reason::MayNotOwn { .. })
        ));

        // The folder stays, with nobody holding its lock.
        owner.release();
        may_not_own(start_as(&b, &Args::default(), raised));
        own(start_as(&b, &Args::default(), None)).release();
    }

    // The owner this launch committed to died, and another process holds
    // the guard: the dead owner may have had the request, so the launch
    // reports it handed off, never alone, and lets go of the lock it took
    // (0004). With the guard free, it owns.
    #[cfg(any(unix, windows))]
    #[test]
    fn a_committed_launch_that_finds_the_guard_held_is_handed_off_unconfirmed() {
        let tmp = tempfile::tempdir().unwrap();
        let b = Builder::new(AppId::headless("test.guard"), tmp.path().join("state"))
            .dir(tmp.path().join("run"));
        let state = b.canonical_state();
        let place = b.place(state.as_deref()).unwrap();
        let folder = sys::open_folder(&place, true).unwrap().unwrap();
        let limits = Limits::new(Instant::now(), Duration::from_secs(1), None);
        let key = b.instance_key(state.as_deref());
        let after = || after_commit(&folder, &b, &key, &[], 1, Some(state.as_deref()), &limits);

        let other = take_state(&b, state.as_deref()).unwrap();
        assert!(other.is_some());
        match after() {
            AfterCommit::Info(info) => assert!(!info.confirmed()),
            AfterCommit::Own(..) => panic!("owned beside a guard another process holds"),
        }
        assert!(!folder.lock_held().unwrap());

        drop(other);
        match after() {
            AfterCommit::Own(_, guard) => assert!(guard.is_some()),
            AfterCommit::Info(info) => panic!("handed off to {info}"),
        }
    }

    // An owner at another level, as its marker shows it, is answered at
    // once: start and hand_off are refused, a probe is told it runs,
    // unconfirmed, and a committed launch whose owner died is handed off
    // unconfirmed, never alone (0004). Each level still locks in its own
    // folder, so the owner is forged: a handle that holds byte 0 and
    // another level's marker.
    #[cfg(windows)]
    #[test]
    fn an_owner_at_another_level_is_answered_at_once() {
        use crate::Args;
        let tmp = tempfile::tempdir().unwrap();
        let b = Builder::new(AppId::headless("test.marker"), crate::State::none())
            .dir(tmp.path().join("run"))
            .timeout(Duration::from_secs(5));
        let folder = sys::open_folder(&b.place(None).unwrap(), true)
            .unwrap()
            .unwrap();
        let key = b.instance_key(None);
        let own = sys::level().unwrap();
        // Below and above high and medium, where the tests run.
        for owner in [Level::LOW, Level::SYSTEM] {
            let _held = folder.lock_at(owner.rid()).unwrap().unwrap();
            let began = Instant::now();
            let rights = Rights::Level { launch: own, owner };
            let refused = |reason: Reason| match reason {
                Reason::MoreRights {
                    owner: info,
                    rights: r,
                } if owner < own => (info, r),
                Reason::OwnerHasMoreRights {
                    owner: info,
                    rights: r,
                } if owner > own => (info, r),
                other => panic!("{owner}: {other}"),
            };
            let unconfirmed = |info: &OwnerInfo| {
                assert_eq!(info.pid(), None, "{owner}");
                assert_eq!(info.level(), Some(owner), "{owner}");
                assert!(!info.confirmed(), "{owner}");
            };

            let started = match start_as(&b, &Args::default(), None) {
                Started::Alone(reason) => reason,
                other => panic!("{owner}: {other:?}"),
            };
            for reason in [started, b.hand_off(&Args::default()).unwrap_err()] {
                let (info, r) = refused(reason);
                assert_eq!(r, rights);
                unconfirmed(&info);
            }
            unconfirmed(&b.probe().unwrap());
            let limits = Limits::new(Instant::now(), b.timeout, Some(own));
            match after_commit(&folder, &b, &key, &[], 1, Some(None), &limits) {
                AfterCommit::Info(info) => assert!(!info.confirmed()),
                AfterCommit::Own(..) => panic!("owned beside an owner at {owner}"),
            }
            assert!(began.elapsed() < Duration::from_secs(1), "{owner}");
        }
    }

    // Byte 0 held with no marker is an owner still starting. Each call
    // looks again until its deadline and then gives Unresponsive, and a
    // committed launch whose owner died is handed off unconfirmed, never
    // alone (0004).
    #[cfg(windows)]
    #[test]
    fn an_owner_still_starting_is_waited_for_until_the_deadline() {
        use crate::Args;
        let tmp = tempfile::tempdir().unwrap();
        let timeout = Duration::from_millis(100);
        let b = Builder::new(AppId::headless("test.starting"), crate::State::none())
            .dir(tmp.path().join("run"))
            .timeout(timeout);
        let folder = sys::open_folder(&b.place(None).unwrap(), true)
            .unwrap()
            .unwrap();
        let key = b.instance_key(None);
        let _held = folder.lock_starting().unwrap().unwrap();
        let unresponsive = |reason: Reason| match reason {
            Reason::Unresponsive { waited } => assert!(waited >= timeout, "{waited:?}"),
            other => panic!("{other}"),
        };

        match start_as(&b, &Args::default(), None) {
            Started::Alone(reason) => unresponsive(reason),
            other => panic!("{other:?}"),
        }
        unresponsive(b.hand_off(&Args::default()).unwrap_err());
        unresponsive(b.probe().unwrap_err());
        let limits = Limits::new(Instant::now(), timeout, sys::level());
        match after_commit(&folder, &b, &key, &[], 1, Some(None), &limits) {
            AfterCommit::Info(info) => assert_eq!(
                (info.pid(), info.level(), info.confirmed()),
                (None, None, false)
            ),
            AfterCommit::Own(..) => panic!("owned beside an owner still starting"),
        }
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
