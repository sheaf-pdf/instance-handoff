//! The owner's side of the exchange, apart from any I/O: [`Session`] is one
//! connection's state machine, and [`Core`] is the handler and the owner's
//! state, shared by every connection on the crate's one thread. Each
//! platform's event loop feeds them bytes and writes out what they produce.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::wire::{self, Hello, Reply, refusal, state, status};
use crate::{Activation, Answer, AppId, End, Payload, Request, sys};

/// From accepting a connection to reading its REQUEST.
pub(crate) const REQUEST_WAIT: Duration = Duration::from_secs(2);
/// From sending READY to reading COMMIT. Long: a launch commits at once
/// unless it was stopped, and giving up early only costs that launch.
pub(crate) const COMMIT_WAIT: Duration = Duration::from_secs(10);
/// How long the owner waits for a launch to close after the last REPLY.
pub(crate) const DRAIN_WAIT: Duration = Duration::from_secs(1);

pub(crate) type Handler<T> = Box<dyn FnMut(Request<T>) -> Answer + Send>;
pub(crate) type OnEnd = Box<dyn FnOnce(End) + Send>;

/// How often the owner checks its lock is still in place, and touches its
/// files so that cleaners that go by age leave them alone.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Upkeep {
    pub(crate) check: Duration,
    // Windows has no cleaners to fend off.
    #[cfg_attr(windows, allow(dead_code))]
    pub(crate) touch: Duration,
}

impl Default for Upkeep {
    fn default() -> Upkeep {
        Upkeep {
            check: Duration::from_secs(60),
            touch: Duration::from_secs(3600),
        }
    }
}

/// What every HELLO says, and what requests are checked against.
#[derive(Debug, Clone)]
pub(crate) struct Ctx {
    pub(crate) app_id: AppId,
    pub(crate) payload_version: u32,
    pub(crate) nonce: u64,
    pub(crate) upkeep: Upkeep,
}

impl Ctx {
    fn hello(&self, state: u8) -> Vec<u8> {
        Hello {
            wire_min: wire::WIRE_MIN,
            wire_max: wire::WIRE_MAX,
            app_id: self.app_id.as_str().to_owned(),
            app_kind: wire::app_kind(self.app_id.kind()),
            nonce: self.nonce,
            payload_version: self.payload_version,
            max_request: wire::MAX_REQUEST,
            state,
            features: wire::features::REFUSALS,
        }
        .encode()
    }
}

/// What the owner's handle and its thread share.
pub(crate) struct Shared {
    /// [`Owner::stop`](crate::Owner::stop): answer busy from now on.
    pub(crate) stop: AtomicBool,
    /// The handle is gone (dropped or released): close the listener and
    /// end the thread.
    pub(crate) close: AtomicBool,
    pub(crate) ended: Mutex<Option<End>>,
    pub(crate) waker: sys::Waker,
    /// The folder and the lock. The thread's upkeep replaces them when the
    /// folder is deleted under it; `release` closes the lock.
    pub(crate) held: Mutex<sys::Held>,
}

impl Shared {
    pub(crate) fn new(held: sys::Held) -> Arc<Shared> {
        Arc::new(Shared {
            stop: AtomicBool::new(false),
            close: AtomicBool::new(false),
            ended: Mutex::new(None),
            waker: sys::Waker::new(),
            held: Mutex::new(held),
        })
    }

    pub(crate) fn ended(&self) -> Option<End> {
        *self.ended.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn held(&self) -> std::sync::MutexGuard<'_, sys::Held> {
        self.held.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Where the owner is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Serving {
    /// A handler takes requests.
    Taking,
    /// [`Claim::decline_all`](crate::Claim::decline_all), or a `Claim`
    /// dropped unserved.
    Declining,
    /// `stop` was called: launches are told busy.
    Stopped,
    /// The handler panicked: launches are turned away.
    Panicked,
}

/// The handler and the owner's state, on the crate's thread.
pub(crate) struct Core<T> {
    handler: Option<Handler<T>>,
    serving: Serving,
    on_end: Option<OnEnd>,
    pub(crate) shared: Arc<Shared>,
    pub(crate) ctx: Ctx,
}

impl<T: Payload> Core<T> {
    pub(crate) fn new(
        handler: Option<Handler<T>>,
        on_end: Option<OnEnd>,
        shared: Arc<Shared>,
        ctx: Ctx,
    ) -> Core<T> {
        Core {
            serving: if handler.is_some() {
                Serving::Taking
            } else {
                Serving::Declining
            },
            handler,
            on_end,
            shared,
            ctx,
        }
    }

    /// The state later launches are told. A stop counts from the moment
    /// it's asked for, not from the next [`Core::poll_control`]: an accept
    /// pass that began before the stop still tells later connections busy.
    pub(crate) fn state(&self) -> u8 {
        match self.serving {
            Serving::Taking | Serving::Declining if self.shared.stop.load(Ordering::SeqCst) => {
                state::BUSY
            }
            Serving::Taking => state::TAKING,
            Serving::Stopped => state::BUSY,
            Serving::Declining | Serving::Panicked => state::DECLINING,
        }
    }

    /// Acts on the handle's requests. `false` once the thread should end.
    pub(crate) fn poll_control(&mut self) -> bool {
        if self.shared.close.load(Ordering::SeqCst) {
            self.end(End::Stopped);
            return false;
        }
        if self.shared.stop.load(Ordering::SeqCst)
            && matches!(self.serving, Serving::Taking | Serving::Declining)
        {
            self.serving = Serving::Stopped;
            self.end(End::Stopped);
        }
        true
    }

    /// Hands a committed request to the handler, one call at a time. `None`
    /// when the handler panicked while it held the request: it may or may
    /// not have taken it.
    pub(crate) fn deliver(&mut self, request: Request<T>) -> Option<Answer> {
        // A stop or release made since this pass began: no call starts after
        // it returned.
        if !self.poll_control() {
            return Some(Answer::Busy);
        }
        match self.serving {
            Serving::Taking => {}
            Serving::Stopped => return Some(Answer::Busy),
            Serving::Declining | Serving::Panicked => return Some(Answer::Decline),
        }
        let handler = self.handler.as_mut()?;
        match catch_unwind(AssertUnwindSafe(|| handler(request))) {
            Ok(answer) => Some(answer),
            Err(_) => {
                log::error!(
                    "instance-handoff {}: the handler panicked; turning launches away",
                    self.ctx.app_id
                );
                self.serving = Serving::Panicked;
                self.end(End::Panicked);
                None
            }
        }
    }

    /// Ends serving: records why, drops the handler (closing whatever it
    /// fed), then tells `on_end`, once. The first reason is kept, except
    /// that a lost lock replaces it: an app that stopped must still learn
    /// that it no longer owns the state.
    pub(crate) fn end(&mut self, why: End) {
        {
            let mut ended = self.shared.ended.lock().unwrap_or_else(|e| e.into_inner());
            if ended.is_none() || why == End::LostLock {
                *ended = Some(why);
            }
        }
        if let Some(handler) = self.handler.take() {
            if catch_unwind(AssertUnwindSafe(move || drop(handler))).is_err() {
                log::error!(
                    "instance-handoff {}: dropping the handler panicked",
                    self.ctx.app_id
                );
            }
        }
        if let Some(on_end) = self.on_end.take() {
            let why = self.shared.ended().unwrap_or(why);
            if catch_unwind(AssertUnwindSafe(move || on_end(why))).is_err() {
                log::error!("instance-handoff {}: on_end panicked", self.ctx.app_id);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// HELLO sent (or going out); waiting for REQUEST.
    Request,
    /// READY sent; waiting for COMMIT.
    Commit,
    /// The last message is going out; then the write side closes and the
    /// launch's EOF is awaited.
    Drain,
    Done,
}

/// One connection, from HELLO, or a refusal sent in its place, to the
/// launch's close.
pub(crate) struct Session<T> {
    phase: Phase,
    inbuf: Vec<u8>,
    out: Vec<u8>,
    sent: usize,
    deadline: Instant,
    pending: Option<Request<T>>,
    launcher_pid: Option<u32>,
}

impl<T: Payload> Session<T> {
    /// A new connection: HELLO goes out at once.
    pub(crate) fn new(core: &Core<T>, launcher_pid: Option<u32>, now: Instant) -> Session<T> {
        Session {
            phase: Phase::Request,
            inbuf: Vec::new(),
            out: core.ctx.hello(core.state()),
            sent: 0,
            deadline: now + REQUEST_WAIT,
            pending: None,
            launcher_pid,
        }
    }

    /// A connection refused before HELLO: REPLY REFUSED with `why` is all
    /// it is told.
    #[cfg_attr(windows, allow(dead_code))]
    pub(crate) fn refused(why: u8, now: Instant) -> Session<T> {
        let mut s = Session {
            phase: Phase::Request,
            inbuf: Vec::new(),
            out: Vec::new(),
            sent: 0,
            deadline: now,
            pending: None,
            launcher_pid: None,
        };
        s.reply(Reply::refused(why), now);
        s
    }

    /// Bytes waiting to be written.
    pub(crate) fn outgoing(&self) -> &[u8] {
        &self.out[self.sent..]
    }

    pub(crate) fn wrote(&mut self, n: usize) {
        self.sent += n;
        if self.sent == self.out.len() {
            self.out.clear();
            self.sent = 0;
        }
    }

    /// The final message is out: time to close the write side. (A pipe has
    /// none to close.)
    #[cfg_attr(windows, allow(dead_code))]
    pub(crate) fn should_shut_write(&self) -> bool {
        self.phase == Phase::Drain && self.out.is_empty()
    }

    pub(crate) fn is_done(&self) -> bool {
        self.phase == Phase::Done
    }

    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }

    /// The write side broke: nothing more can be said.
    pub(crate) fn broken(&mut self) {
        self.phase = Phase::Done;
    }

    /// Refuses the launch with `why`, after HELLO and whatever it has sent
    /// since. A session whose last message is already decided is left as
    /// it is.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn refuse(&mut self, why: u8, now: Instant) {
        if matches!(self.phase, Phase::Request | Phase::Commit) {
            self.reply(Reply::refused(why), now);
        }
    }

    /// Bytes from the launch. Returns a committed request for the handler;
    /// pass its answer to [`Session::answer`].
    pub(crate) fn read(
        &mut self,
        bytes: &[u8],
        core: &Core<T>,
        now: Instant,
    ) -> Option<Request<T>> {
        match self.phase {
            Phase::Request | Phase::Commit => self.inbuf.extend_from_slice(bytes),
            // A launch says nothing after its REPLY; whatever comes is
            // discarded until it closes.
            Phase::Drain | Phase::Done => return None,
        }
        let limit = match self.phase {
            Phase::Request => wire::MAX_REQUEST as usize,
            _ => wire::SMALL,
        };
        let (kind, body, used) = match wire::split(&self.inbuf, limit) {
            Ok(Some(frame)) => frame,
            Ok(None) => return None,
            Err(wire::Error::TooLarge { .. }) => {
                self.reply(Reply::refused(refusal::TOO_LARGE), now);
                return None;
            }
            Err(_) => {
                self.reply(Reply::refused(refusal::MALFORMED), now);
                return None;
            }
        };
        let body = body.to_vec();
        self.inbuf.drain(..used);
        match (self.phase, kind) {
            (Phase::Request, wire::REQUEST) => {
                self.request(&body, core, now);
                None
            }
            (Phase::Commit, wire::COMMIT) => {
                if wire::check_empty(&body).is_err() {
                    self.reply(Reply::refused(refusal::MALFORMED), now);
                    return None;
                }
                let request = self.pending.take();
                if request.is_none() {
                    self.reply(Reply::refused(refusal::MALFORMED), now);
                }
                request
            }
            _ => {
                self.reply(Reply::refused(refusal::MALFORMED), now);
                None
            }
        }
    }

    fn request(&mut self, body: &[u8], core: &Core<T>, now: Instant) {
        let req = match wire::Request::decode(body) {
            Ok(req) => req,
            Err(wire::Error::Unsupported) => {
                return self.reply(Reply::refused(refusal::UNSUPPORTED), now);
            }
            Err(_) => return self.reply(Reply::refused(refusal::MALFORMED), now),
        };
        if !(wire::WIRE_MIN..=wire::WIRE_MAX).contains(&req.wire) {
            return self.reply(Reply::refused(refusal::WIRE), now);
        }
        if req.payload_version != core.ctx.payload_version {
            let mut reply = Reply::refused(refusal::PAYLOAD_VERSION);
            reply.payload_version = Some(core.ctx.payload_version);
            return self.reply(reply, now);
        }
        // The app's decoder runs on the crate's thread: a panic in it must
        // not take the thread down.
        let payload = match catch_unwind(AssertUnwindSafe(|| T::decode(&req.payload))) {
            Ok(Ok(payload)) => payload,
            Ok(Err(e)) => {
                log::warn!(
                    "instance-handoff {}: a launch's payload doesn't decode: {e}",
                    core.ctx.app_id
                );
                return self.reply(Reply::refused(refusal::UNDECODABLE), now);
            }
            Err(_) => {
                log::error!(
                    "instance-handoff {}: Payload::decode panicked on a launch's payload",
                    core.ctx.app_id
                );
                return self.reply(Reply::refused(refusal::UNDECODABLE), now);
            }
        };
        match core.state() {
            state::TAKING => {}
            state::DECLINING => return self.reply(Reply::new(false, status::DECLINED), now),
            _ => return self.reply(Reply::new(false, status::BUSY), now),
        }
        let cwd = req
            .cwd
            .as_deref()
            .and_then(|b| wire::os_from_bytes(b).ok())
            .map(PathBuf::from);
        let activation = Activation::from_parts(req.xdg_activation_token, req.startup_id);
        self.pending = Some(Request::remote(payload, cwd, activation, self.launcher_pid));
        self.out.extend_from_slice(&wire::empty(wire::READY));
        self.phase = Phase::Commit;
        self.deadline = now + COMMIT_WAIT;
    }

    /// The handler's answer to the request [`Session::read`] returned.
    pub(crate) fn answer(&mut self, answer: Answer, now: Instant) {
        let reply = match answer {
            Answer::Take => Reply::new(true, status::TAKEN),
            Answer::Decline => Reply::new(false, status::DECLINED),
            _ => Reply::new(false, status::BUSY),
        };
        self.reply(reply, now);
    }

    /// The handler panicked holding the request: close without a reply. The
    /// launch, committed, finds this owner still there and reports an
    /// unconfirmed handoff: the request may have been taken.
    pub(crate) fn abandon(&mut self) {
        self.pending = None;
        self.out.clear();
        self.sent = 0;
        self.phase = Phase::Done;
    }

    fn reply(&mut self, reply: Reply, now: Instant) {
        self.pending = None;
        self.out.extend_from_slice(&reply.encode());
        self.phase = Phase::Drain;
        self.deadline = now + DRAIN_WAIT;
    }

    /// The launch closed.
    pub(crate) fn eof(&mut self, app_id: &AppId) {
        if self.phase == Phase::Request && self.inbuf.is_empty() {
            // A probe reads HELLO and leaves; so does a launch that found
            // the wrong app or version.
            log::debug!("instance-handoff {app_id}: a launch left after HELLO");
        }
        // A launch that leaves before COMMIT has given up: its request,
        // if any, is never delivered.
        self.pending = None;
        self.phase = Phase::Done;
    }

    /// The phase's deadline passed.
    pub(crate) fn timed_out(&mut self, now: Instant) {
        match self.phase {
            // Silent: there is nothing to answer.
            Phase::Request => self.phase = Phase::Done,
            // The launch had its chance to commit; tell it the request
            // wasn't delivered, so it may act on it itself.
            Phase::Commit => self.reply(Reply::new(false, status::GAVE_UP), now),
            Phase::Drain | Phase::Done => self.phase = Phase::Done,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Args;

    fn ctx(app_id: AppId) -> Ctx {
        Ctx {
            app_id,
            payload_version: 3,
            nonce: 7,
            upkeep: Upkeep::default(),
        }
    }

    fn core(handler: Option<Handler<Args>>) -> Core<Args> {
        let shared = Shared::new(sys::Held::detached());
        Core::new(handler, None, shared, ctx(AppId::headless("test")))
    }

    fn request(payload_version: u32, payload: Vec<u8>) -> Vec<u8> {
        wire::Request {
            wire: 1,
            payload_version,
            cwd: Some(wire::os_to_bytes("/w".as_ref())),
            payload,
            ..Default::default()
        }
        .encode()
    }

    fn frames(mut out: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut all = Vec::new();
        while let Some((kind, body, used)) = wire::split(out, wire::MAX_REQUEST as usize).unwrap() {
            all.push((kind, body.to_vec()));
            out = &out[used..];
        }
        assert!(out.is_empty());
        all
    }

    fn take_out<T: Payload>(s: &mut Session<T>) -> Vec<(u8, Vec<u8>)> {
        let out = s.outgoing().to_vec();
        s.wrote(out.len());
        frames(&out)
    }

    fn reply(frames: &[(u8, Vec<u8>)]) -> Reply {
        let (kind, body) = frames.last().unwrap();
        assert_eq!(*kind, wire::REPLY);
        Reply::decode(body).unwrap()
    }

    // Only the HELLO, with no owner behind it, so the windowed app needs
    // no display.
    #[test]
    fn hello_names_the_app_and_its_kind() {
        for (app_id, byte) in [(AppId::windowed("test"), 0), (AppId::headless("test"), 1)] {
            let hello = frames(&ctx(app_id.clone()).hello(state::TAKING));
            assert_eq!(hello[0].0, wire::HELLO);
            let hello = Hello::decode(&hello[0].1).unwrap();
            assert_eq!(hello.app_id, "test");
            assert_eq!(hello.app_kind, wire::app_kind(app_id.kind()));
            assert_eq!(hello.app_kind, byte, "{app_id:?}");
        }
    }

    #[test]
    fn a_committed_request_reaches_the_handler_once() {
        let core = core(Some(Box::new(|_| Answer::Take)));
        let now = Instant::now();
        let mut s = Session::new(&core, Some(42), now);
        let hello = take_out(&mut s);
        assert_eq!(hello[0].0, wire::HELLO);
        let hello = Hello::decode(&hello[0].1).unwrap();
        assert_eq!(hello.state, state::TAKING);
        assert_eq!(hello.features, wire::features::REFUSALS);

        let args = Args::new(["a.pdf"]);
        let bytes = request(3, args.encode().unwrap());
        // In two pieces, as a socket may deliver it.
        assert!(s.read(&bytes[..5], &core, now).is_none());
        assert!(s.read(&bytes[5..], &core, now).is_none());
        assert_eq!(take_out(&mut s)[0].0, wire::READY);

        let req = s.read(&wire::empty(wire::COMMIT), &core, now).unwrap();
        assert_eq!(req.payload(), &args);
        assert_eq!(req.cwd(), Some(std::path::Path::new("/w")));
        assert_eq!(req.launcher_pid(), Some(42));
        assert!(req.is_remote());
        s.answer(Answer::Take, now);
        let r = reply(&take_out(&mut s));
        assert!(r.delivered);
        assert!(s.should_shut_write());
        s.eof(&core.ctx.app_id);
        assert!(s.is_done());
    }

    #[test]
    fn a_launch_that_leaves_before_commit_is_never_delivered() {
        let core = core(Some(Box::new(|_| Answer::Take)));
        let now = Instant::now();
        let mut s = Session::new(&core, None, now);
        take_out(&mut s);
        s.read(&request(3, Args::default().encode().unwrap()), &core, now);
        s.eof(&core.ctx.app_id);
        assert!(s.is_done());
        assert!(s.read(&wire::empty(wire::COMMIT), &core, now).is_none());
    }

    #[test]
    fn no_commit_in_time_gets_a_gave_up_reply() {
        let core = core(Some(Box::new(|_| Answer::Take)));
        let now = Instant::now();
        let mut s = Session::new(&core, None, now);
        take_out(&mut s);
        s.read(&request(3, Args::default().encode().unwrap()), &core, now);
        take_out(&mut s);
        s.timed_out(s.deadline());
        let r = reply(&take_out(&mut s));
        assert!(!r.delivered);
        assert_eq!(r.status, status::GAVE_UP);
        // A COMMIT that arrives after that is ignored.
        assert!(s.read(&wire::empty(wire::COMMIT), &core, now).is_none());
    }

    #[test]
    fn bad_requests_are_refused_with_a_reason() {
        let core = core(Some(Box::new(|_| Answer::Take)));
        let now = Instant::now();
        let cases: [(Vec<u8>, u8); 4] = [
            (
                request(4, Args::default().encode().unwrap()),
                refusal::PAYLOAD_VERSION,
            ),
            (request(3, vec![9]), refusal::UNDECODABLE),
            (b"{\"v\":1}\n".to_vec(), refusal::MALFORMED),
            (wire::empty(wire::COMMIT), refusal::MALFORMED),
        ];
        for (bytes, why) in cases {
            let mut s = Session::new(&core, None, now);
            take_out(&mut s);
            assert!(s.read(&bytes, &core, now).is_none());
            let r = reply(&take_out(&mut s));
            assert_eq!((r.delivered, r.refusal), (false, Some(why)));
            if why == refusal::PAYLOAD_VERSION {
                assert_eq!(r.payload_version, Some(3));
            }
        }
    }

    #[test]
    fn a_refused_launch_is_told_why_and_nothing_more() {
        let core = core(Some(Box::new(|_| Answer::Take)));
        let now = Instant::now();
        let refused = |out: &[(u8, Vec<u8>)]| {
            assert_eq!(out.len(), 1, "one message");
            let r = reply(out);
            assert_eq!(
                (r.delivered, r.status, r.refusal),
                (false, status::REFUSED, Some(refusal::PEER))
            );
        };
        let bytes = request(3, Args::default().encode().unwrap());

        // Before HELLO, as on Unix: the reply is all there is, then the
        // launch's close is awaited.
        let mut s = Session::<Args>::refused(refusal::PEER, now);
        refused(&take_out(&mut s));
        assert!(s.should_shut_write());
        assert_eq!(s.deadline(), now + DRAIN_WAIT);
        assert!(s.read(&bytes, &core, now).is_none());
        s.refuse(refusal::PEER, now);
        assert!(s.outgoing().is_empty());
        s.eof(&core.ctx.app_id);
        assert!(s.is_done());

        // After HELLO, as on Windows, which checks a launch only once it
        // has read from it. A second refusal adds nothing.
        let mut s = Session::new(&core, None, now);
        assert_eq!(take_out(&mut s)[0].0, wire::HELLO);
        s.refuse(refusal::PEER, now);
        s.refuse(refusal::PEER, now);
        assert!(s.read(&bytes, &core, now).is_none());
        refused(&take_out(&mut s));
        s.timed_out(s.deadline());
        assert!(s.is_done());
    }

    #[test]
    fn a_stopped_owner_says_busy_and_a_declining_one_declines() {
        let mut c = core(Some(Box::new(|_| Answer::Take)));
        c.shared.stop.store(true, Ordering::SeqCst);
        assert!(c.poll_control());
        assert_eq!(c.shared.ended(), Some(End::Stopped));
        let now = Instant::now();
        let mut s = Session::new(&c, None, now);
        let hello = take_out(&mut s);
        assert_eq!(Hello::decode(&hello[0].1).unwrap().state, state::BUSY);
        s.read(&request(3, Args::default().encode().unwrap()), &c, now);
        assert_eq!(reply(&take_out(&mut s)).status, status::BUSY);

        let declining = core(None);
        let mut s = Session::new(&declining, None, now);
        let hello = take_out(&mut s);
        assert_eq!(Hello::decode(&hello[0].1).unwrap().state, state::DECLINING);
        assert_eq!(declining.shared.ended(), None);
    }

    #[test]
    fn a_panicking_handler_ends_the_owner_and_declines() {
        let ended = Arc::new(Mutex::new(None));
        let seen = ended.clone();
        let mut c = core(Some(Box::new(|_| panic!("boom"))));
        c.on_end = Some(Box::new(move |why| *seen.lock().unwrap() = Some(why)));
        assert_eq!(c.deliver(Request::local(Args::default())), None);
        assert_eq!(c.shared.ended(), Some(End::Panicked));
        assert_eq!(*ended.lock().unwrap(), Some(End::Panicked));
        assert_eq!(c.state(), state::DECLINING);
        // Later launches are turned away without reaching the handler.
        assert_eq!(
            c.deliver(Request::local(Args::default())),
            Some(Answer::Decline)
        );
    }

    #[test]
    fn a_panicking_decoder_refuses_the_launch_and_keeps_serving() {
        struct Fragile;
        impl Payload for Fragile {
            fn encode(&self) -> Result<Vec<u8>, crate::BoxError> {
                Ok(Vec::new())
            }
            fn decode(_: &[u8]) -> Result<Fragile, crate::BoxError> {
                panic!("bad bytes")
            }
        }
        let shared = Shared::new(sys::Held::detached());
        let core = Core::<Fragile>::new(
            Some(Box::new(|_| Answer::Take)),
            None,
            shared,
            Ctx {
                app_id: AppId::headless("test"),
                payload_version: 3,
                nonce: 7,
                upkeep: Upkeep::default(),
            },
        );
        let now = Instant::now();
        let mut s = Session::new(&core, None, now);
        take_out(&mut s);
        s.read(&request(3, vec![1]), &core, now);
        let r = reply(&take_out(&mut s));
        assert_eq!(r.refusal, Some(refusal::UNDECODABLE));
        assert_eq!(core.state(), state::TAKING);
    }

    #[test]
    fn stop_reaches_a_declining_owner_and_a_lost_lock_overrides_it() {
        let mut c = core(None);
        c.shared.stop.store(true, Ordering::SeqCst);
        assert!(c.poll_control());
        assert_eq!(c.state(), state::BUSY);
        assert_eq!(c.shared.ended(), Some(End::Stopped));
        c.end(End::LostLock);
        assert_eq!(c.shared.ended(), Some(End::LostLock));
    }

    #[test]
    fn a_stop_is_told_before_the_server_acts_on_it() {
        let c = core(Some(Box::new(|_| Answer::Take)));
        c.shared.stop.store(true, Ordering::SeqCst);
        let now = Instant::now();
        let mut s = Session::new(&c, None, now);
        let hello = take_out(&mut s);
        assert_eq!(Hello::decode(&hello[0].1).unwrap().state, state::BUSY);
        s.read(&request(3, Args::default().encode().unwrap()), &c, now);
        assert_eq!(reply(&take_out(&mut s)).status, status::BUSY);
        assert_eq!(c.shared.ended(), None);
    }

    #[test]
    fn nothing_is_delivered_once_stop_is_called() {
        let mut c = core(Some(Box::new(|_| Answer::Take)));
        c.shared.stop.store(true, Ordering::SeqCst);
        assert_eq!(
            c.deliver(Request::local(Args::default())),
            Some(Answer::Busy)
        );
    }
}
