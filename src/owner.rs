use std::fmt;
use std::io;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use crate::server::{Core, Ctx, Handler, OnEnd, Shared};
use crate::{AppId, Builder, End, IntoAnswer, Payload, Request, sys};

/// The lock, held, before serving. Later launches wait (within their
/// timeout) until [`Claim::serve`] or [`Claim::decline_all`] turns it into
/// an [`Owner`]: create your event loop or channel in between, and nothing
/// slower.
///
/// A `Claim` starts no thread, so a Unix daemon may fork while holding one
/// and serve it in the child (see the crate docs). Dropping a `Claim` that
/// was never served keeps the lock until the process exits, turns later
/// launches away at once as [`Claim::decline_all`] does, and logs a
/// warning; see [`Claim::release`].
#[must_use = "serve the Claim, or later launches are turned away"]
pub struct Claim<T> {
    claimed: Option<Box<sys::Claimed>>,
    place: sys::Place,
    state: Option<PathBuf>,
    /// Boxed, so that [`Started::Owner`](crate::Started::Owner) isn't much
    /// larger than the other outcomes.
    ctx: Box<Ctx>,
    on_end: Mutex<Option<OnEnd>>,
    _payload: PhantomData<fn() -> T>,
}

impl<T> fmt::Debug for Claim<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Claim")
            .field("app_id", &self.ctx.app_id)
            .field("dir", &self.dir())
            .field("state_dir", &self.state_dir())
            .finish_non_exhaustive()
    }
}

impl<T> Claim<T> {
    /// `instance_key` is the key the launch made for `state` and its scope
    /// ([`Builder::instance_key`]) and compared in each HELLO. The owner
    /// sends it as it is, never made again, so it can't differ from what
    /// launches of the same state compare.
    pub(crate) fn new(
        b: &Builder,
        place: sys::Place,
        folder: sys::Folder,
        lock: sys::Lock,
        state: Option<PathBuf>,
        instance_key: Vec<u8>,
    ) -> Claim<T> {
        Claim {
            claimed: Some(Box::new(sys::Claimed::new(folder, lock, &b.app_id))),
            place,
            state,
            ctx: Box::new(Ctx {
                app_id: b.app_id.clone(),
                instance_key,
                payload_version: b.payload_version,
                nonce: nonce(),
                upkeep: b.upkeep,
            }),
            on_end: Mutex::new(None),
            _payload: PhantomData,
        }
    }

    fn claimed(&self) -> &sys::Claimed {
        self.claimed
            .as_ref()
            .expect("a Claim is used up only by consuming it")
    }

    /// Call `f` once, on the crate's thread, when the owner ends, right
    /// after the handler is dropped: no request reaches the handler after
    /// it. For hosts whose channel doesn't close when the handler drops (an
    /// event-loop proxy, a channel with other senders), and to learn of
    /// [`End::LostLock`]. `f` must not block. It isn't called for a `Claim`
    /// that is released, or for a process that exits first. A second call
    /// replaces the first.
    pub fn on_end(self, f: impl FnOnce(End) + Send + 'static) -> Claim<T> {
        *self.on_end.lock().unwrap_or_else(|e| e.into_inner()) = Some(Box::new(f));
        self
    }

    /// Hold the lock but turn every later launch away at once
    /// ([`Reason::Declined`]). For self-tests, scripted runs and debug
    /// builds that may own the app's state when nothing else does, but must
    /// not receive the user's launches.
    ///
    /// [`Reason::Declined`]: crate::Reason::Declined
    pub fn decline_all(mut self) -> Owner {
        self.run::<()>(None)
    }

    /// The runtime folder holding the lock.
    pub fn dir(&self) -> &Path {
        self.claimed().folder.path()
    }

    /// The state folder given to [`Builder::new`], with its links resolved
    /// as [`State::dir`] says, or `None` for [`State::none`]. Write the
    /// state through this path, and only while this process owns the app:
    /// a launch that runs alone gets no `state_dir`.
    ///
    /// [`State::dir`]: crate::State::dir
    /// [`State::none`]: crate::State::none
    pub fn state_dir(&self) -> Option<&Path> {
        self.state.as_deref()
    }

    /// Why later launches can't reach this process, if they can't: the
    /// socket couldn't be made. This process still owns the lock; later
    /// launches wait out their timeout and run alone.
    pub fn listen_error(&self) -> Option<&io::Error> {
        self.claimed().listener.as_ref().err()
    }

    /// Give the lock up without ever serving. In a process forked after
    /// `start`, this only closes the fork's copies: the lock stays with the
    /// process that serves it.
    pub fn release(mut self) {
        if let Some(claimed) = self.claimed.take() {
            claimed.release();
        }
    }

    fn run<U: Payload>(&mut self, handler: Option<Handler<U>>) -> Owner {
        let claimed = self.claimed.take().expect("a Claim is served once");
        let dir = claimed.folder.path().to_path_buf();
        let (held, listener, listen_error) = claimed.into_parts();
        let shared = Shared::new(held);
        let on_end = self
            .on_end
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        spawn(
            Core::new(handler, on_end, shared.clone(), Ctx::clone(&self.ctx)),
            listener,
            self.place.clone(),
        );
        Owner {
            app_id: self.ctx.app_id.clone(),
            dir,
            state: self.state.take(),
            listen_error,
            shared,
        }
    }
}

impl<T: Payload> Claim<T> {
    /// Start taking later launches' requests: each one goes to `handler`, on
    /// a thread this crate owns, one at a time.
    ///
    /// `handler` returns an [`Answer`], or a `bool` (`true` takes, `false`
    /// is busy), so a channel's non-blocking send is a whole handler:
    ///
    /// ```no_run
    /// # use instance_handoff::{Args, Claim, Owner};
    /// # fn f(claim: Claim<Args>) -> Owner {
    /// let (tx, rx) = std::sync::mpsc::channel();
    /// let owner = claim.serve(move |request| tx.send(request).is_ok());
    /// # drop(rx); owner
    /// # }
    /// ```
    ///
    /// `handler` must return quickly and must not wait for the thread that
    /// calls [`Owner::stop`]. It is dropped, on the crate's thread, once the
    /// owner ends (see [`End`]) and any call in progress has returned. If it
    /// panics, the owner ends with [`End::Panicked`].
    ///
    /// [`Answer`]: crate::Answer
    pub fn serve<F, R>(mut self, mut handler: F) -> Owner
    where
        F: FnMut(Request<T>) -> R + Send + 'static,
        R: IntoAnswer,
    {
        self.run::<T>(Some(Box::new(move |request| {
            handler(request).into_answer()
        })))
    }
}

impl<T> Drop for Claim<T> {
    /// Unless served, declined or released: [`Claim::decline_all`], and a
    /// warning through `log`. The lock stays held until the process exits.
    fn drop(&mut self) {
        let Some(claimed) = self.claimed.take() else {
            return;
        };
        // A forked copy (a helper that doesn't serve): touch nothing, so the
        // process that serves stays reachable, and keep this process's share
        // of the lock until it exits, as any dropped Claim does.
        if claimed.forked() {
            claimed.abandon();
            return;
        }
        log::warn!(
            "instance-handoff {}: a Claim was dropped without being served; turning \
             launches away until this process exits",
            self.ctx.app_id
        );
        let (held, listener, _) = claimed.into_parts();
        // The thread keeps `shared`, and with it the lock, until the
        // process exits: nothing ever closes it.
        let shared = Shared::new(held);
        if !spawn(
            Core::<()>::new(None, None, shared.clone(), Ctx::clone(&self.ctx)),
            listener,
            self.place.clone(),
        ) {
            std::mem::forget(shared);
        }
    }
}

/// Starts the crate's thread. `false` if it couldn't be started.
fn spawn<U: Payload>(core: Core<U>, listener: Option<sys::Listener>, place: sys::Place) -> bool {
    let name = core.ctx.app_id.to_string();
    let app_id = core.ctx.app_id.clone();
    let shared = core.shared.clone();
    let ended = shared.clone();
    let spawned = std::thread::Builder::new().name(name).spawn(move || {
        let app_id = core.ctx.app_id.clone();
        // Every call into app code is caught; this is the backstop, so the
        // app hears that the owner ended rather than nothing at all.
        let served = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sys::serve(core, listener, place)
        }));
        if served.is_err() {
            log::error!("instance-handoff {app_id}: the thread serving launches panicked");
            let mut ended = ended.ended.lock().unwrap_or_else(|e| e.into_inner());
            ended.get_or_insert(End::Panicked);
        }
    });
    if let Err(e) = spawned {
        // The core went with the closure; the lock stays with `shared`.
        log::error!("instance-handoff {app_id}: can't start the thread that serves launches: {e}");
        shared.close.store(true, Ordering::SeqCst);
        return false;
    }
    true
}

/// The owner nonce: different for every owner, so a launch can tell a new
/// owner from one it already committed to.
fn nonce() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u32(std::process::id());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    h.write_u128(now);
    h.finish()
}

/// The running owner. `Send` and `Sync`, so it can live on `main`'s stack, in
/// an app struct, in an async task or in a GUI framework's global.
///
/// Dropping it stops serving but keeps the lock until the process exits;
/// see [`Owner::release`] and the crate docs' "Quitting".
#[must_use = "keep the Owner for the life of the app: dropping it stops serving later launches"]
pub struct Owner {
    app_id: AppId,
    dir: PathBuf,
    state: Option<PathBuf>,
    listen_error: Option<io::Error>,
    shared: Arc<Shared>,
}

impl fmt::Debug for Owner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Owner")
            .field("app_id", &self.app_id)
            .field("dir", &self.dir)
            .field("state_dir", &self.state)
            .field("listen_error", &self.listen_error)
            .field("ended", &self.ended())
            .finish_non_exhaustive()
    }
}

impl Owner {
    /// The app this process owns.
    pub fn app_id(&self) -> &AppId {
        &self.app_id
    }

    /// The runtime folder holding the lock.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The state folder, as [`Claim::state_dir`] reported it.
    pub fn state_dir(&self) -> Option<&Path> {
        self.state.as_deref()
    }

    /// Stop delivering, once the app is certain to quit. Launches from now
    /// on are told the owner is busy: they keep trying the lock, take it
    /// once this process exits, or run alone at their timeout. No handler
    /// call starts after `stop` returns. The handler is dropped as soon as a
    /// call in progress returns, even if no launch arrives, which closes the
    /// channel it sends to; the owner then ends with [`End::Stopped`]. A
    /// declining owner ([`Claim::decline_all`]) turns busy and ends the same
    /// way; one whose handler panicked keeps turning launches away.
    ///
    /// Returns at once, from any thread, the handler's own included; it
    /// never waits for the handler. Idempotent, and it can't be undone: to
    /// turn launches away for a while, return [`Answer::Busy`] from the
    /// handler instead. The lock stays held.
    ///
    /// [`Answer::Busy`]: crate::Answer::Busy
    pub fn stop(&self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        self.shared.waker.wake();
    }

    /// Whether [`Owner::stop`] was called.
    pub fn is_stopped(&self) -> bool {
        self.shared.stop.load(Ordering::SeqCst)
    }

    /// Why the owner ended, once it has: set before the handler is dropped,
    /// so it's known by the time a channel the handler fed closes. `None`
    /// while serving or declining. [`End::LostLock`] replaces
    /// [`End::Stopped`] if the lock is lost after `stop`: check this before
    /// writing state.
    pub fn ended(&self) -> Option<End> {
        self.shared.ended()
    }

    /// Why the socket couldn't be made, if it couldn't.
    pub fn listen_error(&self) -> Option<&io::Error> {
        self.listen_error.as_ref()
    }

    /// Stop, remove the socket and give up the lock, so another process can
    /// become the owner while this one runs on. A handler call in progress
    /// may still finish, and its launch is still answered; no call starts
    /// after `release` returns.
    pub fn release(self) {
        self.close(false);
    }

    fn close(&self, keep_lock: bool) {
        self.shared.stop.store(true, Ordering::SeqCst);
        self.shared.close.store(true, Ordering::SeqCst);
        {
            let mut held = self.shared.held();
            // After LostLock the files at the path are another owner's.
            if self.shared.ended() != Some(End::LostLock) {
                held.unlink_socket();
            }
            if let Some(lock) = held.lock.take() {
                if keep_lock {
                    // Held until the process exits, so a mistaken drop can
                    // never let a second owner start beside this one.
                    std::mem::forget(lock);
                }
            }
        }
        self.shared.waker.wake();
    }
}

impl Drop for Owner {
    /// Stop serving and close the socket. The lock stays held until the
    /// process exits.
    fn drop(&mut self) {
        self.close(true);
    }
}
