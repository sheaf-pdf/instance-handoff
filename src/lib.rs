//! Funnel every launch of a program into one process per user.
//!
//! The first launch takes a lock in a private, per-user runtime folder and
//! becomes the **owner**: the one process that holds the program's state.
//! Every later launch connects to the owner, hands over a payload (often its
//! [`Args`]) and exits. The OS releases the lock when the owner exits, crash
//! included, so a lock is never stale.
//!
//! ```no_run
//! use instance_handoff::{AppId, Args, Builder, Request, Started};
//!
//! const APP: AppId = AppId::new("org.example.Player");
//!
//! // Hand over only what the owner needs: here, the files. A flag is not a
//! // path, and `Request::resolve` would make one of it.
//! let files: Args = Args::from_env()
//!     .into_iter()
//!     .filter(|arg| !arg.to_string_lossy().starts_with('-'))
//!     .collect();
//! // Decide first, before any window, event loop or runtime exists.
//! let claim = match Builder::new(APP).start(&files) {
//!     Started::Owner(claim) => claim,
//!     Started::HandedOff(_) => return, // the owner has them; exit
//!     Started::Alone(reason) => panic!("can't run as the only instance: {reason}"),
//! };
//! let (tx, rx) = std::sync::mpsc::channel();
//! let owner = claim.serve(move |request| tx.send(request).is_ok());
//! # fn play(_: &std::path::Path) {}
//! // This launch's own files first (they never go through the handler),
//! // then every later launch's.
//! for request in std::iter::once(Request::local(files)).chain(rx) {
//!     for file in request.payload() {
//!         if let Some(file) = request.resolve(file) {
//!             play(&file);
//!         }
//!     }
//! }
//! # drop(owner);
//! ```
//!
//! # Guarantees
//!
//! - At most one process holds the lock for an app id and runtime folder
//!   at a time, and only it gets [`Started::Owner`]. A process that gets
//!   [`Started::Alone`] must not write the state the owner owns. If the
//!   runtime folder is deleted under a running owner and another process
//!   becomes the owner before this one re-creates its lock, this one is told
//!   ([`End::LostLock`]) within a minute.
//! - Each launch ends one of three ways, whatever the timing (stopped
//!   processes, slow handlers, expired timeouts):
//!   - it hands off ([`Started::HandedOff`]): an owner's handler takes its
//!     request at most once, and has taken it when
//!     [`OwnerInfo::confirmed`];
//!   - it runs alone ([`Started::Alone`]): no owner takes its request;
//!   - it becomes the owner.
//!
//!   "Takes" means the handler answered [`Answer::Take`]: a handler that
//!   answers busy may see the same request again when the launch retries.
//!   The one exception is an owner that dies mid-handoff, after its handler
//!   may have taken a request but before it could say so. The launch then
//!   takes the lock itself or hands the request to the next owner, so work
//!   the dead owner had started may be done again.
//! - Only processes of the same user at the same privilege level hand off
//!   to each other, so a request never runs with more or fewer rights than
//!   its launch had; see [Privileges](#privileges). On Unix both ends check
//!   the other's user id. On Windows the owner checks the launch's token,
//!   and the launch checks that the pipe is its own user's, at its own
//!   integrity level.
//! - [`Builder::start`], [`Builder::hand_off`] and [`Builder::probe`] never
//!   panic, whatever the [timeout](Builder::timeout). Every failure is a
//!   [`Reason`], and failures that waiting can't fix return at once.
//!
//! # Threads, blocking and fork
//!
//! - `start`, `hand_off` and `probe` block for at most the
//!   [timeout](Builder::timeout) plus the greater of the timeout and one
//!   second, and usually for a few milliseconds. Call
//!   them first thing in `main`, before an event loop, a display connection
//!   or an async runtime exists, or inside `spawn_blocking`. Serve the
//!   [`Claim`] soon after: launches wait for it, and run alone if it takes
//!   longer than their timeout.
//! - `start` creates no thread. A [`Claim`] is a held lock and a listening
//!   socket, nothing more; [`Claim::serve`] and [`Claim::decline_all`] start
//!   the crate's one thread, named after the app id.
//! - The handler given to [`Claim::serve`] runs on that thread, one call at
//!   a time, and is dropped there. It must not block: send the [`Request`]
//!   to a channel or an event-loop proxy and return. Use a send that can't
//!   wait (`send` on an unbounded channel, `try_send` on a bounded one); a
//!   send that blocks on a full channel stalls every launch.
//! - Nothing in this crate waits for the handler. [`Owner::stop`],
//!   [`Owner::release`] and dropping an `Owner` return at once, on any
//!   thread, the handler's own included.
//! - On Unix, daemonize by forking after `start` and before `serve`: the
//!   child serves the `Claim`, and the parent leaves with
//!   [`std::process::exit`] so that its copy of the `Claim` is never dropped.
//!   The parent learns the outcome from `start` itself. Never fork after
//!   `serve`: the crate's thread doesn't survive `fork`. (macOS forbids
//!   `fork` without `exec` once Core Foundation is running: fork before
//!   anything touches it.)
//!
//! # Quitting
//!
//! 1. Call [`Owner::stop`] once the quit is certain, after any prompt that
//!    can still cancel it: stop can't be undone. Launches from then on are
//!    told the owner is busy and keep trying the lock, so none hands work to
//!    a process on its way out. The handler is dropped as soon as a call in
//!    progress returns, even if no launch ever arrives again, which closes
//!    your channel.
//! 2. Drain the channel until it closes, if you can: each request in it was
//!    answered "taken", and its launch has exited. Where requests go through
//!    an event-loop proxy or a channel that has other senders, the callback
//!    given to [`Claim::on_end`] marks the same moment.
//! 3. Write your state while still holding the lock, unless the owner ended
//!    with [`End::LostLock`].
//! 4. Exit. The lock goes with the process.
//!
//! Dropping an [`Owner`] stops serving but **keeps the lock until the
//! process exits**, so a value dropped by mistake (`let _ = …`, an `if let`
//! or `matches!` on the result of `start`) can never let a second owner
//! start beside this one. Dropping a [`Claim`] that was never served keeps
//! the lock too, turns later launches away at once as
//! [`Claim::decline_all`] does, and logs a warning. [`Owner::release`] gives
//! the lock up while the process runs on, for tests and services that
//! restart in place. `stop` stays necessary where destructors don't run:
//! `process::exit`, GPUI's and AppKit's `terminate:` on macOS.
//!
//! # Where the lock lives
//!
//! In a local, per-user folder that every launch of the same user finds.
//! Each launch has exactly one right folder and never falls back to
//! another, because a fallback is how two launches end up with two owners:
//!
//! - Linux in a Flatpak sandbox: `$XDG_RUNTIME_DIR/app/$FLATPAK_ID/<id>`;
//!   in a snap: `$XDG_RUNTIME_DIR/<id>`.
//! - Linux with systemd: `/run/user/<uid>/<id>`, which exists while the
//!   user has a session (or lingers). Without it, launches run alone with
//!   [`Reason::NoSession`]; see "Daemons, services and cron".
//! - Linux without systemd, and the BSDs and illumos: `/tmp/<id>-<uid>`,
//!   created private. If another user created it first, launches run alone
//!   with [`Reason::RuntimeDir`]. (CI checks FreeBSD, NetBSD and illumos;
//!   OpenBSD and DragonFly share their code but aren't checked.)
//! - macOS: `<id>` in the per-user temporary folder
//!   (`confstr(_CS_DARWIN_USER_TEMP_DIR)`, not `$TMPDIR`), the same for GUI
//!   apps, agents, ssh and cron.
//! - Windows: `<id>\run` in the Local AppData known folder, and
//!   `<id>\run-high` for a process run as administrator; see
//!   [Privileges](#privileges).
//! - Android: `$TMPDIR/<id>`.
//! - Anywhere else: nothing; launches run alone with
//!   [`Reason::Unsupported`].
//!
//! [`Builder::scope`] adds a subfolder (one owner per session, per profile,
//! per container), and [`Builder::dir`] replaces the folder. It is never a
//! config folder: on Windows that roams and may be a network share, where a
//! lock would span machines. The owner touches its files every hour, so
//! cleaners that go by age leave them alone, and checks every minute that
//! its lock is still in place, re-creating it when something deleted it.
//! On Windows nothing can: the owner holds its folder, its lock and
//! `instance.pipe` open, sharing no delete.
//!
//! # Privileges
//!
//! A request runs with the rights of the launch that made it, never more
//! and never fewer. Handed to a more privileged owner, it would have that
//! owner act for a process that isn't allowed to; handed to a less
//! privileged one, it would run without the rights the user started it
//! with. So a launch hands off only to an owner of its own user at its own
//! privilege level, and each level has an owner of its own:
//!
//! - Unix: the level is the effective user, as the kernel reports it in the
//!   process's own user namespace. On Linux the crate reads it, and the
//!   owners of its folders, with system calls rather than through the C
//!   library, so `fakeroot` doesn't change them: a launch under `fakeroot`
//!   is still its user's, and hands off to that user's owner. Root (`sudo`,
//!   `su`, `doas`, `pkexec`) is another user, with its own folder and
//!   owner, and so is the user a setuid program runs as. On Linux with
//!   systemd, root has `/run/user/0` only while it is logged in somewhere
//!   (a console, SSH): root's launches then meet one owner, like any
//!   user's, and launches under `sudo` meet that owner too. Otherwise
//!   launches under `sudo` run alone with [`Reason::NoSession`].
//! - Windows: the level is the user and the integrity level. A launch run
//!   as administrator (high) uses `<id>\run-high` and an owner of its own,
//!   and never reaches the normal (medium) owner; nor does a normal launch
//!   reach an elevated one. Each level's folder is labelled at its level,
//!   so lower levels can't read it or take its lock. Below medium (low
//!   integrity, AppContainer), launches can't make or open their folder and
//!   run alone with [`Reason::RuntimeDir`].
//!
//! Two limits:
//!
//! - Owners at two levels are two owners. If both read and write the same
//!   files, keep the state apart per level, or refuse to run elevated. An
//!   elevated and a normal process on Windows share the profile, and root
//!   under `sudo -E` (or wherever `HOME` is kept) writes into the user's
//!   home.
//! - Within one Unix user, finer privileges aren't compared: supplementary
//!   groups (`newgrp`), capabilities and LSM confinement. A sandbox that
//!   must keep its processes from the owner hides the runtime folder from
//!   them, as Flatpak and snap do; each then has its own owner.
//!
//! # Daemons, services and cron
//!
//! A launch on Linux finds the owner only if both see the same folder. For
//! a long-running owner that starts outside a login session:
//!
//! 1. Prefer a systemd user unit plus `loginctl enable-linger`, which keeps
//!    `/run/user/<uid>` for good, so interactive launches and the service
//!    meet there. An `@reboot` cron job gets [`Reason::NoSession`] instead.
//! 2. For a system service with `User=`, add `PAMName=` with a PAM stack
//!    that runs `pam_systemd`, or enable linger for that user.
//! 3. [`Builder::dir`] only when every launch of the app passes the same
//!    folder, or for a private instance that interactive launches must
//!    never reach. With systemd's `RuntimeDirectory=`, set
//!    `RuntimeDirectoryMode=0700`: the folder must be private.
//!
//! # Containers and sandboxes
//!
//! - Flatpak: instances of one `FLATPAK_ID` meet each other. Each has its
//!   own PID namespace, so [`OwnerInfo::pid`] and [`Request::launcher_pid`]
//!   are usually `None`.
//! - Containers: one that sees the host's `/run/systemd/system` and
//!   `/run/user/<uid>` (toolbox does) meets the host's owner, which is
//!   usually what you want, since it shares `$HOME`. But paths outside the
//!   shared mounts may name other files there. A container without systemd
//!   uses its own `/tmp`, and so runs its own owner: if it must meet the
//!   host's, pass the bind-mounted folder to [`Builder::dir`] in both. Use
//!   [`Builder::scope`] with the container's name for one owner per
//!   container.
//! - Windows: mapped drives and `SUBST` letters belong to one logon
//!   session, and every logon session of a user at one integrity level (a
//!   second RDP session, an OpenSSH login, a scheduled task) reaches the
//!   same owner. Hand off canonical paths when that matters.
//!
//! # Raising a window
//!
//! A launch the user just started may bring a window forward; the owner, in
//! the background, usually may not. On Windows the launch calls
//! `AllowSetForegroundWindow` for the owner's process before handing off. On
//! Wayland and X11 the launch's `XDG_ACTIVATION_TOKEN` and
//! `DESKTOP_STARTUP_ID` travel with its request: see
//! [`Request::activation`]. macOS has no such token.
//!
//! # The contract between builds
//!
//! Two builds of one app may use different releases of this crate, so what
//! they share is fixed, and only a major release changes it:
//!
//! - the folder rule above, and the scope subfolder's name. On Windows the
//!   folder for an integrity level other than medium is `run-low`,
//!   `run-high`, `run-system`, or else `run-` and the level's RID in
//!   lowercase hex;
//! - the lock: `flock(LOCK_EX | LOCK_NB)` on `instance.lock` on Unix, an
//!   exclusive `LockFileEx` on its first byte on Windows. Both are held per
//!   open file,
//!   inherited across `fork`, and released when the last copy closes;
//! - the address. On Unix, `instance.sock` beside the lock. When that path
//!   is too long for a socket address, Linux reaches it through
//!   `/proc/self/fd`; other Unixes use `<base>/<hash>.sock`, where the base
//!   is the per-user temporary folder on macOS and `/tmp/ih-<uid>`
//!   elsewhere, and the hash is 16 hex digits of the FNV-1a 64 hash of the
//!   folder's device and inode (each a little-endian u64). On Windows, a
//!   named pipe `\\.\pipe\instance-handoff.<id>.<secret>`, where the
//!   secret is 32 random lowercase hex digits, published as
//!   `<id> <secret>` and a newline in `instance.pipe` beside the lock;
//! - the exchange. The owner sends HELLO (its app id, the protocol versions
//!   it speaks, a random nonce, its payload version, its state and its
//!   features). The launch checks it and sends REQUEST. The owner answers
//!   READY. The launch, if still inside its timeout, sends COMMIT, and only
//!   then does the owner call the handler and send REPLY. An owner that
//!   refuses a launch never just closes the connection: it sends REPLY
//!   with the cause at once, in place of READY, or in place of HELLO when
//!   an owner on Unix refuses the launch's user. Feature bit 0 in HELLO
//!   says so, and every owner of this release sets it. A launch reads a
//!   cause it doesn't know as a decline, and a close before HELLO as a
//!   sign to try again. Every message is
//!   `"IHND" | kind u8 | length u32 LE | records`, and a record is
//!   `tag u8 | length u32 LE | bytes`. Peers skip records they don't know,
//!   so later releases add to the exchange without breaking it, unless the
//!   tag's high bit is set: such a record is critical, and a peer that
//!   doesn't know it refuses the message.
//!
//! # Not covered
//!
//! Replies beyond "taken" (exit codes, output, `--wait`), sharing state
//! between processes, taking over from a hung owner, and general IPC. On
//! macOS, Finder and Dock opens reach a running app as Apple Events through
//! its toolkit, not as new launches; feed them to the same channel with
//! [`Request::local`]. On Linux, D-Bus activation reaches the app the same
//! way, if it registers for it.

#![warn(missing_docs, missing_debug_implementations, unsafe_op_in_unsafe_fn)]
// Where nothing can own, the machinery for owning goes unused.
#![cfg_attr(
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "illumos",
        windows
    )),
    allow(dead_code)
)]

mod builder;
mod id;
mod launch;
mod level;
mod naming;
mod outcome;
mod owner;
mod payload;
mod request;
mod server;
mod wire;

#[cfg_attr(
    any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "illumos"
    ),
    path = "sys/unix.rs"
)]
#[cfg_attr(windows, path = "sys/windows.rs")]
#[cfg_attr(
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "illumos",
        windows
    )),
    path = "sys/unsupported.rs"
)]
mod sys;

pub use builder::{Builder, Mode};
pub use id::{AppId, InvalidAppId};
pub use level::{Level, Rights};
pub use outcome::{End, OwnerInfo, Reason, Started};
pub use owner::{Claim, Owner};
#[cfg(feature = "serde")]
pub use payload::Json;
pub use payload::{Args, BoxError, Payload};
pub use request::{Activation, Answer, IntoAnswer, Request};

#[cfg(test)]
mod bounds {
    use super::*;

    fn send_sync<T: Send + Sync + 'static>() {}
    fn send<T: Send + 'static>() {}

    #[test]
    fn the_types_an_app_stores_cross_threads() {
        send_sync::<Owner>();
        send_sync::<Claim<Args>>();
        send_sync::<Builder>();
        send_sync::<Reason>();
        send_sync::<Request<Args>>();
        send_sync::<OwnerInfo>();
        send_sync::<Rights>();
        send_sync::<End>();
        send::<Started<Args>>();
    }

    #[test]
    fn handlers_are_one_liners() {
        // The element type is inferred from the bound, and `bool` converts.
        fn takes<T: Payload>(claim: Claim<T>) {
            let (tx, rx) = std::sync::mpsc::channel();
            let _o = claim.serve(move |r| tx.send(r).is_ok());
            drop(rx);
        }
        fn bounded(claim: Claim<Args>) {
            let (tx, _rx) = std::sync::mpsc::sync_channel(16);
            let _o = claim.serve(move |r| tx.try_send(r).is_ok());
        }
        fn refusing(claim: Claim<Args>) {
            let _o = claim.serve(|r| {
                if r.payload().iter().any(|a| a == "--unknown") {
                    Answer::Decline
                } else {
                    Answer::Take
                }
            });
        }
        fn with_end(claim: Claim<Args>) {
            let (tx, _rx) = std::sync::mpsc::channel();
            let ended = tx.clone();
            let _o = claim
                .on_end(move |end| drop(ended.send(Err(end))))
                .serve(move |r| tx.send(Ok(r)).is_ok());
        }
        let _ = (takes::<Args>, bounded, refusing, with_end);
    }
}
