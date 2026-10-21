//! Funnel every launch of an app into one process per user and state.
//!
//! The first launch takes a lock in a private, per-user folder and becomes
//! the **owner**: the one process that keeps the app's state. Every later
//! launch connects to the owner, hands over a payload (often its [`Args`])
//! and exits. The OS releases the lock when the owner exits, crash
//! included, so a lock is never stale.
//!
//! The state is the folder the app keeps its files in ([`State`]), and the
//! lock's folder is named after it: launches that name one state folder
//! meet one owner, and launches that name two get two.
//!
//! ```no_run
//! use instance_handoff::{AppId, Args, Builder, Reason, Request, Started, State};
//!
//! const APP: AppId = AppId::windowed("org.example.Player");
//! # fn library_dir() -> std::path::PathBuf { unimplemented!() }
//! # fn ask(_: &str) -> bool { false }
//! # fn play_alone(_: Args) {}
//!
//! // Hand over only what the owner needs: here, the files. A flag is not a
//! // path, and `Request::resolve` would make one of it.
//! let files: Args = Args::from_env()
//!     .into_iter()
//!     .filter(|arg| !arg.to_string_lossy().starts_with('-'))
//!     .collect();
//! // Decide first, before any window, event loop or runtime exists. The
//! // state is the folder the player keeps its library in.
//! let player = Builder::new(APP, State::dir(library_dir()));
//! let claim = match player.start(&files) {
//!     Started::Owner(claim) => claim,
//!     Started::HandedOff(_) => return, // the owner has them; exit
//!     Started::Alone(reason) => {
//!         // On Windows, from an administrator terminal, with a normal
//!         // player running: its handler would open the files without
//!         // these rights.
//!         if let Reason::MoreRights { owner, rights, .. } = &reason {
//!             let open = format!("Open in the running player ({owner}), without {rights}?");
//!             if ask(&open) && player.clone().hand_down(true).hand_off(&files).is_ok() {
//!                 return;
//!             }
//!         }
//!         // Play them without the library, which only the owner writes.
//!         eprintln!("{reason}");
//!         return play_alone(files);
//!     }
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
//! - One owner per state. Launches of one app id by one user that name one
//!   state folder and one [scope](Builder::scope) meet at one lock in their
//!   runtime folder, and only the one that holds it gets
//!   [`Started::Owner`]. The user's launches find the same runtime folder
//!   whatever their Windows integrity level, session or display. Both
//!   [kinds](Kind) of an app id meet there, and a launch of the other kind
//!   than the owner's gets [`Reason::OtherApp`]. The owner also holds the
//!   state folder's [guard](Guard), so a launch that took a lock in another
//!   runtime folder (in another container, under another [`Builder::dir`],
//!   or as another app id that shares the folder) doesn't own it too: it
//!   runs alone at once with [`Reason::StateInUse`]. Owners with a scope
//!   share the guard: owners of one state folder under two scopes, or
//!   under one scope in two runtime folders, own it side by side, but
//!   never beside an owner without one. Nor does the guard keep anyone out
//!   where the owner takes none: under [`Guard::Off`], for [`State::none`],
//!   on a network file system, or where the file system can't lock files.
//! - A process that gets [`Started::Alone`], for whatever reason
//!   ([`Reason::MoreRights`] among them), must not write the state: only
//!   the owner, or a process that holds the state with
//!   [`Builder::exclusive`], may. If the state folder is removed or
//!   replaced under an owner that holds its guard, the owner is told
//!   ([`End::LostState`]) within a minute, and gives up its guard and its
//!   lock, so the next launch owns the folder now at the path. If the
//!   runtime folder is deleted under a running owner, the owner makes it
//!   again within a minute, once no other process holds the lock there.
//!   Where the owner holds the guard alone, a launch that takes the lock
//!   there first finds the guard held and lets go, and the owner waits for
//!   any other process that holds it. Otherwise, if another process takes
//!   the lock there first, the owner is told ([`End::LostLock`]), and gives
//!   its guard up.
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
//! - A request never runs with more rights than its launch had, and never
//!   with fewer unless the app lets the launch hand it down
//!   ([`Builder::hand_down`]). It never goes to another user. Both ends
//!   check the other: see [Privileges](#privileges).
//! - [`Builder::start`], [`Builder::hand_off`], [`Builder::probe`] and
//!   [`Builder::exclusive`] never panic, whatever the
//!   [timeout](Builder::timeout). Every failure is a [`Reason`], and
//!   failures that waiting can't fix return at once.
//!
//! # The state
//!
//! [`State::dir`] names the folder the app keeps its state in: the files
//! only the owner writes. Pass the folder the app's storage layer writes,
//! computed by the same function, so that the owner owns what the app
//! writes. An app with several folders passes the one the others are
//! derived from. [`State::none`] is for an app that keeps no files of its
//! own: its launches meet by app id, user and scope alone, and no guard
//! keeps out an owner in another runtime folder.
//!
//! - The folder's links are resolved, so launches that name it through a
//!   symbolic link, a `SUBST` letter or a mapped drive meet one owner, as
//!   long as each can see the link. On Windows a mapped drive or a `SUBST`
//!   letter belongs to one logon session, and a launch run as
//!   administrator with UAC on has a logon session of its own (see
//!   [Containers and sandboxes](#containers-and-sandboxes)).
//! - The folder needn't exist: a [`Builder::start`] that takes the lock,
//!   and [`Builder::exclusive`], make it when it is missing, private,
//!   whether or not they take the guard.
//! - A launch that the app's function gives another folder gets another
//!   owner. If the function follows the environment, as
//!   `dirs::config_dir()` follows `HOME` and `XDG_CONFIG_HOME` on Unix, a
//!   shell or a test that points those elsewhere gets an owner of its own.
//!   If it follows the account, as the Windows known folders do (they
//!   ignore `%APPDATA%`), a test must pass its folder through an option of
//!   the app's own.
//! - The owner keeps its [guard](Guard), `.instance-handoff.lock`, in the
//!   folder. For a folder that a sync tool copies between machines, and
//!   for config that is read-only or shared, use [`Guard::Off`].
//! - The app must never replace or rename the folder, though it may
//!   replace the files in it. On Unix an owner that holds the guard ends
//!   with [`End::LostState`] within a minute when the folder is replaced;
//!   on Windows, replacing or renaming it fails while the owner holds the
//!   guard.
//! - A folder of another user's, as the user's home is to root under
//!   `sudo -E`, gives [`Reason::ForeignState`]: see [`Builder::new`].
//!
//! Recipes:
//!
//! - **An administrator terminal.** On Windows, a launch from one, with a
//!   normal owner running, gets [`Reason::MoreRights`], which names the
//!   owner and what it lacks. The crate never decides whether a request
//!   may do without its launch's rights: the app, or its user, does. Ask
//!   the user whether to open the request in the running instance without
//!   those rights, and on a yes hand it down, as the example above does:
//!   `b.clone().hand_down(true).hand_off(&payload)`. Otherwise run alone,
//!   writing no state. A command that needs no rights, such as `stop` or
//!   `reload`, can hand down without asking.
//! - **Batch work.** Work that rewrites the state, such as a migration, an
//!   import, a cron job or a CI step, holds it with [`Builder::exclusive`]
//!   (see its example). That serves no launches, and while it is held no
//!   launch owns the state folder (see [`Exclusive`] for the exceptions).
//! - **Front ends.** Commands that only make sense against a running app,
//!   such as `status`, `stop` or `--remote open`, use [`Builder::probe`]
//!   and [`Builder::hand_off`], which never own: see
//!   [Daemons](#daemons-services-and-cron).
//! - **Tests and CI.** Give each test a state folder of its own, a fresh
//!   temporary one, say: it gets an owner of its own, and a test that
//!   panics while it owns can't block the next. An app with
//!   [`State::none`] gives each test a [scope](Builder::scope), or a
//!   [`Builder::dir`], of its own instead: a test that points `HOME`
//!   elsewhere still meets the others. Without a display, as on most CI
//!   runners, a [windowed](Kind::Windowed) app's launches can't own: build
//!   the tests' [`AppId`] as headless, or on Linux and the BSDs run them
//!   under a display server such as Xvfb (`xvfb-run cargo test`).
//!
//! # Threads, blocking and fork
//!
//! - `start`, `hand_off` and `probe` block for at most the
//!   [timeout](Builder::timeout) plus the greater of the timeout and one
//!   second, and usually for a few milliseconds. Call them first thing in
//!   `main`, before an event loop, a display connection or an async
//!   runtime exists, or inside `spawn_blocking`. Serve the [`Claim`] soon
//!   after: launches wait for it, and run alone if it takes longer than
//!   their timeout.
//! - `start` creates no thread. A [`Claim`] is a held lock and a listening
//!   socket, nothing more; [`Claim::serve`] and [`Claim::decline_all`] start
//!   the crate's one thread, named after the app id. [`Builder::exclusive`]
//!   never waits for the state folder and creates no thread.
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
//!   `serve`: the crate's thread doesn't survive `fork`. A helper forked
//!   from the owner without `exec` holds the lock and the guard until it
//!   exits too, even after the owner has, and one forked while an
//!   [`Exclusive`] is held holds it too. (macOS forbids `fork` without
//!   `exec` once Core Foundation is running: fork before anything touches
//!   it.)
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
//!    with [`End::LostLock`] or [`End::LostState`].
//! 4. Exit. The lock and the guard go with the process.
//!
//! Dropping an [`Owner`] stops serving but **keeps the lock and the guard
//! until the process exits**, so a value dropped by mistake (`let _ = …`,
//! an `if let` or `matches!` on the result of `start`) can never let a
//! second owner start beside this one. Dropping a [`Claim`] that was never
//! served keeps them too, turns later launches away at once as
//! [`Claim::decline_all`] does, and logs a warning. [`Owner::release`] gives
//! both up while the process runs on, for tests and services that restart
//! in place. `stop` stays necessary where destructors don't run:
//! `process::exit`, GPUI's and AppKit's `terminate:` on macOS. An
//! [`Exclusive`] is different: it serves no launches, and dropping it
//! releases the state folder at once.
//!
//! # Where the lock lives
//!
//! In a local, per-user folder that every launch of the same user finds:
//! the app's folder. Each launch has exactly one right folder and never
//! falls back to another, because a fallback is how two launches end up
//! with two owners. The app's folder is:
//!
//! - Linux in a Flatpak sandbox: `$XDG_RUNTIME_DIR/app/$FLATPAK_ID/<id>`;
//!   in a snap: `$XDG_RUNTIME_DIR/<id>`.
//! - Root: `/run/instance-handoff/<id>` on Linux (outside those sandboxes),
//!   and `/var/run/instance-handoff/<id>` on the BSDs and illumos, whether
//!   or not root is logged in. The crate creates `instance-handoff` for
//!   root alone when it is missing, but not `/run` or `/var/run`. It must
//!   be a real folder, root's, and writable by nobody else, or launches run
//!   alone with [`Reason::RuntimeDir`].
//! - Other users on Linux with systemd: `/run/user/<uid>/<id>`, which
//!   exists while the user has a session (or lingers). Without it,
//!   launches that may own run alone with [`Reason::NoSession`], and
//!   [`Builder::hand_off`], [`Builder::probe`] and the other launches look
//!   only at the state folder's [guard](Guard); see
//!   [Daemons](#daemons-services-and-cron).
//! - Other users on Linux without systemd, the BSDs and illumos:
//!   `/tmp/<id>-<uid>`, created private. If another user created it first,
//!   launches run alone with [`Reason::RuntimeDir`]. (CI checks FreeBSD,
//!   NetBSD and illumos; OpenBSD and DragonFly share their code but aren't
//!   checked.)
//! - macOS: `<id>` in the per-user temporary folder
//!   (`confstr(_CS_DARWIN_USER_TEMP_DIR)` with its links resolved, not
//!   `$TMPDIR`), the same for GUI apps, agents, ssh and cron.
//! - Windows: `<id>` in the Local AppData known folder. If Local AppData
//!   resolves into the profiles folder (`C:\Users`) but outside the user's
//!   own profile (into another user's profile or Public, say), launches run
//!   alone with [`Reason::RuntimeDir`]. Redirected anywhere else, it is
//!   used.
//! - Android: `$TMPDIR/<id>`.
//! - Anywhere else: nothing; launches run alone with
//!   [`Reason::Unsupported`].
//!
//! The lock is in the instance folder of the state, in the app's folder:
//! `i-` and 16 hex digits of a hash of the state folder, with its links
//! resolved as [`State::dir`] says, and of the [scope](Builder::scope).
//! The app's kind isn't part of it. Should two states hash alike, a launch
//! of one that reaches the other's owner gets [`Reason::OtherApp`]:
//! [`start`](Builder::start) runs alone with it, and
//! [`hand_off`](Builder::hand_off) and [`probe`](Builder::probe) return
//! it. On Windows every integrity level shares the app's folder, the
//! instance folder and the lock in it, and each level has an address
//! folder there: `run`, or `run-high` for a process run as administrator.
//! See [Privileges](#privileges) for what they hold.
//!
//! [`Builder::dir`] replaces the app's folder. It is never a config folder:
//! on Windows that roams and may be a network share, where a lock would
//! span machines. The instance folder is made in it, as in the app's
//! folder.
//!
//! On Unix the owner touches its files every hour, so cleaners that go by
//! age leave them alone, and checks every minute that its lock is still in
//! place, making the folder and the lock again when something deleted
//! them. On Windows nothing can: the owner holds its folders, its lock and
//! `instance.pipe` open, sharing no delete.
//!
//! The owner also holds the state folder's [guard](Guard): a lock on
//! `.instance-handoff.lock` in it, alone, or shared for an owner with a
//! [scope](Builder::scope). On a network file system the owner takes no
//! guard, so each host keeps an owner of its own; on Windows that is a
//! share, which a mapped drive resolves to, or a drive that Windows says
//! is remote. Nor does it where the file system can't lock files: see
//! [`Guard::Local`].
//!
//! Every minute, an owner that holds the guard checks that the paths of
//! the state folder and of the guard file still name the ones it holds. On
//! Unix it makes a removed guard file again, and ends with
//! [`End::LostState`] when the state folder was removed or replaced, or
//! another process holds the new guard file. On Windows nothing can remove
//! the file, or rename or remove the folder, while the owner holds the
//! guard. [`Builder::exclusive`] takes the guard alone, with no lock in a
//! runtime folder. Where it takes no guard, it takes the lock in the
//! runtime folder instead, and serves nothing. Unlike an owner, it never
//! checks that the state folder is still in place.
//!
//! # Privileges
//!
//! A request runs with the rights of the launch that made it, never more,
//! and never fewer unless the app says so. Handed to an owner with more
//! rights, it would have that owner act for a process that isn't allowed
//! to; handed to one with fewer, it would run without the rights the user
//! started it with. So a launch hands off only to an owner of its own user
//! at its own privilege level, unless the app lets it hand its request down
//! to one at a lower level ([`Builder::hand_down`]). A request never goes
//! to another user, and is never handed up.
//!
//! - Unix: the level is the effective user, as the kernel reports it in the
//!   process's own user namespace. On Linux the crate reads it, the
//!   process's other ids and the owners of its folders with system calls
//!   rather than through the C library, so `fakeroot` doesn't change them:
//!   a launch under `fakeroot` is still its user's, and hands off to that
//!   user's owner. Root (`sudo`, `su`, `doas`, `pkexec`, `run0`) is another
//!   user, with its own folder and owner, so `hand_down` changes nothing on
//!   Unix. On Linux, the BSDs and illumos, root's folder is fixed, so
//!   root's own launches and launches under `sudo` meet one owner, whether
//!   or not root is logged in anywhere. Both ends check the other's user
//!   id, and an owner refuses a launch of another user at once.
//! - Windows: the level is the user and the integrity level. Every level
//!   shares one lock per state, so a launch run as administrator (high) and
//!   a normal (medium) one meet the same owner, but by default only a
//!   launch at the owner's level hands off to it. An owner marks its level
//!   in its lock and names it in its greeting. It checks each launch's
//!   token, and refuses another user, and a launch at another level,
//!   naming its own level in the refusal. A launch that finds an owner at
//!   another level, from its lock, its greeting or its refusal, hands it
//!   nothing and runs alone at once, with [`Reason::MoreRights`] when the
//!   launch has the higher level, or [`Reason::OwnerHasMoreRights`] when
//!   the owner has; [`Builder::probe`] reports such an owner unconfirmed.
//!   With `hand_down`, a launch above the owner hands its request down
//!   instead: it says so in its request, and the owner, which admits a
//!   launch above it only then, tells its handler what was given up, from
//!   the levels of the two tokens ([`Request::handed_down`]). Each owner
//!   publishes its pipe's name in its level's address folder, labelled at
//!   that level, so lower levels can't read it. A launch talks to an owner
//!   at its own level, or below it when it hands down, through that folder.
//!   It checks that the folder and the owner's pipe are labelled at the
//!   level the lock shows, and that the pipe is its own user's, and
//!   otherwise fails with [`Reason::Peer`].
//!
//! A process that has rights its caller lacks, or that a sandbox confines,
//! takes no part at all. Its launches run alone at once with
//! [`Reason::Excluded`], and [`Builder::hand_off`], [`Builder::probe`] and
//! [`Builder::exclusive`] fail with it, before they look for an owner:
//!
//! - On Unix, a process whose real and effective user or group ids differ,
//!   as a setuid or setgid program's do while it runs with its rights. Its
//!   caller chose its environment and arguments. Only those ids are
//!   compared: a set-id program that has set its effective ids back to its
//!   real ones takes part, though its saved ids may let it take its rights
//!   back, and so does a program given file capabilities.
//! - On Windows, a process below medium integrity (low or untrusted), in
//!   an AppContainer, or with a restricted token, which has restricting
//!   SIDs. The sandbox keeps it from what its user may do, so it must
//!   neither reach the user's owner nor own for launches outside the
//!   sandbox. A Basic User token, as `runas /trustlevel:0x20000` gives, is
//!   at medium and has no restricting SIDs, so it takes part.
//!
//! A launch whose rights were raised from a login hands off to its level's
//! owner, but by default never becomes it ([`Builder::elevated_owner`]):
//! with no owner running, it runs alone at once with
//! [`Reason::MayNotOwn`], and [`Builder::exclusive`] fails with it. On
//! Unix that is root whose person is known and isn't root: `SUDO_UID`
//! names them (`sudo`, `run0`), or `PKEXEC_UID` (`pkexec`), `DOAS_USER`
//! (`doas`), or on Linux the login user id that `su` keeps
//! (`/proc/self/loginuid`). Root's own login and services that systemd
//! starts, which have no login user id, still own, and so does root after
//! `su` on macOS and the BSDs, which keep none at all. Root in a container
//! owns when the container runs in a user namespace or was started outside
//! a login, by a daemon such as Docker's. A container started from `sudo`
//! with no user namespace keeps the login user id, so its root counts as
//! raised. On Windows that is a launch with the full half of a token that
//! UAC split, above medium integrity, as Run as administrator and Windows
//! `sudo` give an administrator with UAC on. A medium token made from that
//! half, as `runas /trustlevel:0x20000` makes from an elevated shell,
//! isn't raised: its rights were lowered again. An administrator with UAC
//! off has no split token, and nor has the built-in Administrator (RID
//! 500) unless Admin Approval Mode covers it, so their elevated launches
//! still own when no owner runs, and normal launches then run alone with
//! [`Reason::OwnerHasMoreRights`]. An elevated OpenSSH logon owns too if,
//! as expected, its token isn't split. Under
//! [`ElevatedOwner::NotAboveNormal`] none of these own: on Windows no
//! launch above medium integrity owns, except one at the UIAccess level
//! ([`Level::UI_ACCESS`]), and on Unix no root launch does.
//!
//! Two limits:
//!
//! - On Unix, owners at two levels are two owners. If both read and write
//!   the same files, keep the state apart per level, or refuse to run
//!   elevated. Root under `sudo -E` (or wherever `HOME` is kept) would
//!   write into the user's home, so a state folder of the user's there, or
//!   one root would create there, gives root [`Reason::ForeignState`]
//!   instead of the lock. On Windows an elevated and a normal process
//!   share the profile, and launches of one state meet one owner at either
//!   level: a launch at the other level that doesn't hand its request down
//!   runs alone at once, and must not write the state.
//! - Within one Unix user, finer privileges aren't compared: supplementary
//!   groups (`newgrp`), capabilities and LSM confinement. A sandbox that
//!   must keep its processes from the owner hides the runtime folder from
//!   them, as Flatpak and snap do; each then has its own owner.
//!
//! # Daemons, services and cron
//!
//! A daemon is usually a [headless](Kind::Headless) app, so a launch with
//! no display may own it. Its front-end commands never own: `status` uses
//! [`Builder::probe`], `stop` and `reload` use [`Builder::hand_off`] on a
//! clone with [`hand_down`](Builder::hand_down) set, since they need no
//! rights, and batch commands hold the state with [`Builder::exclusive`].
//! The repository's `examples/cli.rs` is such a daemon.
//!
//! `hand_off` and `probe` never fail with [`Reason::NoSession`]. With no
//! runtime folder to look in, as from cron on Linux without a login
//! session, they can reach no owner, and report [`Reason::NoOwner`], or
//! [`Reason::StateInUse`] while an owner in another runtime folder, or an
//! exclusive run, holds the state folder's [guard](Guard) so that `start`
//! couldn't own.
//!
//! A launch on Linux finds the owner only if both see the same folder.
//! Root's folder is fixed, so a service that runs as root meets root's
//! launches as it is, unless its unit makes `/run` read-only, as
//! `ProtectSystem=strict` does; then give it
//! `RuntimeDirectory=instance-handoff`. A root daemon started by hand
//! from `sudo`, or from `su` on Linux, counts as raised and doesn't own by
//! default: start it through systemd, which gives services no login user
//! id, or set [`ElevatedOwner::Allow`], as OpenRC and SysV init scripts
//! run from `sudo` need.
//!
//! For a long-running owner of another user that starts outside a login
//! session:
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
//!   `/run/user/<uid>` (toolbox does) meets the host's owner of a state
//!   folder in the `$HOME` they share, which is usually what you want. Both
//!   must resolve the state folder to the same path. But paths outside the
//!   shared mounts may name other files there. A container without systemd
//!   uses its own `/tmp`, and root in a container usually its own `/run`,
//!   so its launches and the host's can't reach each other's owner.
//!   On a local disk, whichever owns a state folder they share first holds
//!   its guard, and the other's launches run alone with
//!   [`Reason::StateInUse`]. On a network file system neither takes the
//!   guard, so each owns (see [`Guard::Local`]). To have them meet
//!   instead, pass the bind-mounted folder to [`Builder::dir`] in both,
//!   with a state folder both see at one path. For one owner per
//!   container, give the launches in each container, and the host's, a
//!   [scope](Builder::scope) of their own, such as the container's name:
//!   owners with scopes share the guard, so the app must keep their writes
//!   to the state safe.
//! - User namespaces: root in one (rootless Podman, `bwrap --uid 0`) is
//!   the user on the host, but root to this crate. It owns in
//!   `/run/instance-handoff` in its own `/run`, and the user's folders are
//!   its own. In any user namespace, Flatpak's too, the folders of users
//!   it doesn't map, host root's among them, show as the overflow user
//!   (`nobody`), which counts as another user: a state folder there gives
//!   [`Reason::ForeignState`], and so does a missing one whose nearest
//!   folder is there, as in a `/tmp` shared with the host.
//! - Windows: mapped drives and `SUBST` letters belong to one logon
//!   session, and every logon session of a user (a second RDP session, an
//!   OpenSSH login, a scheduled task, or the one a launch run as
//!   administrator has with UAC on) finds the same owner, at any integrity
//!   level from medium up: a process that a sandbox confines takes no
//!   part. Hand off canonical paths when that matters.
//!
//! # Windowed apps
//!
//! Only a launch that can show windows becomes the owner of a
//! [windowed](Kind::Windowed) app: an owner without a display couldn't
//! open the windows its launches ask for. A launch that can't, as from
//! `ssh`, cron or a system service, hands off to the owner if one is
//! running, and otherwise runs alone at once, with [`Reason::MayNotOwn`].
//! Where it has no runtime folder to look in, it looks at the state
//! folder's [guard](Guard) as [`Builder::hand_off`] does, and runs alone
//! with [`Reason::StateInUse`] where `hand_off` would fail with it.
//! On Linux, the BSDs and illumos a launch can show windows when
//! `WAYLAND_DISPLAY` or `DISPLAY` is set and not empty, and on macOS when
//! its login session has graphic access. On Windows it can unless it runs
//! in session 0, as services and OpenSSH logins do, or on a window station
//! that isn't visible. Elsewhere, and on macOS or Windows when that can't
//! be told, every launch counts as able. A [headless](Kind::Headless)
//! app's launches need no display to own. So where tests run without a
//! display, a windowed app's tests can't own: see [The state](#the-state)
//! for what to do.
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
//! - the folder rule above, and the instance folder's name: `i-` and 16
//!   lowercase hex digits of the FNV-1a 64 hash of the state folder, as
//!   [`State::dir`] resolves it, then the scope. Each is written as
//!   `tag u8 | length u32 LE | bytes` (tag 1 for the state, 2 for the
//!   scope), and left out when there is none. A path or a scope is its
//!   bytes on Unix, and the WTF-8 of its UTF-16 on Windows. On Windows
//!   each integrity level's address folder in the instance folder is `run`
//!   at medium, and `run-low`, `run-high`, `run-system`, or else `run-` and
//!   the level's RID in lowercase hex at the others;
//! - the lock: `instance.lock` in the instance folder. On Unix,
//!   `flock(LOCK_EX | LOCK_NB)` on it, held per open file, inherited across
//!   `fork`, and released when the last copy closes. On Windows, where
//!   every integrity level locks the same file, exclusive `LockFileEx`
//!   locks on two bytes of it, through one handle: byte 0, which is owning,
//!   then the byte at the owner's integrity level's RID (0x2000 at medium),
//!   which marks its level. An owner that can't take its marker gives byte
//!   0 back. Closing the handle releases both;
//! - the guard: `.instance-handoff.lock` in the state folder, never
//!   written. On Unix, `flock(LOCK_EX | LOCK_NB)` on it, or
//!   `flock(LOCK_SH | LOCK_NB)` for an owner with a scope, held as the lock
//!   is. On Windows, a `LockFileEx` lock on one byte of it, at 2^31
//!   (0x80000000), exclusive, or shared for an owner with a scope, released
//!   when the handle closes. A launch with no runtime folder to look in
//!   takes it for a moment, in the mode an owner of its scope would, and
//!   gives it back at once, with `LOCK_UN` or `UnlockFileEx`. So a launch
//!   that would take it, and finds it held, looks again for 50 ms, and a
//!   Unix owner that locks a replaced guard file again, for 250 ms;
//! - the address. On Unix, `instance.sock` beside the lock. When that path
//!   is too long for a socket address, Linux reaches it through
//!   `/proc/self/fd`; otherwise, and on other Unixes, it uses
//!   `<base>/<hash>.sock`, where the base is the per-user temporary folder
//!   on macOS, root's own folder (`/run/instance-handoff` on Linux,
//!   `/var/run/instance-handoff` on the BSDs and illumos) for root, and
//!   `/tmp/ih-<uid>` elsewhere, and the hash is 16 hex digits of the
//!   FNV-1a 64 hash of the folder's device and inode (each a little-endian
//!   u64). On Windows, a named pipe
//!   `\\.\pipe\instance-handoff.<id>.<secret>`, where the secret is 32
//!   random lowercase hex digits, published as `<id> <secret>` and a
//!   newline in `instance.pipe` in the address folder of the owner's level;
//! - the exchange. The owner sends HELLO (its app id and kind, the protocol
//!   versions it speaks, a random nonce, its payload version, whether it
//!   serves, on Windows its integrity level, its state folder and scope,
//!   and its features). The state folder and scope are the bytes the
//!   instance folder's name is hashed from, compared byte for byte, so a
//!   launch tells apart the owner of another state whose hash collides
//!   with its own. The launch checks it all and sends REQUEST. The owner
//!   answers READY. The launch, if still inside its timeout, sends COMMIT,
//!   and only then does the owner call the handler and send REPLY. An
//!   owner that refuses a launch never just closes the connection: it
//!   sends REPLY with the cause at once, in place of READY, or in place of
//!   HELLO when an owner on Unix refuses the launch's user. An owner on
//!   Windows refuses a launch at another integrity level with its own level
//!   in the REPLY, before it decodes the payload, unless the launch is
//!   above it and its REQUEST carries the critical HAND_DOWN record, its
//!   consent to hand the request down. The record names the rights given
//!   up, but the owner reads them from the launch's token. Feature bit 0
//!   in HELLO says an owner never just closes, and every owner of this
//!   release sets it. A launch reads a cause it doesn't know as a decline,
//!   and a close before HELLO as a sign to try again. Every message is
//!   `"IHND" | kind u8 | length u32 LE | records`, and a record is
//!   `tag u8 | length u32 LE | bytes`. Peers skip records they don't know,
//!   so later releases add to the exchange without breaking it, unless the
//!   tag's high bit is set: such a record is critical, and a peer that
//!   doesn't know it refuses the message.
//!
//! # Not covered
//!
//! - Where the owner runs. A launch hands off to the owner wherever it is,
//!   in another session or on another display of the same user (a second
//!   RDP session, a second X server), where the windows it opens may not
//!   be seen.
//! - Replies beyond "taken": exit codes, output, and waiting until the
//!   owner is done with a request, as `--wait` and `$EDITOR` need.
//! - Sharing state between processes, taking over from a hung owner, and
//!   general IPC.
//!
//! On macOS, Finder and Dock opens reach a running app as Apple Events
//! through its toolkit, not as new launches; feed them to the same channel
//! with [`Request::local`]. On Linux, D-Bus activation reaches the app the
//! same way, if it registers for it.

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
mod state;
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

pub use builder::{Builder, ElevatedOwner, Guard, State};
pub use id::{AppId, InvalidAppId, Kind};
pub use level::{Level, Rights};
pub use outcome::{End, Excluded, Exclusive, Ineligible, OwnerInfo, Reason, Started};
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
        send_sync::<Exclusive>();
        send_sync::<Builder>();
        send_sync::<State>();
        send_sync::<Guard>();
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
