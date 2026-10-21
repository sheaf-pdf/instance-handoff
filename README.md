# instance-handoff

Make your program single-instance, whatever it's built with: GPUI, winit, egui, a tokio service or a plain CLI.

The first launch takes a lock in a private, per-user runtime folder and becomes the *owner*: the one process that keeps your app's state. Every later launch connects to the owner, hands over its request (its arguments and working directory, or any payload you define), gets an answer, and exits. The lock's folder is named after the folder your app keeps its state in, so launches that name one state folder meet one owner, and launches that name two get two. The OS releases the lock when the owner exits, crash included, so there's never a stale lock to clean up. Only the same user can connect, and when a launch can't hand over, it tells you why.

```rust
use instance_handoff::{AppId, Args, Builder, Reason, Request, Started, State};

const APP: AppId = AppId::windowed("org.example.Viewer");

fn main() {
    let args = Args::from_env();
    // The folder the viewer keeps its state in, from your storage code.
    let viewer = Builder::new(APP, State::dir(data_dir()));
    // Decide first, before any window, event loop or runtime exists.
    let claim = match viewer.start(&args) {
        Started::Owner(claim) => claim,
        Started::HandedOff(_) => return, // the owner has it; exit
        Started::Alone(reason) => {
            // On Windows, from an administrator terminal, with a normal
            // viewer running: hand the request down only if the user agrees.
            if let Reason::MoreRights { owner, rights, .. } = &reason {
                let open = format!("Open in the running viewer ({owner}), without {rights}?");
                if ask(&open) && viewer.clone().hand_down(true).hand_off(&args).is_ok() {
                    return;
                }
            }
            // Run without the state, which only the owner writes.
            eprintln!("{reason}");
            return view_alone(args);
        }
    };
    let (tx, rx) = std::sync::mpsc::channel();
    let owner = claim.serve(move |request| tx.send(request).is_ok());
    for request in std::iter::once(Request::local(args)).chain(rx) {
        // request.payload(), request.cwd(), request.resolve(path), …
    }
    drop(owner);
}
```

## Status

0.1.0-alpha.1 is an alpha. The API was reworked from sheaf's `sheaf-instance` after a pre-release review, then reworked again around the app's state ([0015](docs/design/0015-state-keyed-identity.md)), and it's published so that sheaf can move to it. Until 0.1.0, an alpha may change the API, and even what two builds share ([0009](docs/design/0009-contract-between-builds.md)), where sheaf's move shows it must; the changelog says when. 0.1.0 follows once sheaf has moved and the maintainers have reviewed the API.

Cargo counts a later alpha as compatible, so pin the one you build against:

```toml
instance-handoff = "=0.1.0-alpha.1"
```

CI runs the tests on Linux, macOS and Windows, on Windows at high and at medium integrity. Its Windows runner is an administrator with UAC off, so no launch there has a split token, and the Windows layout was also checked by hand on a machine with UAC on ([measurements](docs/design/0015-windows-measurements.md)).

## How it works

- **The lock decides the owner.** `flock` on `instance.lock` (Unix) or `LockFileEx` (Windows), in a per-user runtime folder. Dropping the `Owner` by mistake never frees it: only `release()` or the process's exit does.
- **One owner per state.** The runtime folder is named after a hash of the state folder, with its links resolved, and of an optional scope. The owner also holds a guard: a lock on `.instance-handoff.lock` in the state folder. So a launch that took its lock in another runtime folder (in another container, say) runs alone with `StateInUse` rather than own the state too. Use `Guard::Off` for a folder that a sync tool copies between machines. Your app must never replace or rename the state folder, though it may replace the files in it. Batch work, such as a migration, holds the state with `exclusive()` and serves nothing.
- **Deciding and serving are separate.** `start` decides before your event loop exists and starts no thread. `Claim::serve` attaches a handler once there is somewhere to send requests; launches arriving in between wait.
- **A launch commits.** The owner greets each connection (HELLO: app id and kind, versions, state folder). The launch sends its request, the owner answers READY, and the launch commits only if it is still within its timeout. Only then is the handler called. So a launch that gave up and ran on its own is never also delivered, whether the owner was suspended, slow or killed.
- **Any payload.** `Args` carries argv losslessly, non-UTF-8 included, plus the launch's working directory and its activation tokens (`XDG_ACTIVATION_TOKEN`, `DESKTOP_STARTUP_ID`). Implement `Payload` for your own type, or use `Json<T>` with the `serde` feature.
- **Never more rights, and fewer only if you say so.** A request never runs with more rights than its launch had, and never goes to another user. It runs with fewer only when your app hands it down (`Builder::hand_down`), as the example does once the user agrees. On Unix, root is another user, with an owner of its own, and both ends check the peer's uid.
- **On Windows, one lock for every level.** Every integrity level from medium up shares one lock per state, so a launch run as administrator meets the normal owner, and runs alone at once with `MoreRights` unless it hands its request down. The owner marks its level in its lock and checks each launch's token. Its pipe has a random name, an access list for the user alone and an integrity label, and the name is published in a folder labelled at the owner's level. The launch checks the pipe against the level the owner's lock shows: its own, or a lower one it hands down to.
- **Raised launches don't own by default.** A launch whose rights were raised from a login (`sudo`, `run0`, `pkexec`, `doas`, and on Linux `su`; on Windows, Run as administrator with UAC on) hands off to an owner at its level, but doesn't become one: with no owner running, it runs alone at once with `MayNotOwn`. `Builder::elevated_owner` sets who may: `ElevatedOwner::Allow` lets them own, and under `ElevatedOwner::NotAboveNormal` no root launch owns, nor any Windows launch above medium integrity except at the UIAccess level. A setuid or setgid program that runs with its rights takes no part: it gets `Excluded` at once. On Windows, a sandboxed process (below medium integrity, in an AppContainer, or with a restricted token) gets `Excluded` too.
- **Windowed or headless.** An app id has a kind. Only a launch that can show windows owns a windowed app: one from `ssh`, cron or a service hands off, or runs alone with `MayNotOwn`. A headless app's launches, such as a daemon's, need no display to own. So without a display, as on most CI runners, a windowed app's tests can't own: give them a headless app id, or run them under Xvfb.
- **One right folder.** Each launch has exactly one runtime folder, `i-` and a hash in the app's folder, and never falls back to another, so two launches of one user can't end up with two owners. On Linux outside Flatpak and snap, the app's folder is `/run/user/<uid>/<id>` with systemd, and `/run/instance-handoff/<id>` for root, whether or not root is logged in. A launch with no session (cron, `@reboot`) that may own runs alone with `Reason::NoSession` instead of guessing. `hand_off` and `probe` there report `NoOwner`, or `StateInUse` while another process holds the state folder's guard so that `start` couldn't own.

The crate docs have the full guarantees, the state and recipes for it, the folder rule for each platform, privileges, the protocol, and notes on daemons, containers and quitting. [docs/design](docs/design) records why each of these was chosen over the alternatives.

## With an event loop

Start before the loop exists, then serve once the loop can be woken. The handler runs on the crate's thread, so it only forwards:

```rust
// winit 0.30
let event_loop = EventLoop::<UserEvent>::with_user_event().build()?;
let proxy = event_loop.create_proxy();
let ended = proxy.clone();
let owner = claim
    .on_end(move |end| drop(ended.send_event(UserEvent::Ended(end))))
    .serve(move |r| proxy.send_event(UserEvent::Launch(r)).is_ok());
```

```rust
// GPUI, or any async executor: a futures channel drained by a task
let (tx, mut rx) = futures::channel::mpsc::unbounded();
let owner = claim.serve(move |r| tx.unbounded_send(r).is_ok());
cx.spawn(async move |cx| {
    while let Some(request) = rx.next().await {
        cx.update(|cx| open(request, cx)).ok();
    }
})
.detach();
```

[`examples/cli.rs`](examples/cli.rs) is a daemon that keeps notes in a folder under `HOME` (`LOCALAPPDATA` on Windows), with `add`, `status`, `stop` and `migrate` commands. [`examples/tokio.rs`](examples/tokio.rs) is a tokio service.

## Other crates

As of October 2026:

- [single-instance](https://crates.io/crates/single-instance) only tells you another instance exists. On Linux it uses an abstract socket, which every user on the machine shares.
- [tauri-plugin-single-instance](https://crates.io/crates/tauri-plugin-single-instance) is the right choice inside Tauri, and only there. Arguments arrive as lossy strings, and nothing comes back to the second launch.
- [single-application](https://crates.io/crates/single-application), [existing_instance](https://crates.io/crates/existing_instance) and [app-single-instance](https://crates.io/crates/app-single-instance): whoever binds a socket name first wins, and the name is one that every user shares, so one user's launch can reach another user's process. None replies, checks the user, or limits sizes.
- `gio::Application` from [gtk-rs](https://gtk-rs.org) is the API this crate learns most from (open, remote command line), but it needs GLib and a D-Bus session bus.
- [interprocess](https://crates.io/crates/interprocess), [named-lock](https://crates.io/crates/named-lock) and [fd-lock](https://crates.io/crates/fd-lock) are good building blocks. instance-handoff is the whole protocol on top.

## Development

The checks are recipes in the [justfile](justfile), run with [just](https://github.com/casey/just):

```sh
just          # list the recipes
just ci       # run everything CI runs on Linux
just windows  # or one at a time
```

`just windows` lints the Windows code from Linux and needs `rustup target add x86_64-pc-windows-gnu`. `just targets` checks the other platforms and needs their targets added too. `just msrv` needs the oldest supported Rust installed. Some tests need `fakeroot`, a `bubblewrap` that can make user namespaces, or a second group of yours (for a setgid copy of the test binary), and skip with a message without them. CI runs the recipes on Linux, and clippy and the tests on macOS and Windows. On Windows it also runs the tests at medium integrity (`just test-medium`) and the probe in `just levels`.

## License

Licensed under either of Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)) or MIT license ([LICENSE-MIT](LICENSE-MIT)) at your option.
