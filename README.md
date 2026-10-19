# instance-handoff

Make your program single-instance, whatever it's built with: GPUI, winit, egui, a tokio service or a plain CLI.

The first launch takes a lock in a private, per-user runtime folder and becomes the *owner*. Every later launch connects to the owner, hands over its request (its arguments and working directory, or any payload you define), gets an answer, and exits. Only one process ever holds the lock, so the owner can keep your app's state to itself. The OS releases the lock when the owner exits, crash included, so there's never a stale lock to clean up. Only the same user can connect, and when a launch can't hand over, it tells you why.

```rust
use instance_handoff::{AppId, Args, Builder, Request, Started, State};

const APP: AppId = AppId::windowed("org.example.Viewer");

fn main() {
    let args = Args::from_env();
    // The folder the viewer keeps its state in, from your storage code.
    let state = State::dir(data_dir());
    // Decide first, before any window, event loop or runtime exists.
    let claim = match Builder::new(APP, state).start(&args) {
        Started::Owner(claim) => claim,
        Started::HandedOff(_) => return, // the owner has it; exit
        Started::Alone(reason) => panic!("{reason}"), // or run without state
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

Not published yet. The API was reworked from sheaf's `sheaf-instance` after a pre-release review, and `Cargo.toml` keeps `publish = false` until:

- the Windows transport (named pipes) has run in CI: it is written and compile-checked from Linux, but no test has run on Windows;
- sheaf has moved to the new API;
- the maintainers have settled the decisions the review left open.

## How it works

- **The lock decides the owner.** `flock` on `instance.lock` (Unix) or `LockFileEx` (Windows), in a per-user runtime folder. Dropping the `Owner` by mistake never frees it: only `release()` or the process's exit does.
- **Deciding and serving are separate.** `start` decides before your event loop exists and starts no thread. `Claim::serve` attaches a handler once there is somewhere to send requests; launches arriving in between wait.
- **A launch commits.** The owner greets each connection (HELLO: app id, versions, state). The launch sends its request, the owner answers READY, and the launch commits only if it is still within its timeout. Only then is the handler called. So a launch that gave up and ran on its own is never also delivered, whether the owner was suspended, slow or killed.
- **Any payload.** `Args` carries argv losslessly, non-UTF-8 included, plus the launch's working directory and its activation tokens (`XDG_ACTIVATION_TOKEN`, `DESKTOP_STARTUP_ID`). Implement `Payload` for your own type, or use `Json<T>` with the `serde` feature.
- **Only the same user, at the same privilege level.** A request never runs with more or fewer rights than its launch had, so root on Unix and an elevated process on Windows each get an owner of their own: run as administrator, a launch never hands off to the normal instance, which lacks those rights. On Unix the runtime folder must be private, and both ends check the peer's uid. On Windows each integrity level has its own folder, labelled at that level; the pipe has a random name published in that folder, an access list for the user alone and an integrity label; the owner checks the launch's token, and the launch checks that the pipe is its own user's at its own level.
- **One right folder.** Each launch has exactly one runtime folder and never falls back to another, so two launches of one user can't end up with two owners. On Linux with systemd it's `/run/user/<uid>/<id>`; a launch with no session (cron, `@reboot`) runs alone with `Reason::NoSession` instead of guessing.

The crate docs have the full guarantees, the folder rule for each platform, the protocol, and notes on daemons, containers and quitting. [docs/design](docs/design) records why each of these was chosen over the alternatives.

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

[`examples/cli.rs`](examples/cli.rs) is a daemon with `status` and `stop` commands, and [`examples/tokio.rs`](examples/tokio.rs) a tokio service.

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

`just windows` lints the Windows code from Linux and needs `rustup target add x86_64-pc-windows-gnu`. `just targets` checks the other platforms and needs their targets added too. `just msrv` needs the oldest supported Rust installed. CI runs the recipes on Linux, and clippy and the tests on macOS and Windows.

## License

Licensed under either of Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)) or MIT license ([LICENSE-MIT](LICENSE-MIT)) at your option.
