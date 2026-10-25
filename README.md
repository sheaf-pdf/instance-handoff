# instance-handoff

Make your program single-instance, whatever it's built with: winit, egui, GPUI, a tokio service or a plain CLI.

The first launch becomes the *owner*. Every later launch hands its request to the owner (its arguments and working directory, or a payload of your own), gets an answer, and exits. Launches meet per user and per state folder, the folder your app keeps its files in.

```rust
use instance_handoff::{AppId, Args, Builder, Request, Started, State};

const APP: AppId = AppId::windowed("org.example.Viewer");

fn main() {
    let args = Args::from_env();
    let claim = match Builder::new(APP, State::dir(data_dir())).start(&args) {
        Started::Owner(claim) => claim,
        Started::HandedOff(_) => return, // the owner has it; exit
        Started::Alone(reason) => {
            // This launch may neither hand off nor own, and the reason says
            // why. Run without writing the state: only the owner does.
            eprintln!("{reason}");
            return view_alone(args);
        }
    };
    let (tx, rx) = std::sync::mpsc::channel();
    let owner = claim.serve(move |request| tx.send(request).is_ok());
    // This launch's own request first, then every later launch's.
    for request in std::iter::once(Request::local(args)).chain(rx) {
        // request.payload(), request.cwd(), request.resolve(path), …
    }
    drop(owner);
}
```

## Install

```sh
cargo add instance-handoff@=0.1.0-alpha.2
```

This is an alpha. Until 0.1.0, an alpha may change the API, and how two builds of your app find each other; the [changelog](CHANGELOG.md) says when. Cargo treats a later alpha as compatible, so pin the version with `=`. The `serde` feature adds `Json<T>`, for any serde type as a payload.

## What it guarantees

- **One owner per user and state.** Launches that name one state folder meet one owner, and launches that name two get two. On a local disk, a lock in the state folder keeps out a second owner, even from another container.
- **No stale locks.** The OS releases the lock when the owner exits, crash included. Dropping the `Owner` by mistake never frees it.
- **Delivered once or not at all.** A launch commits its request only inside its timeout, so a launch that gave up and ran on its own is never also delivered, even if the owner was suspended or slow.
- **Lossless payloads.** `Args` carries argv (non-UTF-8 included), the working directory and the activation tokens that let the owner raise its window. Implement `Payload` for a type of your own.
- **Never more rights.** Only the same user connects. A request never runs with more rights than its launch had, and with fewer only if your app hands it down. A launch raised with `sudo` or Run as administrator doesn't become the owner unless you allow it.
- **Decide first, serve later.** `start` runs before any window, event loop or runtime exists, and starts no thread. `Claim::serve` attaches a handler once there is somewhere to send requests.
- **A reason for every outcome.** A launch that neither hands off nor owns gets a `Reason`, at once wherever waiting can't help.

A windowed app is owned only by a launch that can show windows. Give tests and daemons a headless app id (`AppId::headless`), or run tests under Xvfb.

The [crate docs](https://docs.rs/instance-handoff) cover the rest: the state folder, the folder rule on each platform, privileges, daemons, containers, quitting, and what two builds of an app share.

## With an event loop

The handler runs on the crate's thread, so it only forwards. With winit 0.30:

```rust
let event_loop = EventLoop::<UserEvent>::with_user_event().build()?;
let proxy = event_loop.create_proxy();
let owner = claim.serve(move |r| proxy.send_event(UserEvent::Launch(r)).is_ok());
```

With an async executor, send to an unbounded channel and drain it in a task. [`examples/cli.rs`](examples/cli.rs) is a daemon with `status`, `stop` and `migrate` commands, and [`examples/tokio.rs`](examples/tokio.rs) is a tokio service.

## Platforms

Linux, Android, macOS, FreeBSD, NetBSD, illumos and Windows. OpenBSD and DragonFly share the BSD code but aren't checked in CI. Every other target compiles, and launches there run alone with `Reason::Unsupported`. The minimum Rust version is 1.85.

## Other crates

As of October 2026:

- [single-instance](https://crates.io/crates/single-instance) only tells you another instance exists. On Linux it uses an abstract socket, which every user on the machine shares.
- [tauri-plugin-single-instance](https://crates.io/crates/tauri-plugin-single-instance) is the right choice inside Tauri, and only there. Arguments arrive as lossy strings, and nothing comes back to the second launch.
- [single-application](https://crates.io/crates/single-application), [existing_instance](https://crates.io/crates/existing_instance) and [app-single-instance](https://crates.io/crates/app-single-instance): whoever binds a socket name first wins, and every user shares the name, so one user's launch can reach another user's process.
- `gio::Application` from [gtk-rs](https://gtk-rs.org) handles opens and remote command lines well, but needs GLib and a D-Bus session bus.
- [interprocess](https://crates.io/crates/interprocess), [named-lock](https://crates.io/crates/named-lock) and [fd-lock](https://crates.io/crates/fd-lock) are building blocks; instance-handoff is the whole protocol on top.

## Development

The checks are [just](https://github.com/casey/just) recipes:

```sh
just          # list the recipes
just ci       # run everything CI runs on Linux
```

Some tests need `fakeroot`, a `bubblewrap` that can make user namespaces, or a second group of yours, and skip with a message without them. [docs/design](docs/design) records why the crate works as it does.

## License

Licensed under either of Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)) or MIT license ([LICENSE-MIT](LICENSE-MIT)) at your option.
