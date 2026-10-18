# instance-handoff

One instance of an app per user on each machine. The first launch takes a lock and becomes the *owner*. A later launch connects to the owner's socket, hands over the files it was given, and exits.

## Status

Not published, and not yet generic. `src/lib.rs` is an unchanged copy of `crates/sheaf-instance` from [sheaf](https://github.com/sheaf-pdf/sheaf) at commit `468aaf1`, so it still says "sheaf" in places, and `Cargo.toml` has `publish = false` until that's fixed. The plan before a first release:

- **App name.** "sheaf" is written into the runtime folder (`default_dir`), the fallback socket's name, the listener thread's name and the reasons `Started::Standalone` gives. Take an app id instead.
- **Payload.** `Request` carries absolute paths and the Wayland activation token, nothing else. Make it generic, with a ready-made type for argv plus the working directory.
- **Versions.** `PROTOCOL` versions both the wire format and sheaf's request. Split them, so a new release of the crate doesn't refuse handoffs between two builds of the same app.
- **Delivery.** Requests go to a `futures` `UnboundedSender`. Take a callback that accepts a request or says it's busy, which suits std channels, tokio, winit's `EventLoopProxy` and GPUI alike.
- **Reasons.** `Started::Standalone(String)` becomes an enum.
- **Shutdown.** `Owner::stop` removes the socket, but the listener thread runs until the process exits. Stop it when the `Owner` drops.
- **Tests.** They run on Unix only, and there's no peer check on Windows.
- **Smaller things.** A request that doesn't parse gets no reply, so the launch waits out its timeout. The fallback socket for a long folder path goes in the shared temp folder under a name others can predict. The crate docs point at sheaf's `todos/m9.md`.
- **To decide:** AF_UNIX on Windows through `uds_windows` (one code path; Windows 10 1803 or later; no peer check), or named pipes (the usual choice there, and they can check the client's user).

## How it works

- **The lock decides the owner.** The owner holds `instance.lock` in a per-user runtime folder, taken with `File::try_lock`. The OS releases it when the owner exits, crash included, so a lock is never stale and there's no guessing about leftover sockets. The lock file holds the owner's process id.
- **The socket only carries requests.** `instance.sock` sits beside the lock, or under a hashed name in the temp folder when the path is too long for a socket address. It's AF_UNIX on every platform; on Windows through `uds_windows`.
- **One line each way.** A launch writes its request as a JSON line, and the owner answers *ok*, *retry* (it's quitting, or not ready) or *refused* (another protocol version). The owner replies as soon as the request is queued, so a busy window never keeps a launch waiting. Requests are capped at 1 MiB.
- **Only the same user.** On Unix the runtime folder must be a folder, not a symlink, owned by the user and writable by no one else, group included, and both ends check the peer's user id (`SO_PEERCRED`, or `getpeereid` off Linux).
- **Where the folder is.** `$XDG_RUNTIME_DIR/sheaf` on Linux and the BSDs (`/tmp/sheaf-<uid>` without one), `$TMPDIR/sheaf` on macOS, `%LOCALAPPDATA%\sheaf\run` on Windows. Never the config folder, which on Windows roams and may be on a network share, where sockets don't work and a lock would span machines.
- **Two ways to launch.** `Mode::Join` becomes the owner or hands its files over, trying again until a deadline when the owner doesn't answer. `Mode::Separate` becomes the owner if nobody is and otherwise runs alone, for scripts, tests and `--new-instance` flags.
- **Raising the window.** A launch was just started by the user, so it may bring a window forward, and the owner otherwise may not. On Windows the launch calls `AllowSetForegroundWindow` before handing off. On Wayland it passes `XDG_ACTIVATION_TOKEN` along for the owner to use.

## Other crates

As of October 2026:

- [single-instance](https://crates.io/crates/single-instance) only detects a running instance.
- [tauri-plugin-single-instance](https://crates.io/crates/tauri-plugin-single-instance) hands off, for Tauri apps only.
- [single-application](https://crates.io/crates/single-application), [existing_instance](https://crates.io/crates/existing_instance) and [app-single-instance](https://crates.io/crates/app-single-instance) pass a message over an [interprocess](https://crates.io/crates/interprocess) local socket. The socket decides which process is the owner, so there's no lock file. None has a reply built in, and none checks which user connected.
- `gio::Application` from [gtk-rs](https://gtk-rs.org) hands off over D-Bus, for GLib apps.

## Development

The checks are recipes in the [justfile](justfile), run with [just](https://github.com/casey/just):

```sh
just          # list the recipes
just ci       # run everything CI runs on Linux
just windows  # or one at a time
```

`just windows` lints the Windows code from Linux and needs `rustup target add x86_64-pc-windows-gnu`. `just msrv` needs Rust 1.89 installed. CI runs the recipes on Linux, and clippy and the tests on macOS and Windows.

## License

Licensed under either of Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)) or MIT license ([LICENSE-MIT](LICENSE-MIT)) at your option.
