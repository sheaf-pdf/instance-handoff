# Changelog

## Unreleased

The first release as a crate of its own, reworked from sheaf's `sheaf-instance` after a pre-release review. On Linux with systemd and on Windows, a build that uses this release with the app id `sheaf` meets builds that use `sheaf-instance` on the same lock; their handoffs to each other fail safely, and the launch runs alone after its timeout. Elsewhere (macOS, Linux without systemd, Flatpak) the folder moved, so during an upgrade an old and a new build can each be an owner until the old one quits.

- **API.** `Builder` (app id, scope, folder, mode, timeout, payload version) ends in `start`, `hand_off` or `probe`. `start` returns `Started::{Owner(Claim), HandedOff(OwnerInfo), Alone(Reason)}`, and a `Claim` is served with a handler (`claim.serve(|r| tx.send(r).is_ok())`) once the app has somewhere to send requests. No `futures` or `serde` in the public API.
- **Payloads.** The `Payload` trait, implemented for `Args` (argv, lossless), `Vec<u8>`, `String`, `()`, and `Json<T>` with the `serde` feature. The launch's working directory and activation tokens travel beside every payload.
- **No duplicate delivery.** A launch commits its request only inside its timeout, and the owner calls the handler only after the commit. So a launch that ran alone is never also delivered, even when the owner was suspended, slow or killed.
- **Concurrent serving.** One thread serves every connection at once, so a silent or slow client delays nobody.
- **Lifecycle.** Dropping an `Owner` or a `Claim` keeps the lock until the process exits; `release()` frees it. `stop()` wakes the thread at once and drops the handler. `on_end` and `Owner::ended` report `Stopped`, `Panicked` or `LostLock`.
- **Reasons.** `Reason` is an error enum with a variant for every outcome, and every variant can gain fields later.
- **Folders.** One right folder per launch, never a fallback: `/run/user/<uid>/<id>` on Linux with systemd (otherwise `Reason::NoSession`), `/tmp/<id>-<uid>` without systemd and on the BSDs, the per-user temporary folder on macOS, Local AppData on Windows. The owner re-creates its lock if the folder is deleted, and touches its files so that cleaners leave them alone.
- **Privileges.** A launch hands off only to an owner of its own user at its own privilege level, so a request never runs with more or fewer rights than its launch had. Each level has its own owner: root on Unix, and on Windows each integrity level, in a folder of its own (`<id>\run` at medium, `<id>\run-high` when run as administrator). An elevated launch no longer hands off to a normal owner.
- **Windows.** Named pipes replace AF_UNIX through `uds_windows`. The pipe has a random name, a user-only access list and an integrity label. The owner checks the launch's token; the launch checks that the pipe is its user's, at its own integrity level. Runtime folders are created private and labelled at their level. Not yet run on Windows.
- **Platforms.** `flock` and `LockFileEx` are called directly, not through std. Linux, Android, macOS, FreeBSD, NetBSD, illumos and Windows are supported; OpenBSD and DragonFly share the BSD code but aren't checked in CI. Every other target compiles, and launches there run alone with `Reason::Unsupported`.
- **MSRV** 1.85.
