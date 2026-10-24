# 0002. Decide before the event loop exists, serve after

**Status:** Accepted in part, 2026-10-18, by the maintainer. Built on `api-0.1`. Accepted: the shape, meaning `start`, `Claim`, `serve`, a handler that only forwards, and non-exhaustive `Reason` and `End`. The `Builder`'s arguments follow [0015](0015-state-keyed-identity.md), built on `migrate-to-0015` (2026-10-20): `Builder::new` takes the state, and `exclusive()` replaces `Mode`. [0018](0018-own-or-run-alone.md) adds `try_own()`, built on `alpha-2` (2026-10-24).

## Context

A launch should know whether it owns before it opens a window, starts a GPU context or builds a runtime: a launch that will hand off shouldn't flash a window. But the owner can only deliver requests once there is somewhere to send them, such as an event loop proxy or a channel drained by a task, and that exists only after the loop is built.

`sheaf-instance` took five positional arguments, exposed `futures` and `serde` types in its API, and had exhaustive enums and public fields, so it couldn't grow without breaking.

## Decision

- `Builder::new(id, state)`, configured with `scope`, `dir`, `guard`, `elevated_owner`, `hand_down`, `timeout` and `payload_version`, ends in `start(&payload)`, `hand_off(&payload)`, `probe()` or `exclusive()`. `exclusive()`, which holds the state for batch work and serves nothing, replaces `Mode::Separate` ([0015](0015-state-keyed-identity.md)).
- `start` returns `Started::{Owner(Claim), HandedOff(OwnerInfo), Alone(Reason)}` and starts no thread.
- A `Claim` holds the lock and the listening socket. `serve(handler)` or `decline_all()` turns it into an `Owner`. Launches that arrive in between wait.
- The handler runs on the crate's one thread and only forwards: `FnMut(Request) -> Answer`, or `-> bool`, so `tx.send(r).is_ok()` is a complete handler.
- `Reason` and `End` are `#[non_exhaustive]` enums with struct variants, so variants can gain fields later.

## Why

The pre-release review had three API designs written as stubs, then ported real host code onto each: a std CLI, a tokio service, winit, eframe/egui and sheaf on GPUI. Everything but GPUI went through `cargo check` and clippy; GPUI was checked on paper.

- "Typed and toolkit-friendly", the base of this decision, was the only design that was clean in every host, because delivery attaches after `start`.
- "Minimal and std-first" was the simplest, but awkward under winit, and it resisted misuse less.
- "Learn from prior art" contributed the wire versioning, the activation tokens and the owner's pid.

The typed design lost points for its weight and for having two ways to serve. The recommendation kept its shape and made `serde` optional.

## Consequences

- Only the owner path has a second step, and nothing slow may come between `start` and `serve`, since later launches wait for it.
- Quitting under winit needs about 25 lines of host code to handle a request taken just before `stop()`. A pause with a fence is a candidate for 0.2.
