# 0003. A `Payload` trait, lossless `Args` by default

**Status:** Accepted, 2026-10-18, by the maintainer. Built on `api-0.1`.

## Context

`sheaf-instance` sent the launch's paths to the owner as JSON. A path that wasn't UTF-8 couldn't be encoded, so the launch waited out its 3 s timeout and then ran as a second instance. Four reviewers confirmed it. The JSON also put `serde` in the public API.

## Decision

- A `Payload` trait encodes a request to bytes and decodes it back.
- `Args` carries argv without the program name, losslessly: raw bytes on Unix, UTF-16 on Windows.
- `Vec<u8>`, `String` and `()` implement `Payload`, and so does `Json<T>`, behind the `serde` feature.
- The launch's working directory, in native bytes, and its activation tokens (`XDG_ACTIVATION_TOKEN`, `DESKTOP_STARTUP_ID`) travel beside every payload, whatever its type.
- The launch encodes before it connects, so an encoding failure never reaches the owner.
- `Builder::payload_version` goes into HELLO, so builds with incompatible payloads refuse each other at once instead of failing to decode.

## Why

Argv is what most apps hand off, and only raw bytes carry every path. With a trait, apps with structured requests choose their own encoding. Keeping `serde` behind a feature means a new `serde` major version can't break this crate's API.

## Consequences

- An app that changes its payload format bumps `payload_version`. During an upgrade, the old and new builds then refuse each other's handoffs.
- Relative paths are resolved against the launch's working directory (`Request::resolve`), not the owner's.
