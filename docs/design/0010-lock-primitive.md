# 0010. `flock` and `LockFileEx` directly; elsewhere `Unsupported`

**Status:** Proposed, 2026-10-18. Built on `api-0.1`; awaiting maintainer review.

## Context

`sheaf-instance` locked with std's `File::try_lock`. The primitive behind it is std's choice, and it varies with the Rust version and the target. Whether a launch could ever become the owner therefore depended on how it was compiled. The crate also failed to compile on 12 of the 22 targets checked, and required Rust 1.89.

## Decision

- Call `flock(LOCK_EX | LOCK_NB)` on Unix and `LockFileEx` on Windows directly, and never write to the lock file.
- On a target without a lock that this crate trusts (wasm, WASI, Solaris and others), the crate still compiles, every type is usable, and launches return `Reason::Unsupported`.
- The minimum Rust version is 1.85.

## Why

The lock primitive is part of the contract between builds ([0009](0009-contract-between-builds.md)), so it can't be left to std. On the other targets, owning anyway would break the one guarantee, at most one owner. Failing to compile would break apps that share code with a web build.

## Consequences

- Linux, Android, macOS, FreeBSD, NetBSD, illumos and Windows are supported. OpenBSD and DragonFly share the BSD code but aren't checked in CI.
- Adding a platform means adding its folder rule and its peer check, not just a lock.
