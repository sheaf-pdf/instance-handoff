# 0009. What two builds share is frozen at 0.1

**Status:** Accepted in part, 2026-10-18, by the maintainer. Accepted: only a major release of this crate changes what two builds share. What is on that list follows [0015](0015-state-keyed-identity.md), and nothing is frozen until 0.1 ships.

## Context

Two builds of one app can be running at once while they link different releases of this crate. That happens during an upgrade while the old version is still open, and when an app's CLI and GUI ship separately. If those builds disagree about where the lock is or how to talk to each other, each becomes an owner.

## Decision

The crate docs ("The contract between builds") define what builds share, and only a major release of this crate changes it:

- the folder rule, the scope subfolder's name, and on Windows the names of the integrity-level folders;
- the lock: `flock(LOCK_EX | LOCK_NB)` on `instance.lock`, or an exclusive `LockFileEx` on its first byte;
- the address: `instance.sock`, its fallback for long paths, or the named pipe published in `instance.pipe`;
- the exchange and its framing ([0004](0004-commit-point.md)).

Tests pin some of it: the scope and level folder names (`scope_folders_are_frozen`, `level_folders_are_frozen`) and the bytes of HELLO (`hello_bytes_are_frozen`). The other messages have no such test yet.

## Why

A changed folder or lock between minor releases would bring back the two-owner failure that [0008](0008-one-folder.md) removes, and only for users in the middle of an upgrade, which makes it hard to notice and to reproduce.

## Consequences

- The wire can grow inside the contract: new record tags are skipped by older peers, and critical tags make an older peer refuse a message it can't honour.
- With the app id `sheaf`, this release meets `sheaf-instance` builds on the same lock on Linux with systemd and on Windows. Their handoffs to each other fail safely, and the launch runs alone after its timeout. Elsewhere the folder moved, so an old and a new build can each be an owner until the old one quits.
