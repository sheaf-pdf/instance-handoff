# 0009. What two builds share is frozen at 0.1

**Status:** Accepted in part, 2026-10-18, by the maintainer. Accepted: only a major release of this crate changes what two builds share. What is on that list follows [0015](0015-state-keyed-identity.md), and nothing is frozen until 0.1 ships. With 0015 built (2026-10-20), the list below is complete. The Windows layout went on it only after a run under real UAC ([0015-windows-measurements.md](0015-windows-measurements.md)). The maintainer's call of 2026-10-20: 0.1.0's alphas, from 0.1.0-alpha.1, are published so that sheaf can move to the crate, and may still change the list where that move shows they must; the changelog says when. It's frozen from 0.1.0.

## Context

Two builds of one app can be running at once while they link different releases of this crate. That happens during an upgrade while the old version is still open, and when an app's CLI and GUI ship separately. If those builds disagree about where the lock is or how to talk to each other, each becomes an owner.

## Decision

The crate docs ("The contract between builds") define what builds share, and only a major release of this crate changes it:

- the folder rule, root's fixed folders, the instance folder's name (`i-` and the FNV-1a 64 hash of the state folder and the scope, each framed), and on Windows the names of the integrity levels' address folders (`run`, `run-high` and the rest);
- the lock: `flock(LOCK_EX | LOCK_NB)` on `instance.lock` in the instance folder, or on Windows exclusive `LockFileEx` locks on its byte 0 and on the byte at the owner's level's RID, which marks the level. On Windows `instance.lock` has its own access list and a medium label, so every level can lock it;
- the guard: `.instance-handoff.lock` in the state folder, never written, locked by `flock` or by `LockFileEx` on its byte 2^31, exclusive, or shared for an owner with a scope;
- the address: `instance.sock`, its fallback for long paths, or the named pipe published in `instance.pipe`, the only file in the address folder of the owner's level;
- the exchange and its framing ([0004](0004-commit-point.md)).

Tests pin its names and bytes: the instance folder's name and the framing of its key (`instance_folders_are_frozen`, `a_path_that_isnt_unicode_has_a_frozen_folder_too`, `the_instance_key_frames_each_part`, `fnv1a64_matches_the_reference`), root's folders (`root_bases_are_frozen`), the level folders (`level_folders_are_frozen`), the guard's name (`the_guard_file_is_frozen`), the Windows lock bytes (`the_windows_lock_bytes_are_frozen`), and the bytes of every message (`hello_bytes_are_frozen`, `request_bytes_are_frozen`, `ready_and_commit_bytes_are_frozen`, `reply_bytes_are_frozen`). The crate docs ("The contract between builds") give the full list.

## Why

A changed folder or lock between minor releases would bring back the two-owner failure that [0008](0008-one-folder.md) removes, and only for users in the middle of an upgrade, which makes it hard to notice and to reproduce.

## Consequences

- The wire can grow inside the contract: new record tags are skipped by older peers, and critical tags make an older peer refuse a message it can't honour.
- With [0015](0015-state-keyed-identity.md) the lock moved into the instance folder on every platform, so this release never meets `sheaf-instance` builds. While sheaf upgrades, an old and a new build can each be an owner until the old one quits. The guard doesn't help, since `sheaf-instance` takes none.
