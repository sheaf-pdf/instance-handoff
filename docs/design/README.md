# Design decisions

Each file here records one decision about instance-handoff: the problem, what we chose, why, and what it costs. They exist so that a later change can see what the current behaviour was protecting against before undoing it.

The crate docs say what the crate does. These records say why it does that and not something else.

## Status

- **Accepted**: a maintainer decided it.
- **Accepted in part**: a maintainer accepted its principle; the status line says which details wait on another record.
- **Proposed**: recommended by a review and built on the branch, but not yet confirmed by a maintainer.
- **Deferred**: considered and postponed until a stated trigger.
- **Superseded by NNNN**: replaced; kept for its reasoning.

A record's status line gives the date and, for an accepted record, who decided. When a decision changes, add a new record and mark the old one superseded rather than rewriting it, unless the change is only a correction.

## Writing one

Copy the shape of an existing record: a status line, then **Context**, **Decision**, **Why** (including the alternatives turned down) and **Consequences**. Number it with the next free number. State evidence plainly: what was measured, how, and what it showed. Leave the platform facts to the crate docs, and keep here the reasons behind them.

Material that supports a record but is too long for it, such as an API sketch, goes in a file named after the record: `0015-api-sketch.md`.

Decisions about how one app uses the crate, such as sheaf's app id, belong in that app's repository.

## Records

| # | Decision | Status |
|---|---|---|
| [0001](0001-scope.md) | Scope: funnel every launch into one owning process | Accepted |
| [0002](0002-decide-then-serve.md) | Decide before the event loop exists, serve after | Accepted in part (the shape) |
| [0003](0003-payloads.md) | A `Payload` trait, lossless `Args` by default | Accepted |
| [0004](0004-commit-point.md) | The launch commits before the owner delivers | Accepted |
| [0005](0005-replies-later.md) | Replies, exit codes and `--wait` wait for 0.2 | Deferred until 0.2 |
| [0006](0006-lock-held-until-exit.md) | Dropping an owner keeps the lock until the process exits | Accepted |
| [0007](0007-unserved-claim-declines.md) | A claim dropped without serving declines launches | Accepted |
| [0008](0008-one-folder.md) | One right runtime folder, never a fallback | Accepted in part (no fallback) |
| [0009](0009-contract-between-builds.md) | What two builds share is frozen at 0.1 | Accepted in part (frozen by major releases) |
| [0010](0010-lock-primitive.md) | `flock` and `LockFileEx` directly; elsewhere `Unsupported` | Accepted |
| [0011](0011-windows-named-pipes.md) | Named pipes on Windows, with seven controls | Accepted |
| [0012](0012-privilege-levels.md) | Hand off only within one user and privilege level | Superseded by 0015 |
| [0013](0013-root-on-linux.md) | No special case for root or `sudo` on Linux | Superseded by 0015 |
| [0014](0014-process-ids.md) | Process ids come from the OS, never from the peer | Accepted |
| [0015](0015-state-keyed-identity.md) | One owner per state; rights and placement decided separately | Accepted with changes, built |
| [0016](0016-windows-address-file.md) | The Windows owner keeps its address file open | Accepted, built |
| [0017](0017-own-the-transport.md) | Sockets and pipes directly, not through interprocess | Accepted |
| [0018](0018-own-or-run-alone.md) | A launch that owns if nobody does, and otherwise runs alone | Accepted, built |
