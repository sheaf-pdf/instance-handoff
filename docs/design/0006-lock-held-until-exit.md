# 0006. Dropping an owner keeps the lock until the process exits

**Status:** Accepted, 2026-10-18, by the maintainer. Built on `api-0.1`.

## Context

In `sheaf-instance`, dropping the `Owner` freed the lock at once, contrary to its own docs. A test confirmed it. Code like `if let Started::HandedOff(_) = start(..)`, `let _ = start(..)` or `matches!(start(..), ..)` drops the owner value on the spot, and `#[must_use]` doesn't catch any of those forms. Each one silently gave up ownership, and the next launch became a second owner.

## Decision

Dropping a `Claim` or an `Owner` stops serving, but keeps the lock until the process exits. `release()` gives the lock up explicitly.

## Why

These mistakes are easy to make and hard to see. With the lock held, a mistake produces a deaf owner: later launches are declined or time out and run alone, which is visible and safe. A freed lock instead produces a second owner, which corrupts state silently.

## Consequences

- A process that really wants to step down must call `release()`.
- The lock is held per open file and is inherited across `fork`. A forked child that drops its copy must not release the parent's lock: the drop sees it is a forked copy and touches nothing. No test covers this yet.
