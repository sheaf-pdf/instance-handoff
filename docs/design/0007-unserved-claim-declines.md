# 0007. A claim dropped without serving declines launches

**Status:** Proposed, 2026-10-18. Built on `api-0.1`; awaiting maintainer review.

## Context

Between `start` and `serve`, launches wait, so an owner can build its event loop without turning them away ([0002](0002-decide-then-serve.md)). If the app drops the `Claim` without ever serving, perhaps on an early-return error path, the lock is still held ([0006](0006-lock-held-until-exit.md)), and every later launch would wait out its full timeout before running alone.

## Decision

A `Claim` dropped without `serve` or `decline_all` declines later launches at once, and logs a warning.

## Why

Otherwise a mistake stalls every launch for the full timeout, with no message. Declining sends those launches to `Started::Alone` immediately, with a reason, and the warning names the cause.

## Consequences

An app that deliberately runs as owner without serving, such as a debug run that must not take the user's requests, should call `decline_all()` to say so.
