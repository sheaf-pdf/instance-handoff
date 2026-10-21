# 0001. Scope: funnel every launch into one owning process

**Status:** Accepted, 2026-10-18, by the maintainer. Built for 0.1, 2026-10-20, with [0015](0015-state-keyed-identity.md).

## Context

instance-handoff was extracted from sheaf's `sheaf-instance` to be published on its own. Inside sheaf it only had to work with GPUI on the desktops sheaf supports. On its own it has to suit any program that wants to be single-instance.

## Decision

The crate funnels every launch of a program into a single process, the owner, which then keeps the program's state to itself. It is usable from any GUI toolkit, or with no GUI at all: a CLI, a daemon, a tokio service.

In scope:

- deciding, at each launch, whether this process owns, hands off, or has to run alone, and saying why;
- carrying a launch's request to the owner losslessly and exactly once, or not at all;
- deciding which launches count as the same instance (since [0015](0015-state-keyed-identity.md), the same app, user, state folder and scope), correctly across the ways programs get launched: terminals, desktops, `sudo`, SSH, remote desktops, services, CI, containers.

Out of scope, for now or for good:

- general IPC, and shared state between processes;
- replies beyond "taken" in 0.1 (see [0005](0005-replies-later.md));
- taking over from a hung owner;
- toolkit glue: the crate hands requests to a callback, and the app moves them onto its own event loop;
- anything across machines or across users.

## Why

The hard part of single-instance behaviour is not the socket. It is deciding who counts as "the same instance" under every way a program is started, and never delivering one request twice. Few apps get that right on their own, and the crates that exist get it wrong in ways the README lists. A small, well-encapsulated crate that gets it right is worth more than a larger one that also does RPC.

## Consequences

- The public API has no async runtime and no toolkit types, and `serde` is behind a feature (see [0002](0002-decide-then-serve.md) and [0003](0003-payloads.md)).
- Features that would turn the crate into RPC are weighed against this record first.
