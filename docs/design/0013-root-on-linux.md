# 0013. No special case for root or `sudo` on Linux

**Status:** Accepted, 2026-10-18, by the maintainer. One exception is deferred (see below). Revisited by [0015](0015-state-keyed-identity.md), which proposes a fixed root folder and the exception below.

## Context

Under [0008](0008-one-folder.md) and [0012](0012-privilege-levels.md), root's folder on Linux with systemd is `/run/user/0/<id>`. That folder exists only while root has a session somewhere, such as a console login or SSH as root. So:

- **Root logged in.** Root's own launches meet one owner, like any user's. Launches under `sudo` from another user's session meet that same owner.
- **Root not logged in** (the usual case on desktops). Launches under `sudo` run alone with `Reason::NoSession`.

So whether a `sudo` launch hands off depends on whether root happens to be logged in elsewhere.

## Decision

Leave it as is, and document it (crate docs, "Privileges"). Root is just another user. Since the owner it would meet also runs as root, a handoff between two root processes never crosses a privilege level.

## Why

Both cases follow the one rule: same user, same level, same folder. An exception would be the first rule based on how a process came to have its uid rather than what the uid is. The maintainer wants to see real use before adding one.

## Deferred: elevation always runs alone

A possible exception: a process whose euid is 0 but whose audit login uid (`/proc/self/loginuid`) isn't 0 was elevated from another user's session (`sudo`, `su`), and would always run alone. The maintainer leans toward adding it. The trigger is real-world reports of `sudo` launches meeting a root owner they didn't expect. Don't add it unprompted.

## Consequences

- An app that should never share an owner across `sudo` can check for root itself and skip the crate.
- Root under `sudo -E` keeps the user's `HOME` and can write the user's files; see the limits in [0012](0012-privilege-levels.md).
