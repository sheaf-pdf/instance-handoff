# 0005. Replies, exit codes and `--wait` wait for 0.2

**Status:** Proposed, 2026-10-18. Awaiting maintainer review.

## Context

Some single-instance tools return more than "taken": `code --wait` blocks until the file is closed, and `emacsclient` prints a result and exits with its code. Apps ask for this.

## Decision

0.1 tells a launch only how the handler answered: `Answer::Take`, `Busy` or `Decline`. The wire leaves room for more: new record tags are skipped by peers that don't know them, so replies, exit codes and waiting can be added in a minor release without a protocol version bump.

## Why

Each of these needs the connection held open while the owner works, and an outcome with a fourth state (taken, still running). That is a step toward RPC ([0001](0001-scope.md)) and deserves its own design, not a rush before 0.1.

## Consequences

Apps that need `--wait` today have to build it themselves, for example by having the owner signal completion through a file or another channel.
