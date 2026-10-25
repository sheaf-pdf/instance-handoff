# 0018. A launch that owns if nobody does, and otherwise runs alone

**Status:** Accepted, 2026-10-24, by the maintainer, from the notes on sheaf's port to the crate. The maintainer chose the name `try_own`, and `StateInUse` for a held lock. Built on `alpha-2` the same day.

## Context

`sheaf-instance` had a `Mode::Separate`, used for `--new-instance`, sheaf's developer flags and debug builds. A launch in that mode became the serving owner when nothing else was running, and ran alone otherwise. It never handed off.

The crate had no way to do that in one step:

- `exclusive()`, which [0002](0002-decide-then-serve.md) put in `Mode::Separate`'s place and whose docs suggested it for `--new-instance` flags, never serves. With nothing else running, it holds the state, and every ordinary launch until it ends runs alone with `StateInUse` instead of handing off.
- `probe()` and then `start()` can, but if another launch takes the lock between the two calls, `start` hands the request off: the opposite of what `--new-instance` asked for.

sheaf kept `exclusive()` when it moved to the crate (sheaf PR #32), which is acceptable for developer launches.

## Decision

A fifth way for a `Builder` to end: `try_own::<T>() -> Result<Claim<T>, Reason>`. Taking the lock is the decision, so there is nothing to race:

- It checks what `start` checks before taking the lock: `Excluded`, then `MayNotOwn` (a windowed app's launch that can't show windows, or one with raised rights under `elevated_owner`), then `ForeignState`, then the runtime folder.
- With the lock free, it owns as `start` does, guard included, and returns the `Claim`. With the guard held elsewhere, it lets the lock go and fails with `StateInUse`, naming the guard file, as `start` runs alone.
- With the lock held, it fails at once with `StateInUse`, naming the lock file. It looks again for 50 ms (`LOCK_RETRY`), as `exclusive` does, so that a `hand_off` or `probe` testing the lock isn't taken for an owner. It never connects, never encodes anything and never waits for the timeout.

`StateInUse` is what a held lock means here: another process holds the state folder. `exclusive` already reports a held lock with it where it takes no guard. A new variant, to tell an owner in the launch's own runtime folder from one elsewhere, was the alternative; the maintainer chose against it.

`exclusive()` stays for work that holds the state and serves nothing (migrations, batch commands, CI). Its docs point `--new-instance` flags to `try_own`.

## Why

- It is in scope: [0001](0001-scope.md) has the crate decide, at each launch, whether the process owns, hands off or runs alone. This is one more combination of those, decided where the others are.
- A terminal method, not an option on `start`. An option would leave `start` returning `Started::HandedOff` in a type where it can't happen, and 0002 replaced `Mode` with `exclusive()` so that each behaviour is its own call. `Result<Claim<T>, Reason>` has no case the app can't get. It takes no payload, since nothing is handed off, so the app names `T`, unless `serve`'s handler lets the compiler infer it.
- It costs little. It shares `start`'s checks and its way of owning (`own` in `src/launch.rs`), and takes the lock as an exclusive run does (`lock_alone`).
- Nothing changes between builds ([0009](0009-contract-between-builds.md)): the owner it makes is an ordinary owner, and launches of any build hand off to it.
- Turned down: `probe` then `start` (the race above), `exclusive` (serves nothing), and documenting the race instead of removing it.

## Consequences

- Two `try_own` launches at once: one owns and the other runs alone. A `start` that loses the lock to a `try_own` waits for it to serve and hands off to it, as to any owner that is starting. A `try_own` that loses to a `start` runs alone.
- Because it never hands off, it needs no commit ([0004](0004-commit-point.md)) and raises no question of rights. Who may own is decided as for `start`.
- The other launch that holds the lock without owning is a `start` that finds the guard held, which keeps the lock for up to 50 ms (`GUARD_RETRY`) and then runs alone. Whoever holds that guard would keep a `try_own` from owning too, so it runs alone either way.
- Tests: `try_own_owns_when_nobody_does_and_otherwise_runs_alone` (it owns, another fails at once, a `start` hands off to it), `launches_that_try_own_at_once_make_one_owner` (eight threads at once), and `try_own_needs_the_guard_too` (an exclusive run, and an owner in another runtime folder) in `tests/handoff.rs`; the `try_own` role of `only_a_launch_that_can_show_windows_owns_a_windowed_app` in `tests/process.rs` (`MayNotOwn { why: NoWindows }`, nothing made); and in `src/launch.rs`, raised rights beside an owner or not, and `a_lock_held_for_a_moment_is_looked_at_again`, which fails without the second look. That test gives the second look 10 s, not 50 ms: on macOS CI, its holder's 25 ms sleep ran past 50 ms, which a real holder, letting go without sleeping, never does.
