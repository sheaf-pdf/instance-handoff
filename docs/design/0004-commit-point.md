# 0004. The launch commits before the owner delivers

**Status:** Proposed, 2026-10-18. Built on `api-0.1`; awaiting maintainer review.

## Context

In `sheaf-instance`, a launch whose timeout expired ran alone, yet the owner could still deliver its request later (sheaf's bug 11). This was reproduced three ways: a suspended owner (Ctrl-Z, `SIGSTOP`), and two silent connections queued ahead of the launch. The owner also served one connection at a time with a timeout on each read, so one silent or trickling client held up every launch behind it.

## Decision

- **Wire.** The exchange is HELLO, REQUEST, READY, COMMIT, REPLY.
- **Commit.** After READY, the launch writes COMMIT only if it is still within its timeout; otherwise it closes and runs alone.
- **Delivery.** The owner calls the handler only after reading COMMIT, and then sends REPLY.
- **No REPLY.** A launch that gets no REPLY after its COMMIT reports `HandedOff` with `OwnerInfo::confirmed() == false`.
- **Dropped connection.** If the connection drops before then, the launch takes the lock, or hands off again to an owner with a different nonce.
- **Serving.** The owner serves every connection at once from one thread, with `poll` and one absolute deadline per phase.
- **Framing.** Every message is `"IHND" | kind u8 | length u32 LE | records`, and each record is `tag u8 | length u32 LE | bytes`.
  - Unknown records are skipped, unless their tag has the high bit set (critical).

## Why

A fault-injection prototype on Linux ran 520 scenarios twice. No rule based on timing or hang-ups prevented duplicate delivery, and both commit-point designs had zero violations. The commit costs about 20 µs per handoff. Once the code was written, a stress test ran about 370,000 launches, under `SIGSTOP`, `SIGKILL`, bursts of up to 1,000 launches and folder deletion, with no violation of the invariant.

## Consequences

- Each launch ends in exactly one of three ways: handed off (the request delivered at most once), alone (no owner delivers it), or owner.
- The one gap is an owner that dies after its handler took a request but before REPLY. The launch then owns or hands off again, so work the dead owner had started may be done twice. This is documented under Guarantees.
- If a handler panics mid-request, the launch reports an unconfirmed handoff, not alone, because the request may already have been acted on.
- Timeouts under 100 ms count as 100 ms. A launch blocks for at most its timeout plus the greater of the timeout and 1 s.
