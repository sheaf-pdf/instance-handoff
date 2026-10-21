# Implementation plans

Each plan here builds decisions recorded in [docs/design](../design). The design records say what was decided and why. These files say how it gets built: the slices, their order and status, and the calls made along the way that no design decides.

A design record is marked built only when its implementation is complete. Slices follow whatever order keeps each commit small and green, not the records' boundaries.

| Plan | Builds | Files |
|---|---|---|
| 0015 | [0015](../design/0015-state-keyed-identity.md), and the open follow-ups of 0004, 0006 and 0009 | [plan and status](0015-plan.md), [requirements](0015-requirements.md), [calls](0015-calls.md) |

Plan 0015 is complete (2026-10-20): every slice landed or was dropped by a call, and 0015 is marked built.
