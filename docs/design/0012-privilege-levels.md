# 0012. Hand off only within one user and privilege level

**Status:** Accepted, 2026-10-18, by the maintainer. It replaces the review's earlier proposal that an elevated launch on Windows hand off to the normal owner. Under review: its cost for admin shells and elevated SSH sessions led to a wider identity review, which proposes [0015](0015-state-keyed-identity.md). That would keep this record's principle but replace its per-level owners.

## Context

A handoff moves a request from the process that launched it to the owner, which then acts on it with its own rights. If the two run at different privilege levels, the request runs with rights its launch never had, or without rights it did have.

## Decision

A request never runs with more or fewer rights than its launch had. So a launch hands off only to an owner of its own user, at its own privilege level, and each level has an owner of its own.

- **Unix.** The level is the effective uid. Root, whether reached by `sudo`, `su`, `doas` or `pkexec`, is another user, with its own folder and owner, and so is the user a setuid program runs as. Both ends check the peer's uid.
- **Windows.** The level is the user SID plus the integrity level.
  - Each level has its own folder: `<id>\run` at medium, `run-high`, `run-low`, `run-system`, or `run-<hex rid>` for any other level.
  - Each folder is created with a mandatory label at its level (`NWNR`). A folder whose label doesn't match the process's level is refused.
  - The pipe carries the same label.
  - The owner requires the client's level to equal its own, and the client requires the same of the pipe.
  - Below medium (low integrity, AppContainer), launches can't create or open their folder, and run alone with `Reason::RuntimeDir`.

## Why

The maintainer's rule: "if you run as admin, but then don't have admin privileges... that is not correct". The other directions are worse:

- **Elevated to normal** (the earlier proposal) drops rights the user asked for.
- **Normal to elevated** lets an unprivileged process have an elevated one act for it, which is privilege escalation.

The labels make the separation enforced by the OS, not by convention: a lower level can't read a higher level's folder or take its lock.

## Consequences

- On Windows, launches from an admin terminal, or from an SSH session that runs elevated, don't reach the normal desktop owner. They get an owner of their own. This is the cost under review.
- Owners at two levels may share files: the Windows profile, or root under `sudo -E` writing into the user's home. Apps that write shared state must keep it apart per level, or refuse to run elevated.
- Within one Unix user, finer privileges aren't compared: supplementary groups (`newgrp`), capabilities, LSM confinement. A sandbox that must keep its processes away from the owner hides the runtime folder from them, as Flatpak and snap do.
