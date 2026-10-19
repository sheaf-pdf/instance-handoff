# 0016. The Windows owner keeps its address file open

**Status:** Accepted, 2026-10-18, by the maintainer. Built on `migrate-to-0015`; its Windows test awaits CI.

## Context

A Windows owner keeps two files in its runtime folder:

- `instance.lock`, which it holds open, without delete sharing, for as long as it runs. Nothing can delete it, so the folders around it can't be deleted either.
- `instance.pipe`, which names its pipe ([0011](0011-windows-named-pipes.md)). The owner writes it to a temporary file, renames that into place, and closes it. After that, anything running as the user can delete it.

A recursive delete of the app's folder, such as a user resetting the app, removes `instance.pipe` and fails on the rest. Launches then find the lock held and no address. They take the owner for one that is still starting, wait out their timeout, and run alone with `Reason::Unresponsive`. The owner checks its address only once a minute ([0008](0008-one-folder.md)), so for up to a minute no launch reaches it. No request is lost and no second owner starts, but to every launch the running app looks hung.

This was seen on a Windows 11 machine with UAC on, on 2026-10-18, in a run discarded for a fault in its script. With a medium and a high owner running, an elevated `Remove-Item -Recurse` of `%LOCALAPPDATA%\com.example.notes` removed part of the folder; which files went wasn't logged. Launches at both levels then got "an instance is running but didn't answer in 5.0008735s" (5.0010296s at medium). The code accounts for this as described above.

The tests missed it. The deletion tests in `tests/handoff.rs` are Unix-only, on the grounds that "Windows can't delete or open up a folder the owner holds". That is true of the folders and the lock, but not of the address file.

## Decision

While the owner publishes its address, it keeps `instance.pipe` open to read, sharing only reads. Nothing else can then delete it, rename over it or write to it, and launches can still read it.

- The owner closes the file just before it rewrites or withdraws it, and opens it again after a rewrite.
- The handle isn't inherited, so no child process holds the file after the owner exits. When the owner dies, the handle closes with it, and the next owner replaces the file as it does today.
- The check once a minute stays, for a publish that failed.

A Windows test deletes the app's folder recursively under a running owner, with the check set much longer than the test. The delete must fail, `instance.pipe` must still be there, and a launch must hand off at once. The test also tries to rename the folder. Windows is expected to refuse while a file in the folder is open, and the test confirms it. If Windows allowed it, a rename would move the live owner's lock aside, and the next launch would become a second owner in a new folder at the old path.

## Why

- It closes the gap instead of narrowing it, and costs no wakeups: an idle owner still sleeps for a minute at a time.
- Checking every second would make launches wait up to a second instead, but it would wake every idle app each second.
- A folder change notification (`FindFirstChangeNotificationW`) would fit the owner's wait loop. But it still lets the file go and reacts afterwards, and it's more code.
- Writing the address into the lock file would leave one file to protect. But that changes what two builds share ([0009](0009-contract-between-builds.md)), and readers would need a guard against torn reads.
- A pipe name derived from the folder would need no file at all. But other users could squat a name they can predict, which 0011's random name prevents.

## Consequences

- Nobody can delete the app's runtime folder while the app runs. That was already so because of the lock file; now the owner also stays reachable after an attempt.
- A program that opens `instance.pipe` to write or delete it while the owner runs gets a sharing violation. Programs that only read it are unaffected.
- Unix can't do this, because a file held open can still be unlinked. There the gap stays as 0008 records, including a possible second owner for up to a minute. Whether to check more often there is a separate decision.
- If [0015](0015-state-keyed-identity.md) changes the layout, the same rule applies to whichever file names the pipe.
